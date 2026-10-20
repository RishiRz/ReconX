from unittest.mock import Mock
import argparse
import json
import time

import pytest
import requests

import reconx


def test_save_html_report_creates_report(tmp_path):
    import reconx

    output = tmp_path / "report.html"
    results = [
        {
            "status": 301,
            "path": "/admin",
            "url": "http://127.0.0.1:8000/admin",
            "classification": "REDIRECT",
            "size": 0,
            "time_ms": 9.66,
            "redirect_url": "http://127.0.0.1:8000/admin/",
        }
    ]

    reconx.save_html_report(
        results,
        output,
        target="http://127.0.0.1:8000/",
        duration=0.84,
    )

    content = output.read_text(encoding="utf-8")

    assert "ReconX Scan Report" in content
    assert "/admin" in content
    assert "REDIRECT" in content
    assert "HTTP 301" in content


def test_save_html_report_escapes_untrusted_values(tmp_path):
    import reconx

    output = tmp_path / "safe-report.html"
    results = [
        {
            "status": 200,
            "path": '<script>alert("test")</script>',
            "url": "http://127.0.0.1:8000/",
            "classification": "FOUND",
            "size": 10,
            "time_ms": 1.0,
            "redirect_url": None,
        }
    ]

    reconx.save_html_report(results, output)

    content = output.read_text(encoding="utf-8")

    assert "<script>alert(" not in content
    assert "&lt;script&gt;" in content


def test_rate_limiter_rejects_non_positive_rate():
        import reconx
        import pytest

        with pytest.raises(ValueError):
            reconx.RateLimiter(0)

        with pytest.raises(ValueError):
            reconx.RateLimiter(-1)


def test_rate_limiter_waits_between_requests():
        import reconx

        limiter = reconx.RateLimiter(10)

        start = time.monotonic()
        limiter.wait()
        limiter.wait()
        elapsed = time.monotonic() - start

        assert elapsed >= 0.08



def test_valid_url_accepts_http_and_https():
    assert reconx.valid_url("http://localhost:8000") == "http://localhost:8000"
    assert reconx.valid_url("https://example.com") == "https://example.com"


def test_valid_url_rejects_invalid_scheme():
    with pytest.raises(argparse.ArgumentTypeError):
        reconx.valid_url("ftp://example.com")


def test_valid_url_rejects_embedded_credentials():
    with pytest.raises(argparse.ArgumentTypeError):
        reconx.valid_url("http://user:password@example.com")


def test_load_words_and_extensions(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text(
        "# comment\nadmin\nlogin\n\n",
        encoding="utf-8",
    )

    words = reconx.load_words(str(wordlist), ["php"])

    assert "admin" in words
    assert "admin.php" in words
    assert "login" in words
    assert "login.php" in words
    assert len(words) == 4


def test_load_words_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        reconx.load_words(str(tmp_path / "missing.txt"), [])


def test_profile_loading_and_unknown_keys(tmp_path):
    profile = tmp_path / "profile.json"
    profile.write_text(
        json.dumps({"threads": 5, "timeout": 3}),
        encoding="utf-8",
    )

    loaded = reconx.load_profile(str(profile))

    assert loaded["threads"] == 5
    assert loaded["timeout"] == 3

    profile.write_text(
        json.dumps({"unexpected_setting": True}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Unknown profile settings"):
        reconx.load_profile(str(profile))


def test_invalid_profile_json(tmp_path):
    profile = tmp_path / "invalid.json"
    profile.write_text("{invalid json", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid profile JSON"):
        reconx.load_profile(str(profile))


def test_response_filters():
    settings = {
        "exclude_status": [404],
        "exclude_size": [123],
    }

    wildcard = {"detected": False}

    base = {
        "status": 200,
        "size": 500,
        "content_type": "text/html",
        "body_hash": "abc",
    }

    assert not reconx.is_filtered(base, settings, wildcard)

    assert reconx.is_filtered(
        {**base, "status": 404}, settings, wildcard
    )

    assert reconx.is_filtered(
        {**base, "size": 123}, settings, wildcard
    )


def test_wildcard_requires_matching_body_hash(monkeypatch):
    wildcard = {
        "detected": True,
        "status": 200,
        "size": 500,
        "content_type": "text/html",
        "body_hash": "wildcard-hash",
    }

    settings = {"exclude_status": [], "exclude_size": []}

    matching = {
        "status": 200,
        "size": 500,
        "content_type": "text/html",
        "body_hash": "wildcard-hash",
    }

    legitimate = {
        **matching,
        "body_hash": "different-body-hash",
    }

    assert reconx.is_filtered(matching, settings, wildcard)
    assert not reconx.is_filtered(legitimate, settings, wildcard)


def test_detect_wildcard_when_responses_match(monkeypatch):
    response = {
        "status": 200,
        "size": 500,
        "content_type": "text/html",
        "body_hash": "same-hash",
    }

    monkeypatch.setattr(
        reconx,
        "request_info",
        lambda url, timeout: dict(response),
    )

    result = reconx.detect_wildcard("http://localhost:8000/", 2)

    assert result["detected"] is True
    assert result["status"] == 200
    assert result["body_hash"] == "same-hash"
    assert result["probes"] == 3


def test_detect_wildcard_when_responses_differ(monkeypatch):
    responses = [
        {
            "status": 200,
            "size": 400,
            "content_type": "text/html",
            "body_hash": "hash-a",
        },
        {
            "status": 200,
            "size": 401,
            "content_type": "text/html",
            "body_hash": "hash-b",
        },
        {
            "status": 302,
            "size": 0,
            "content_type": "text/html",
            "body_hash": "hash-c",
        },
    ]

    iterator = iter(responses)

    monkeypatch.setattr(
        reconx,
        "request_info",
        lambda url, timeout: dict(next(iterator)),
    )

    result = reconx.detect_wildcard("http://localhost:8000/", 2)

    assert result["detected"] is False
    assert result["probes"] == 3


def test_scan_one_handles_request_error(monkeypatch):
    def fail_request(url, timeout):
        raise requests.Timeout("test timeout")

    monkeypatch.setattr(reconx, "request_info", fail_request)

    result = reconx.scan_one(
        "http://localhost:8000/", "admin", 1
    )

    assert result["status"] is None
    assert result["error"] is not None
    assert "timeout" in result["error"].lower()


def test_classify_result_categories():
    assert reconx.classify_result({"status": 200}) == "SUCCESS"
    assert reconx.classify_result({"status": 301}) == "REDIRECT"
    assert reconx.classify_result({"status": 403}) == "RESTRICTED"
    assert reconx.classify_result({"status": 404}) == "NOT_FOUND"
    assert reconx.classify_result({"status": 500}) == "SERVER_ERROR"
    assert reconx.classify_result({"status": None}) == "ERROR"


def test_find_duplicates_groups_identical_responses():
    results = [
        {"url": "http://localhost/admin", "status": 200, "body_hash": "abc"},
        {"url": "http://localhost/login", "status": 200, "body_hash": "abc"},
        {"url": "http://localhost/about", "status": 200, "body_hash": "xyz"},
    ]

    duplicates = reconx.find_duplicates(results)

    assert len(duplicates) == 1
    assert duplicates[0]["count"] == 2
    assert set(duplicates[0]["urls"]) == {
        "http://localhost/admin",
        "http://localhost/login",
    }


def test_request_info_records_redirect(monkeypatch):
    response = Mock()
    response.status_code = 301
    response.content = b""
    response.headers = {
        "Location": "/admin/",
        "Content-Type": "",
    }

    request_mock = Mock(return_value=response)
    monkeypatch.setattr(reconx.requests, "get", request_mock)

    result = reconx.request_info("http://localhost:8000/admin", 5)

    assert result["status"] == 301
    assert result["redirect_url"] == "http://localhost:8000/admin/"
    request_mock.assert_called_once_with(
        "http://localhost:8000/admin",
        timeout=5,
        allow_redirects=False,
    )

def test_parse_status_codes():
    assert reconx.parse_status_codes("200,301,403") == [200, 301, 403]
    assert reconx.parse_status_codes("200, 301, 200") == [200, 301]


def test_parse_status_codes_rejects_invalid_values():
    with pytest.raises(argparse.ArgumentTypeError):
        reconx.parse_status_codes("200,abc")

    with pytest.raises(argparse.ArgumentTypeError):
        reconx.parse_status_codes("99,600")


def test_include_status_filter():
    results = [
        {"status": 200},
        {"status": 301},
        {"status": 403},
    ]
    allowed = reconx.parse_status_codes("200,403")

    filtered = [r for r in results if r["status"] in allowed]

    assert [r["status"] for r in filtered] == [200, 403]


def test_exclude_redirects_filter():
    results = [
        {"status": 200},
        {"status": 301},
        {"status": 302},
        {"status": 403},
        {"status": None},
    ]

    filtered = [
        r for r in results
        if r["status"] is None
        or not 300 <= r["status"] < 400
    ]

    assert [r["status"] for r in filtered] == [200, 403, None]

   