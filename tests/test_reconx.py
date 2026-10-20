
import argparse
import json

import pytest
import requests

import reconx


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
