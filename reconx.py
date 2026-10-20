
#!/usr/bin/env python3

import argparse
import concurrent.futures
import hashlib
import json
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

VERSION = "0.2.0"

GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


def banner():
    print(f"""
{CYAN}
 ____  ____   ____ ___  _  __
|  _ \\| __ ) / ___/ _ \\| |/ /
| |_) |  _ \\| |  | | | | ' /
|  _ <| |_) | |__| |_| | . \\
|_| \\_\\____/ \\____\\___/|_|\\_\\
{RESET}
 Smart Web Content Discovery
 Version {VERSION}
""")


def valid_url(value):
    parsed = urlparse(value)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise argparse.ArgumentTypeError(
            "Enter a valid HTTP or HTTPS URL."
        )

    if parsed.username or parsed.password:
        raise argparse.ArgumentTypeError(
            "Credentials in URLs are not supported."
        )

    return value


def load_words(wordlist, extensions):
    path = Path(wordlist).expanduser()

    if not path.is_file():
        raise FileNotFoundError(f"Wordlist not found: {path}")

    words = set()

    with path.open("r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            word = line.strip()

            if not word or word.startswith("#"):
                continue

            word = word.lstrip("/")
            if not word:
                continue

            words.add(word)

            for extension in extensions:
                extension = extension.lstrip(".")
                if extension and not word.endswith("." + extension):
                    words.add(f"{word}.{extension}")

    return sorted(words)


def request_info(url, timeout):
    """Fetch response metadata without following redirects."""
    response = requests.get(
        url,
        timeout=timeout,
        allow_redirects=False,
        headers={"User-Agent": f"ReconX/{VERSION}"},
    )

    body = response.content

    return {
        "status": response.status_code,
        "size": len(body),
        "content_type": response.headers.get("Content-Type", ""),
        "body_hash": hashlib.sha256(body).hexdigest(),
    }


def scan_one(base_url, word, timeout):
    target = urljoin(base_url, word)
    start = time.perf_counter()

    try:
        info = request_info(target, timeout)
        elapsed = round((time.perf_counter() - start) * 1000, 2)

        return {
            "path": "/" + word,
            "url": target,
            **info,
            "time_ms": elapsed,
            "error": None,
        }

    except requests.RequestException as error:
        return {
            "path": "/" + word,
            "url": target,
            "status": None,
            "size": None,
            "content_type": None,
            "body_hash": None,
            "time_ms": None,
            "error": str(error),
        }


def detect_wildcard(base_url, timeout):
    """
    Heuristic: probe three random, unlikely paths.
    Two matching status/size/content-type signatures suggest
    that the server may return a common response for missing paths.
    """
    probes = []

    for _ in range(3):
        random_path = f"reconx-not-found-{secrets.token_hex(8)}"
        try:
            probes.append(
                request_info(urljoin(base_url, random_path), timeout)
            )
        except requests.RequestException:
            continue

    signatures = [
        (item["status"], item["size"], item["content_type"])
        for item in probes
    ]

    for signature in set(signatures):
        if signatures.count(signature) >= 2:
            return {
                "detected": True,
                "status": signature[0],
                "size": signature[1],
                "content_type": signature[2],
                "probes": len(probes),
            }

    return {
        "detected": False,
        "probes": len(probes),
    }


def status_color(status):
    if 200 <= status < 300:
        return GREEN
    if 300 <= status < 400:
        return CYAN
    if 400 <= status < 500:
        return YELLOW
    return RED


def run_scan(args):
    banner()

    try:
        words = load_words(args.wordlist, args.extensions)
    except OSError as error:
        print(f"{RED}[!] {error}{RESET}")
        return 1

    if not words:
        print(f"{RED}[!] Wordlist contains no usable entries.{RESET}")
        return 1

    base_url = args.url.rstrip("/") + "/"

    print(f"{CYAN}[+] Target:     {base_url}")
    print(f"[+] Candidates: {len(words)}")
    print(f"[+] Threads:    {args.threads}")
    print(f"[+] Timeout:    {args.timeout}s{RESET}")

    wildcard = {"detected": False, "probes": 0}

    if not args.no_wildcard_detection:
        print(f"{CYAN}[+] Checking for wildcard responses...{RESET}")
        wildcard = detect_wildcard(base_url, args.timeout)

        if wildcard["detected"]:
            print(
                f"{YELLOW}[!] Possible wildcard response detected: "
                f"HTTP {wildcard['status']}, "
                f"{wildcard['size']} bytes.{RESET}"
            )
            print(
                f"{YELLOW}[!] Matching responses will be hidden. "
                "Use --no-wildcard-detection to disable this heuristic."
                f"{RESET}"
            )
        else:
            print(f"{GREEN}[+] No consistent wildcard signature detected.{RESET}")

    print()

    results = []
    shown = []
    errors = 0
    completed = 0
    started = time.perf_counter()

    try:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=args.threads
        ) as executor:
            futures = {
                executor.submit(scan_one, base_url, word, args.timeout): word
                for word in words
            }

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                completed += 1

                if result["error"]:
                    errors += 1
                    if args.show_errors:
                        print(
                            f"\n{RED}[ERROR] {result['path']}: "
                            f"{result['error']}{RESET}"
                        )
                else:
                    results.append(result)

                    excluded = (
                        result["status"] in args.exclude_status
                        or result["size"] in args.exclude_size
                    )

                    signature_matches = (
                        wildcard["detected"]
                        and result["status"] == wildcard.get("status")
                        and result["size"] == wildcard.get("size")
                        and result["content_type"]
                        == wildcard.get("content_type")
                    )

                    if not excluded and not signature_matches:
                        shown.append(result)
                        color = status_color(result["status"])
                        print(
                            f"\n{color}[{result['status']}] "
                            f"{result['path']:<30} "
                            f"{result['size']:>8} bytes "
                            f"{result['time_ms']:>8} ms{RESET}"
                        )

                print(
                    f"\rProgress: {completed}/{len(words)}",
                    end="",
                    flush=True,
                )

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted.{RESET}")
        return 130

    duration = time.perf_counter() - started

    print(f"\n\n{GREEN}[+] Scan finished{RESET}")
    print(f"[+] HTTP responses: {len(results)}")
    print(f"[+] Displayed results: {len(shown)}")
    print(f"[+] Request errors: {errors}")
    print(f"[+] Duration: {duration:.2f}s")

    if args.output:
        output_path = Path(args.output).expanduser()

        report = {
            "tool": "ReconX",
            "version": VERSION,
            "target": base_url,
            "duration_seconds": round(duration, 2),
            "wildcard_detection": wildcard,
            "total_candidates": len(words),
            "http_responses": len(results),
            "request_errors": errors,
            "results": shown,
        }

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(report, indent=2),
                encoding="utf-8",
            )
            print(f"{GREEN}[+] Report saved: {output_path}{RESET}")
        except OSError as error:
            print(f"{RED}[!] Could not save report: {error}{RESET}")
            return 1

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="Web content discovery for authorized testing.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ReconX {VERSION}",
    )

    subparsers = parser.add_subparsers(
        dest="command", required=True
    )

    scan = subparsers.add_parser(
        "scan", help="Discover paths using a wordlist."
    )
    scan.add_argument(
        "-u", "--url", required=True, type=valid_url
    )
    scan.add_argument(
        "-w", "--wordlist", required=True
    )
    scan.add_argument(
        "-t", "--threads", type=int, default=10
    )
    scan.add_argument(
        "--timeout", type=float, default=5
    )
    scan.add_argument(
        "-x", "--extensions", nargs="*", default=[]
    )
    scan.add_argument(
        "-o", "--output",
        help="Save filtered results to a JSON report.",
    )
    scan.add_argument(
        "--exclude-status", nargs="*", type=int, default=[404]
    )
    scan.add_argument(
        "--exclude-size", nargs="*", type=int, default=[]
    )
    scan.add_argument(
        "--no-wildcard-detection",
        action="store_true",
        help="Disable random-path wildcard checks.",
    )
    scan.add_argument(
        "--show-errors", action="store_true"
    )

    args = parser.parse_args()

    if args.command == "scan":
        if not 1 <= args.threads <= 100:
            parser.error("--threads must be between 1 and 100")
        if args.timeout <= 0:
            parser.error("--timeout must be greater than zero")
        if any(not 100 <= code <= 599 for code in args.exclude_status):
            parser.error("Excluded status codes must be 100-599")
        if any(size < 0 for size in args.exclude_size):
            parser.error("Excluded sizes cannot be negative")

        return run_scan(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
