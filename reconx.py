
#!/usr/bin/env python3

import argparse
import concurrent.futures
import json
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

VERSION = "0.1.0"

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


def scan_one(base_url, word, timeout):
    target = urljoin(base_url, word)

    try:
        start = time.perf_counter()

        response = requests.get(
            target,
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": f"ReconX/{VERSION}"},
        )

        elapsed = round((time.perf_counter() - start) * 1000, 2)

        return {
            "path": "/" + word,
            "url": target,
            "status": response.status_code,
            "size": len(response.content),
            "time_ms": elapsed,
            "error": None,
        }

    except requests.RequestException as error:
        return {
            "path": "/" + word,
            "url": target,
            "status": None,
            "size": None,
            "time_ms": None,
            "error": str(error),
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
    except (OSError, UnicodeError) as error:
        print(f"{RED}[!] {error}{RESET}")
        return 1

    if not words:
        print(f"{RED}[!] Wordlist contains no usable entries.{RESET}")
        return 1

    base_url = args.url.rstrip("/") + "/"

    print(f"{CYAN}[+] Target:      {base_url}")
    print(f"[+] Wordlist:    {args.wordlist}")
    print(f"[+] Candidates:  {len(words)}")
    print(f"[+] Threads:     {args.threads}")
    print(f"[+] Timeout:     {args.timeout}s{RESET}\n")

    results = []
    completed = 0
    started = time.perf_counter()

    try:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=args.threads
        ) as executor:
            futures = {
                executor.submit(
                    scan_one, base_url, word, args.timeout
                ): word
                for word in words
            }

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                completed += 1

                if result["error"]:
                    if args.show_errors:
                        print(
                            f"{RED}[ERROR] {result['path']}: "
                            f"{result['error']}{RESET}"
                        )
                else:
                    results.append(result)

                    if (
                        result["status"] not in args.exclude_status
                        and result["size"] not in args.exclude_size
                    ):
                        color = status_color(result["status"])
                        print(
                            f"{color}[{result['status']}] "
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
    print("\n")

    print(f"{GREEN}[+] Scan finished")
    print(f"[+] Requests completed: {len(results)}")
    print(f"[+] Duration: {duration:.2f}s")
    print(f"[+] Responses per second: "
          f"{len(results) / duration if duration else 0:.2f}{RESET}")

    if args.output:
        output_path = Path(args.output).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        report = {
            "tool": "ReconX",
            "version": VERSION,
            "target": base_url,
            "duration_seconds": round(duration, 2),
            "results": results,
        }

        try:
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
        description="Simple web content discovery for authorized testing.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ReconX {VERSION}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan", help="Discover web paths using a wordlist."
    )
    scan.add_argument(
        "-u", "--url", required=True, type=valid_url,
        help="Target base URL, e.g. http://127.0.0.1:8000",
    )
    scan.add_argument(
        "-w", "--wordlist", required=True,
        help="Path to a newline-separated wordlist.",
    )
    scan.add_argument(
        "-t", "--threads", type=int, default=10,
        help="Concurrent requests (default: 10; maximum: 100).",
    )
    scan.add_argument(
        "--timeout", type=float, default=5,
        help="Request timeout in seconds (default: 5).",
    )
    scan.add_argument(
        "-x", "--extensions", nargs="*", default=[],
        help="Optional extensions, e.g. php html txt",
    )
    scan.add_argument(
        "-o", "--output",
        help="Save all successful HTTP responses to a JSON report.",
    )
    scan.add_argument(
        "--exclude-status", nargs="*", type=int, default=[404],
        help="Status codes to hide (default: 404).",
    )
    scan.add_argument(
        "--exclude-size", nargs="*", type=int, default=[],
        help="Response sizes in bytes to hide.",
    )
    scan.add_argument(
        "--show-errors", action="store_true",
        help="Display individual request errors.",
    )

    args = parser.parse_args()

    if args.command == "scan":
        if not 1 <= args.threads <= 100:
            parser.error("--threads must be between 1 and 100")
        if args.timeout <= 0:
            parser.error("--timeout must be greater than zero")
        if any(not 100 <= code <= 599 for code in args.exclude_status):
            parser.error("Excluded status codes must be between 100 and 599")
        if any(size < 0 for size in args.exclude_size):
            parser.error("Excluded sizes cannot be negative")

        return run_scan(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
