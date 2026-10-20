#!/usr/bin/env python3

import argparse
import concurrent.futures
import hashlib
import json
import csv
import secrets
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table

VERSION = "1.0.0"
console = Console()

DEFAULTS = {
    "threads": 10,
    "timeout": 5.0,
    "extensions": [],
    "exclude_status": [404],
    "exclude_size": [],
    "show_errors": False,
    "wildcard_detection": True,
}

ALLOWED_PROFILE_KEYS = set(DEFAULTS)


def format_request_error(error):
    """Return a concise, user-friendly network error message."""
    if isinstance(error, requests.exceptions.ConnectTimeout):
        return "Connection timed out."

    if isinstance(error, requests.exceptions.ReadTimeout):
        return "Server response timed out."

    if isinstance(error, requests.exceptions.ConnectionError):
        message = str(error).lower()

        if "name resolution" in message or "getaddrinfo failed" in message:
            return "DNS resolution failed."

        if "connection refused" in message or "actively refused" in message:
            return "Connection refused."

        return "Could not connect to the server."

    if isinstance(error, requests.exceptions.Timeout):
        return "Request timeout."

    return str(error)


def banner():
    console.print(
        "[bold cyan]"
        r"""
 ____  ____   ____ ___  _  __
|  _ \| __ ) / ___/ _ \| |/ /
| |_) |  _ \| |  | | | | ' /
|  _ <| |_) | |__| |_| | . \
|_| \_\____/ \____\___/|_|_\

"""
        "[/bold cyan]"
        "[bold white]Smart Web Content Discovery[/bold white]\n"
        f"[dim]ReconX v{VERSION}[/dim]\n"
    )


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


def load_profile(profile_path):
    if not profile_path:
        return {}

    path = Path(profile_path).expanduser()

    try:
        profile = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"Cannot read profile: {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid profile JSON: {error}") from error

    if not isinstance(profile, dict):
        raise ValueError("Profile must be a JSON object.")

    unknown = set(profile) - ALLOWED_PROFILE_KEYS
    if unknown:
        raise ValueError(
            f"Unknown profile settings: {', '.join(sorted(unknown))}"
        )

    return profile


def resolve_settings(args):
    settings = dict(DEFAULTS)
    settings.update(load_profile(args.profile))

    # Explicit command-line options override profile values.
    for key in ALLOWED_PROFILE_KEYS:
        value = getattr(args, key, None)
        if value is not None:
            settings[key] = value

    if not isinstance(settings["threads"], int) or not 1 <= settings["threads"] <= 100:
        raise ValueError("threads must be an integer between 1 and 100.")

    if (
        not isinstance(settings["timeout"], (int, float))
        or isinstance(settings["timeout"], bool)
        or settings["timeout"] <= 0
    ):
        raise ValueError("timeout must be a positive number.")

    for key in ("extensions", "exclude_status", "exclude_size"):
        if not isinstance(settings[key], list):
            raise ValueError(f"{key} must be a JSON array.")

    if any(
        not isinstance(code, int) or isinstance(code, bool) or not 100 <= code <= 599
        for code in settings["exclude_status"]
    ):
        raise ValueError("Excluded status codes must be integers from 100 to 599.")

    if any(
        not isinstance(size, int) or isinstance(size, bool) or size < 0
        for size in settings["exclude_size"]
    ):
        raise ValueError("Excluded response sizes must be non-negative integers.")

    if not all(isinstance(ext, str) for ext in settings["extensions"]):
        raise ValueError("Extensions must be strings.")

    for key in ("show_errors", "wildcard_detection"):
        if not isinstance(settings[key], bool):
            raise ValueError(f"{key} must be true or false.")

    return settings


def save_profile(path, settings):
    output = Path(path).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")


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
                extension = extension.strip().lstrip(".")
                if extension and not word.endswith("." + extension):
                    words.add(f"{word}.{extension}")

    return sorted(words)



def request_info(url, timeout):
    """Collect response details without following redirects."""
    response = requests.get(
        url,
        timeout=timeout,
        allow_redirects=False,
    )

    body = response.content
    location = response.headers.get("Location")

    redirect_url = urljoin(url, location) if location else None

    return {
        "status": response.status_code,
        "size": len(body),
        "content_type": response.headers.get("Content-Type", ""),
        "body_hash": hashlib.sha256(body).hexdigest(),
        "redirect_url": redirect_url,
    }




def scan_one(base_url, word, timeout, rate_limiter=None):
    target = urljoin(base_url, word)
    start = time.perf_counter()

    try:
        # Wait before sending the HTTP request.
        if rate_limiter is not None:
            rate_limiter.wait()

        info = request_info(target, timeout)

        return {
            "path": "/" + word,
            "url": target,
            **info,
            "time_ms": round((time.perf_counter() - start) * 1000, 2),
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
            "redirect_url": None,
            "time_ms": round((time.perf_counter() - start) * 1000, 2),
            "error": format_request_error(error),
        }




def detect_wildcard(base_url, timeout):
    """Detect repeated response signatures for random nonexistent paths."""
    probes = []

    for _ in range(3):
        random_path = f"reconx-missing-{secrets.token_hex(8)}"

        try:
            probes.append(
                request_info(urljoin(base_url, random_path), timeout)
            )
        except requests.RequestException:
            continue

    def signature(item):
        return (
            item["status"],
            item["size"],
            item["content_type"],
            item["body_hash"],
        )

    signatures = [signature(item) for item in probes]

    for candidate in set(signatures):
        if signatures.count(candidate) >= 2:
            return {
                "detected": True,
                "status": candidate[0],
                "size": candidate[1],
                "content_type": candidate[2],
                "body_hash": candidate[3],
                "probes": len(probes),
            }

    return {
        "detected": False,
        "probes": len(probes),
    }




def is_filtered(result, settings, wildcard):
    if result["status"] in settings["exclude_status"]:
        return True

    if result["size"] in settings["exclude_size"]:
        return True

    if wildcard.get("detected"):
        return (
            result["status"] == wildcard["status"]
            and result["size"] == wildcard["size"]
            and result["content_type"] == wildcard["content_type"]
            and result["body_hash"] == wildcard["body_hash"]
        )

    return False



def show_results(results):
    table = Table(title="Discovered Web Paths")
    table.add_column("Status", justify="right")
    table.add_column("Path", style="cyan")
    table.add_column("Size", justify="right")
    table.add_column("Time", justify="right")

    for result in results:
        status = result["status"]
        style = (
            "green" if 200 <= status < 300
            else "cyan" if 300 <= status < 400
            else "yellow" if 400 <= status < 500
            else "red"
        )

        table.add_row(
            f"[{style}]{status}[/{style}]",
            result["path"],
            f"{result['size']} B",
            f"{result['time_ms']:.2f} ms",
        )

    console.print(table)


def show_summary(results, displayed, errors, filtered, duration):
    console.print("\n[bold green]Scan complete[/bold green]")

    table = Table(title="Scan Summary")
    table.add_column("Metric")
    table.add_column("Value", justify="right")

    table.add_row("HTTP responses", str(len(results)))
    table.add_row("Displayed findings", str(len(displayed)))
    table.add_row("Filtered responses", str(filtered))
    table.add_row("Request errors", str(errors))
    table.add_row("Duration", f"{duration:.2f} seconds")
    table.add_row(
        "HTTP responses per second",
        f"{len(results) / duration:.2f}" if duration else "0.00",
    )

    console.print(table)

    counts = Counter(str(item["status"]) for item in results)
    if counts:
        status_table = Table(title="HTTP Status Breakdown")
        status_table.add_column("Status")
        status_table.add_column("Count", justify="right")

        for status, count in sorted(counts.items()):
            status_table.add_row(status, str(count))

        console.print(status_table)



from collections import defaultdict


def classify_result(result):
    """Assign a simple category to a scan result."""
    status = result.get("status")

    if status is None:
        return "ERROR"
    if status in (200, 201, 202, 204):
        return "SUCCESS"
    if status in (301, 302, 303, 307, 308):
        return "REDIRECT"
    if status in (401, 403):
        return "RESTRICTED"
    if status == 404:
        return "NOT_FOUND"
    if 400 <= status < 500:
        return "CLIENT_ERROR"
    if 500 <= status < 600:
        return "SERVER_ERROR"

    return "OTHER"


def find_duplicates(results):
    """Group responses with the same status and body hash."""
    groups = defaultdict(list)

    for result in results:
        status = result.get("status")
        body_hash = result.get("body_hash")

        # Ignore failed requests and responses without a fingerprint.
        if status is None or not body_hash:
            continue

        key = (status, body_hash)
        groups[key].append(result.get("url", ""))

    return [
        {
            "status": key[0],
            "body_hash": key[1],
            "count": len(urls),
            "urls": urls,
        }
        for key, urls in groups.items()
        if len(urls) > 1
    ]


def save_html_report(results, output_path, target="", duration=0):
    """Save scan results as a standalone HTML report."""
    import html
    from collections import Counter
    from datetime import datetime
    from pathlib import Path

    status_counts = Counter(
        str(result.get("status") or "Error")
        for result in results
    )

    def safe(value):
        return html.escape(str(value if value is not None else ""))

    rows = []

    for result in results:
        rows.append(
            "<tr>"
            f"<td>{safe(result.get('status'))}</td>"
            f"<td>{safe(result.get('path'))}</td>"
            f"<td>{safe(result.get('classification'))}</td>"
            f"<td>{safe(result.get('size'))}</td>"
            f"<td>{safe(result.get('time_ms'))}</td>"
            f"<td>{safe(result.get('redirect_url'))}</td>"
            f"<td>{safe(result.get('url'))}</td>"
            "</tr>"
        )

    status_rows = "".join(
        f"<li>HTTP {safe(status)}: {count}</li>"
        for status, count in sorted(status_counts.items())
    )

    document = f"""<!doctype html>
            <html lang="en">
            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>ReconX Scan Report</title>
            <style>
            body {{ font-family: Arial, sans-serif; margin: 2rem; color: #202938; }}
            header {{ border-bottom: 2px solid #334155; margin-bottom: 1.5rem; }}
            h1 {{ margin-bottom: .25rem; }}
            .meta {{ color: #475569; overflow-wrap: anywhere; }}
            .cards {{ display: flex; flex-wrap: wrap; gap: 1rem; }}
            .card {{ background: #f1f5f9; padding: 1rem; border-radius: 8px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
            th, td {{ border: 1px solid #cbd5e1; padding: .65rem; text-align: left; }}
            th {{ background: #e2e8f0; }}
            td {{ overflow-wrap: anywhere; }}
            tr:nth-child(even) {{ background: #f8fafc; }}
            </style>
            </head>
            <body>
            <header>
            <h1>ReconX Scan Report</h1>
            <p class="meta">Generated: {safe(datetime.now().astimezone().isoformat(timespec="seconds"))}</p>
            <p class="meta">Target: {safe(target)}</p>
            <p class="meta">Duration: {safe(round(duration, 2))} seconds</p>
            </header>

            <section class="cards">
            <div class="card"><strong>Displayed findings</strong><br>{len(results)}</div>
            <div class="card"><strong>Distinct status groups</strong><br>{len(status_counts)}</div>
            </section>

            <h2>HTTP Status Breakdown</h2>
            <ul>{status_rows or "<li>No results</li>"}</ul>

            <h2>Discovered Paths</h2>
            <table>
            <thead>
            <tr>
            <th>Status</th><th>Path</th><th>Classification</th>
            <th>Size (bytes)</th><th>Time (ms)</th>
            <th>Redirect URL</th><th>URL</th>
            </tr>
            </thead>
            <tbody>
            {"".join(rows) or '<tr><td colspan="7">No findings</td></tr>'}
            </tbody>
            </table>
            </body>
            </html>
            """

    output_path = Path(output_path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(document, encoding="utf-8")


def save_csv_report(results, output_path):
    """Save scan results as a CSV file."""
    fields = [
            "path",
            "url",
            "status",
            "classification",
            "size",
            "content_type",
            "redirect_url",
            "body_hash",
            "error",
        ]
    
    with open(output_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()

        for result in results:
            writer.writerow(result)


def parse_status_codes(value):
    """Parse comma-separated HTTP status codes."""
    try:
        codes = [int(item.strip()) for item in value.split(",")]
    except ValueError:
        raise argparse.ArgumentTypeError(
            "Use comma-separated status codes, e.g. 200,301,403"
        )

    if not codes or any(code < 100 or code > 599 for code in codes):
        raise argparse.ArgumentTypeError(
            "HTTP status codes must be between 100 and 599"
        )

    return list(dict.fromkeys(codes))



class RateLimiter:
    """Limit the start rate of concurrent HTTP requests."""

    def __init__(self, requests_per_second):
        if requests_per_second <= 0:
            raise ValueError("Request rate must be greater than zero")

        self.interval = 1.0 / requests_per_second
        self.lock = threading.Lock()
        self.next_allowed = 0.0

    def wait(self):
        # Reserve request-start times in one shared sequence.
        # Holding the lock prevents concurrent workers from
        # passing the limiter at the same time.
        with self.lock:
            now = time.monotonic()
            scheduled_time = max(now, self.next_allowed)
            delay = scheduled_time - now

            if delay > 0:
                time.sleep(delay)

            self.next_allowed = scheduled_time + self.interval



def run_scan(args):
    try:
        settings = resolve_settings(args)
        words = load_words(args.wordlist, settings["extensions"])
    except (ValueError, OSError) as error:
        console.print(f"[bold red]Error:[/bold red] {error}")
        return 1

    if args.max_requests is not None:
        words = words[:args.max_requests]

    if not words:
        console.print("[bold red]Wordlist contains no usable entries.[/bold red]")
        return 1

    try:
        base_url = valid_url(args.url).rstrip("/") + "/"
    except argparse.ArgumentTypeError as error:
        console.print(f"[bold red]Invalid target URL:[/bold red] {error}")
        return 1

    if args.save_profile:
        try:
            save_profile(args.save_profile, settings)
            console.print(f"[green]Profile saved:[/green] {args.save_profile}")
        except OSError as error:
            console.print(f"[red]Could not save profile:[/red] {error}")
            return 1

    banner()
    console.print(f"[cyan]Target:[/cyan] {base_url}")
    console.print(f"[cyan]Candidates:[/cyan] {len(words)}")
    console.print(f"[cyan]Threads:[/cyan] {settings['threads']}")
    console.print(f"[cyan]Timeout:[/cyan] {settings['timeout']} seconds")

    wildcard = {"detected": False, "probes": 0}

    if settings["wildcard_detection"]:
        console.print("[cyan]Checking for wildcard responses...[/cyan]")
        wildcard = detect_wildcard(base_url, settings["timeout"])

        if wildcard["detected"]:
            console.print(
                "[yellow]Possible wildcard response detected. "
                "Matching signatures will be filtered; verify manually.[/yellow]"
            )
        else:
            console.print("[green]No consistent wildcard signature detected.[/green]")

    results = []
    errors = []
    start = time.perf_counter()

    rate_limiter = RateLimiter(args.rate_limit)

    try:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=settings["threads"]
        ) as executor:
            futures = {
                executor.submit(
                    scan_one,
                    base_url,
                    word,
                    settings["timeout"],
                    rate_limiter,
                ): word
                for word in words
            }
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Scanning", total=len(futures))
                                
            for future in concurrent.futures.as_completed(futures):
                word = futures[future]

                try:
                    result = future.result()
                except Exception as error:
                    target = urljoin(base_url, word)

                    errors.append({
                        "path": "/" + word,
                        "url": target,
                        "status": None,
                        "size": None,
                        "content_type": None,
                        "body_hash": None,
                        "redirect_url": None,
                        "time_ms": None,
                        "error": f"Unexpected worker error: {error}",
                    })
                else:
                    if result["error"]:
                        errors.append(result)
                    else:
                        results.append(result)

                progress.advance(task)


    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        return 130

    duration = time.perf_counter() - start

    displayed = [
        result for result in results
        if not is_filtered(result, settings, wildcard)
    ]

    if args.include_status is not None:
        displayed = [
            result for result in displayed
            if result["status"] in args.include_status
        ]

    if args.exclude_redirects:
        displayed = [
            result for result in displayed
            if result["status"] is None
            or not 300 <= result["status"] < 400
        ]

    filtered_count = len(results) - len(displayed)


    for result in displayed:
        result["classification"] = classify_result(result)

    duplicates = find_duplicates(displayed)

    if duplicates:
        duplicate_table = Table(title="Duplicate Responses")
        duplicate_table.add_column("Status")
        duplicate_table.add_column("Count")
        duplicate_table.add_column("URLs")

        for group in duplicates:
            duplicate_table.add_row(
                str(group["status"]),
                str(group["count"]),
                "\n".join(group["urls"]),
            )

        console.print(duplicate_table)

    if displayed:
        show_results(displayed)
    else:
        console.print("[yellow]No results matched the display filters.[/yellow]")

    if settings["show_errors"] and errors:
        error_table = Table(title="Request Errors")
        error_table.add_column("Path")
        error_table.add_column("Error")

        for item in errors:
            error_table.add_row(item["path"], item["error"])

        console.print(error_table)

    show_summary(results, displayed, len(errors), filtered_count, duration)

    
    if args.csv:
        try:
            save_csv_report(displayed, args.csv)
            console.print(f"[green]CSV report saved:[/green] {args.csv}")
        except OSError as error:
            console.print(f"[red]Could not save CSV report:[/red] {error}")
            return 1


    if args.output:
        output_path = Path(args.output).expanduser()
        report = {
            "tool": "ReconX",
            "version": VERSION,
            "target": base_url,
            "settings": settings,
            "wildcard_detection": wildcard,
            "summary": {
                "candidates": len(words),
                "http_responses": len(results),
                "displayed_findings": len(displayed),
                "filtered_responses": filtered_count,
                "request_errors": len(errors),
                "duration_seconds": round(duration, 2),
            },
            "results": displayed,
            "duplicates": duplicates,
            "errors": errors if settings["show_errors"] else [],
        }

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(report, indent=2), encoding="utf-8"
            )
            console.print(f"[green]Report saved:[/green] {output_path}")
        except OSError as error:
            console.print(f"[red]Could not save report:[/red] {error}")
            return 1

    
    if args.html:
        try:
            html_path = Path(args.html).expanduser()
            html_path.parent.mkdir(parents=True, exist_ok=True)

            save_html_report(
                displayed,
                html_path,
                target=base_url,
                duration=duration,
            )

            console.print(
                f"[green]HTML report saved:[/green] {html_path}"
            )
        except OSError as error:
            console.print(
                f"[red]Could not save HTML report:[/red] {error}"
            )
            return 1

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="Web content discovery for authorized security testing.",
    )
    parser.add_argument("--version", action="version", version=f"ReconX {VERSION}")

    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Discover web paths.")

    scan.add_argument("-u", "--url", required=True, type=valid_url)
    scan.add_argument("-w", "--wordlist", required=True)
    scan.add_argument("-t", "--threads", type=int, default=None)
    scan.add_argument("--timeout", type=float, default=None)
    scan.add_argument("-x", "--extensions", nargs="*", default=None)
    scan.add_argument("-o", "--output")
    scan.add_argument("--csv", help="Save scan results to a CSV file",)
    scan.add_argument("--profile", help="Load settings from a JSON profile.")
    scan.add_argument("--save-profile", help="Save effective settings to a JSON profile.")
    scan.add_argument("--exclude-status", nargs="*", type=int, default=None)
    scan.add_argument("--exclude-size", nargs="*", type=int, default=None)
    scan.add_argument(
        "--show-errors", action="store_true", default=None
    )    
    scan.add_argument(
        "--include-status",
        type=parse_status_codes,
        default=None,
        help="Only display selected HTTP status codes, e.g. 200,301,403",
    )

    scan.add_argument(
        "--exclude-redirects",
        action="store_true",
        help="Hide HTTP redirect responses (3xx)",
    )

    scan.add_argument(
        "--no-wildcard-detection",
        action="store_false",
        dest="wildcard_detection",
        default=None,
    )

    scan.add_argument(
        "--rate-limit",
        type=float,
        default=5.0,
        help="Maximum scan request start rate per second (default: 5)",
    )

    scan.add_argument(
        "--max-requests",
        type=int,
        default=None,
        help="Maximum number of wordlist entries to scan",
    )

    scan.add_argument(
        "--html",
        help="Save scan results as an HTML report",
    )


    args = parser.parse_args()

    if args.rate_limit <= 0:
        parser.error("--rate-limit must be greater than zero")

    if args.max_requests is not None and args.max_requests < 1:
        parser.error("--max-requests must be at least 1")
        
    if args.command == "scan":
        return run_scan(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
