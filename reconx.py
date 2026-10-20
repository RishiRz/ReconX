#!/usr/bin/env python3

import argparse
import concurrent.futures
import hashlib
import json
import csv
import secrets
import sys
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

VERSION = "0.3.0"
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
            "time_ms": None,
            "error": str(error),
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


def save_csv_report(results, output_path):
    """Save scan results as a CSV file."""
    fields = [
        "url",
        "status",
        "size",
        "content_type",
        "body_hash",
        "error",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()

        for result in results:
            writer.writerow(result)


def run_scan(args):
    try:
        settings = resolve_settings(args)
        words = load_words(args.wordlist, settings["extensions"])
    except (ValueError, OSError) as error:
        console.print(f"[bold red]Error:[/bold red] {error}")
        return 1

    if not words:
        console.print("[bold red]Wordlist contains no usable entries.[/bold red]")
        return 1

    base_url = args.url.rstrip("/") + "/"

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

    try:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=settings["threads"]
        ) as executor:
            futures = [
                executor.submit(
                    scan_one, base_url, word, settings["timeout"]
                )
                for word in words
            ]

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
                    result = future.result()

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
    filtered_count = len(results) - len(displayed)

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
        "--no-wildcard-detection",
        action="store_false",
        dest="wildcard_detection",
        default=None,
    )

    args = parser.parse_args()

    if args.command == "scan":
        return run_scan(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
