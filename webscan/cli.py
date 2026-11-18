import argparse
import sys

from . import __version__, report
from .scanner import Scanner

BANNER = r"""
 __        __   _     ____
 \ \      / /__| |__ / ___|  ___ __ _ _ __
  \ \ /\ / / _ \ '_ \\___ \ / __/ _` | '_ \
   \ V  V /  __/ |_) |___) | (_| (_| | | | |
    \_/\_/ \___|_.__/|____/ \___\__,_|_| |_|
   Passive web security misconfiguration scanner
"""


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="webscan",
        description="Scan a website you own or are authorised to test for common security misconfigurations.",
    )
    p.add_argument("url", help="Target URL, e.g. https://example.com")
    p.add_argument("-o", "--output", help="Save report to file (.json or .html)")
    p.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds")
    p.add_argument("--no-color", action="store_true", help="Disable coloured output")
    p.add_argument("--version", action="version", version=f"webscan {__version__}")
    args = p.parse_args(argv)

    print(BANNER)
    print("Only scan websites you own or have written permission to test.\n")

    try:
        result = Scanner(args.url, timeout=args.timeout).run()
    except Exception as e:
        print(f"Error: could not scan {args.url}: {e}", file=sys.stderr)
        return 2

    report.print_console(result, color=not args.no_color)

    if args.output:
        content = report.to_html(result) if args.output.endswith(".html") else report.to_json(result)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"Report saved to {args.output}")

    return 1 if any(f.severity == "HIGH" for f in result["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
