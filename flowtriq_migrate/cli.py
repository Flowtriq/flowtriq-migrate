"""Command-line interface for flowtriq-migrate."""

from __future__ import annotations

import argparse
import json
import sys

from flowtriq_migrate import __version__
from flowtriq_migrate.mapper import map_to_flowtriq
from flowtriq_migrate.parser import parse_config
from flowtriq_migrate.report import format_report


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="flowtriq-migrate",
        description=(
            "Migrate to Flowtriq from FastNetMon, Wanguard, or Corero.\n"
            "Reads your existing DDoS platform config and outputs a working "
            "Flowtriq agent configuration."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  flowtriq-migrate /etc/fastnetmon.conf\n"
            "  flowtriq-migrate wanguard-export.json --vendor wanguard\n"
            "  flowtriq-migrate corero-api-export.json --vendor corero\n"
            "  flowtriq-migrate config.conf -o /etc/ftagent/config.json\n"
            "  flowtriq-migrate config.conf --dry-run\n"
            "\n"
            "Get your API key and Node UUID at: https://flowtriq.com/dashboard\n"
            "Documentation: https://flowtriq.com/docs"
        ),
    )
    parser.add_argument(
        "config_file",
        help="Path to your DDoS platform configuration file",
    )
    parser.add_argument(
        "-o", "--output",
        default="config.json",
        help="Output path for the Flowtriq config (default: ./config.json)",
    )
    parser.add_argument(
        "--networks-file",
        default=None,
        help=(
            "Path to the networks_list file. Auto-detected from the config "
            "if not specified."
        ),
    )
    parser.add_argument(
        "--api-key",
        default="",
        help="Your Flowtriq API key (can also be set later in the config file)",
    )
    parser.add_argument(
        "--node-uuid",
        default="",
        help="Your Flowtriq Node UUID (can also be set later in the config file)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the generated config to stdout instead of writing a file",
    )
    parser.add_argument(
        "--vendor",
        default=None,
        choices=["fastnetmon", "wanguard", "corero"],
        help=(
            "Source platform (auto-detected if not specified). "
            "Use 'wanguard' or 'corero' for JSON export files."
        ),
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the migration report; only output the config",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args(argv)

    # Parse the FastNetMon config
    try:
        parsed = parse_config(args.config_file, args.networks_file, args.vendor)
    except FileNotFoundError:
        print(f"Error: Config file not found: {args.config_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error parsing config: {e}", file=sys.stderr)
        sys.exit(1)

    # Map to Flowtriq config
    flowtriq_config, notes = map_to_flowtriq(
        parsed,
        api_key=args.api_key,
        node_uuid=args.node_uuid,
    )

    # Output the config
    config_json = json.dumps(flowtriq_config, indent=2, ensure_ascii=False)

    if args.dry_run:
        print(config_json)
        output_path = None
    else:
        with open(args.output, "w") as f:
            f.write(config_json + "\n")
        output_path = args.output

    # Print the migration report
    if not args.quiet:
        report = format_report(
            parsed,
            flowtriq_config,
            notes,
            source_path=args.config_file,
            output_path=output_path,
        )
        print(report, file=sys.stderr if args.dry_run else sys.stdout)


if __name__ == "__main__":
    main()
