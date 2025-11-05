# All-in-One WP Migration Backup Finder

A security research tool for discovering exposed WordPress backup files from the All-in-One WP Migration plugin vulnerability.

## About

This tool identifies exposed backup files created by vulnerable versions of the All-in-One WP Migration WordPress plugin. It's designed for authorized security testing, penetration testing engagements, and educational purposes.

**Based on research by [@vavkamil](https://vavkamil.cz/2020/03/25/all-in-one-wp-migration/)**

## Features

- Two scanning engines: `wfuzz` and `ffuf`
- Automatic vulnerability detection
- Smart timestamp-based brute-forcing
- Directory listing detection
- Wayback Machine integration
- Rate limiting support
- Comprehensive logging
- Type-safe Python code with full error handling

## Vulnerability Details

Certain versions of the All-in-One WP Migration plugin expose backup files through predictable URLs. This tool attempts to discover these files using:
1. Directory listing detection
2. Multi-part response checking
3. Wayback Machine archives
4. Timestamp-based filename brute-forcing

## Installation

### Requirements

- Python 3.11 or higher
- One of the following scanning tools:
  - [wfuzz](https://github.com/xmendez/wfuzz) - `pip install wfuzz`
  - [ffuf](https://github.com/ffuf/ffuf) - Install from releases

### Setup

```bash
# Clone the repository
git clone https://github.com/random-robbie/All-in-One-WP-Migration-Backup-Finder
cd All-in-One-WP-Migration-Backup-Finder

# Install Python dependencies
pip install -r requirements.txt

# Install scanning tool (choose one)
pip install wfuzz           # For finder.py
# OR download ffuf binary    # For ffufinder.py
```

### Docker

```bash
docker build -t wp-backup-finder .
docker run --rm wp-backup-finder https://example.com
```

## Usage

### Basic Usage

Using wfuzz (finder.py):
```bash
python3 finder.py -u https://example.com
```

Using ffuf (ffufinder.py):
```bash
python3 ffufinder.py -u https://example.com
```

### Advanced Options

```bash
# Extended time range (±20 minutes)
python3 finder.py -u https://example.com -d 20

# Custom thread count and rate limiting
python3 ffufinder.py -u https://example.com -t 50 --rate-limit 100

# Verbose output
python3 finder.py -u https://example.com -v

# Custom output file
python3 ffufinder.py -u https://example.com -o results.json

# Enable SSL verification
python3 finder.py -u https://example.com --verify-ssl

# Skip preliminary checks
python3 finder.py -u https://example.com --skip-checks
```

### All Options

**finder.py (wfuzz version):**
```
-u, --url              Target WordPress URL (required)
-d, --delta           Minutes to check before/after timestamp (default: 10)
-o, --output          Output file for results
-t, --threads         Number of concurrent threads (default: 1)
-v, --verbose         Enable verbose output
--verify-ssl          Verify SSL certificates
--timeout             Request timeout in seconds (default: 30)
--skip-checks         Skip preliminary checks
--payload-file        Custom payload filename (default: timerange.txt)
```

**ffufinder.py (ffuf version):**
```
-u, --url              Target WordPress URL (required)
-d, --delta           Minutes to check before/after timestamp (default: 10)
-o, --output          Output file for results (default: ffuf.json)
-t, --threads         Number of concurrent threads (default: 30)
-v, --verbose         Enable verbose output
--verify-ssl          Verify SSL certificates
--timeout             Request timeout in seconds (default: 30)
--skip-checks         Skip preliminary checks
--payload-file        Custom payload filename (default: timerange.txt)
--rate-limit          Rate limit (requests per second)
```

## How It Works

1. **Version Check**: Verifies if the plugin version is vulnerable
2. **Quick Checks**: Tests for directory listings and exposed backups
3. **Wayback Machine**: Searches for archived backup URLs
4. **Timestamp Discovery**: Retrieves backup timestamp from web.config
5. **Payload Generation**: Creates time-based payload (±delta minutes)
6. **Brute-force Scan**: Uses wfuzz/ffuf to test generated filenames

## Output

The tool will:
- Display progress and findings in real-time
- Save detailed results to output file
- Show success/error codes for each request
- Highlight discovered backup files

Example output:
```
============================================================
All-in-One WP Migration Backup Finder
ffuf version
============================================================
Target: https://example.com
============================================================
INFO - Checking server status: https://example.com
INFO - Server is reachable (status: 200)
INFO - Checking for exposed backup directory...
INFO - Checking for multiple backups...
INFO - Checking Wayback Machine...
INFO - Checking plugin version...
INFO - Version appears to be vulnerable
INFO - Retrieving backup timestamp...
INFO - Backup timestamp: 2024-01-15 14:30:00
INFO - Generating payload with ±10 minute range...
INFO - Generated 1,079,100 entries in timerange.txt
============================================================
Starting ffuf scan...
============================================================
```

## Ethical Use

**IMPORTANT**: This tool is for authorized security testing only.

- ✅ Penetration testing with written authorization
- ✅ Security research on systems you own
- ✅ Educational purposes in lab environments
- ✅ Bug bounty programs with appropriate scope
- ❌ Unauthorized access to systems you don't own
- ❌ Malicious purposes
- ❌ Testing without permission

**Unauthorized access to computer systems is illegal.**

## Performance Considerations

This tool generates a large number of requests:
- Default: ~1,079,100 requests per scan (±10 minutes, 3 digits)
- Extended: ~2,158,200 requests (±20 minutes)

Impact:
- May trigger rate limiting or WAF blocking
- Generates significant log entries on target server
- Can cause performance degradation on the target

**Use responsibly** and consider:
- Rate limiting (`--rate-limit` for ffuf)
- Lower thread counts (`-t`)
- Shorter time ranges (`-d`)

## Troubleshooting

**"wfuzz/ffuf not found"**
- Install the required tool or ensure it's in your PATH

**"Request timeout" errors**
- Increase timeout: `--timeout 60`
- Reduce thread count: `-t 10`

**Only seeing 403/401 errors**
- Server may have WAF protection
- Try enabling SSL verification: `--verify-ssl`
- Reduce request rate

**No backups found**
- Plugin may not be vulnerable
- Backups may use different timestamp
- Try increasing time range: `-d 30`

## Architecture

The project consists of three main files:

- `wp_migration_common.py` - Shared library with core functionality
- `finder.py` - wfuzz-based scanner
- `ffufinder.py` - ffuf-based scanner (generally faster)

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests if applicable
4. Submit a pull request

## Credits

- Research: [@vavkamil](https://twitter.com/vavkamil)
- Tool Development: [@random_robbie](https://twitter.com/random_robbie)
- Additional contributions from the community

## License

MIT License - see [LICENSE](LICENSE) file for details.

This tool is provided "as is" without warranty. Use at your own risk.

## Related Resources

- [Original Research by vavkamil](https://vavkamil.cz/2020/03/25/all-in-one-wp-migration/)
- [All-in-One WP Migration Plugin](https://wordpress.org/plugins/all-in-one-wp-migration/)
- [wfuzz Documentation](https://wfuzz.readthedocs.io/)
- [ffuf Documentation](https://github.com/ffuf/ffuf)

## Changelog

### Version 2.0.0 (2025)
- Complete rewrite with modern Python practices
- Added comprehensive error handling and logging
- Fixed security vulnerabilities (command injection, resource leaks)
- Added type hints throughout codebase
- Improved input validation
- Added rate limiting support
- Better documentation and professional README
- Docker support improvements
- Added .gitignore and LICENSE files

### Version 1.0.0 (Original)
- Initial release
- Basic wfuzz and ffuf support
- Timestamp-based brute-forcing

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors and contributors are not responsible for misuse or damage caused by this tool. Users are responsible for complying with all applicable laws and regulations.
