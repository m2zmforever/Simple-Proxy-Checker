# Proxy Checker

A comprehensive, single-file, fast proxy checker script for Python 3.10+.

## Features
- Supports HTTP, HTTPS, SOCKS4, SOCKS5 proxies (auto-detect or manual selection)
- TCP connect and real GET request test via HTTP/HTTPS/SOCKS
- Anonymity level detection (transparent / anonymous / elite)
- IP and country (geolocation) lookup (optional)
- Fast, asyncio-based concurrency
- Timeout, retry, exponential backoff
- Proxy authentication (user:pass supported)
- Results as terminal table, CSV, and JSON
- Save only alive proxies to a separate file
- Progress bar (tqdm)
- Logging to both console and file
- Verbose/quiet modes
- Exit code: based on number of failed proxies

## Requirements
- Python 3.10+
- Dependencies: `aiohttp`, `aiohttp_socks`, `requests`, `tqdm`, `python-socks`, `aiofiles`, `tabulate`

Install dependencies:
```
pip install -r requirements.txt
```

## Usage

### Basic Usage
```
python proxy_checker.py -i proxies.txt
```

### Parameters
- `-i, --input` : Proxy list file (default: stdin)
- `-p, --proxy` : Single proxy or comma-separated list (host:port or host:port:user:pass)
- `-t, --type` : Proxy type (http, https, socks4, socks5, auto)
- `-c, --concurrency` : Number of concurrent tasks (default: 100)
- `-T, --timeout` : Timeout in seconds
- `--retries` : Number of retries (default: 2)
- `--geo` : Enable/disable IP -> country lookup
- `--save-csv path` : Save results as CSV
- `--save-json path` : Save results as JSON
- `--save-alive path` : Save only alive proxies
- `--throughput [size_kb]` : Optional small file download test
- `--verbose` : Verbose output
- `--quiet` : Quiet mode

### Examples
```
python proxy_checker.py -i proxies.txt --concurrency 200 --timeout 8 --save-csv results.csv --save-alive alive.txt
python proxy_checker.py -p 5.6.7.8:1080:user:pass -t socks5 --verbose
```

### Proxy Format
- `host:port`
- `host:port:user:pass`
- Multiple proxies can be provided as a comma-separated list in file or CLI.

### Output Fields
- proxy, scheme_tested, ok, anonymity, origin_ip, proxy_reported_ip, latency_ms, country, last_error, tested_at

### Logging
- Logs to both console and `proxy_checker.log` file.

### Error Handling
- Invalid proxy format, connection errors, timeouts, HTTP errors are reported in a user-friendly way.

## License
(´･-･`)?

## Author
idk... .D
