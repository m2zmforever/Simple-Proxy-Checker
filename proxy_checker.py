import sys
import os
import re
import csv
import json
import argparse
import logging
import asyncio
import time
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple

try:
    import aiohttp
    from aiohttp_socks import ProxyConnector, ProxyType
    import requests
    from tqdm import tqdm
except ImportError as e:
    print("[!] Missing dependencies. Please install them with:\n    pip install -r requirements.txt")
    sys.exit(1)

# Optional: aiofiles for async file writing
try:
    import aiofiles
    HAS_AIOFILES = True
except ImportError:
    HAS_AIOFILES = False

# ========== CONFIGURATION ==========
DEFAULT_TIMEOUT = 8
DEFAULT_CONCURRENCY = 100
DEFAULT_RETRIES = 2
HTTPBIN_URL = "https://httpbin.org/get"
HTTPBIN_IP_URL = "http://httpbin.org/ip"
GEO_API_URL = "http://ip-api.com/json/{}"
LOG_FILE = "proxy_checker.log"
LOG_MAX_BYTES = 2 * 1024 * 1024  # 2MB
LOG_BACKUP_COUNT = 2

# ========== LOGGING SETUP ==========
def setup_logging(verbose: bool, quiet: bool, log_file: str = LOG_FILE):
    from logging.handlers import RotatingFileHandler
    log_level = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.INFO)
    logger = logging.getLogger()
    logger.setLevel(log_level)
    fmt = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    # File handler
    fh = RotatingFileHandler(log_file, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

# ========== UTILS ==========
def parse_proxy_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a proxy line into its components."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    # host:port or host:port:user:pass
    parts = line.split(":")
    if len(parts) == 2:
        host, port = parts
        return {"host": host, "port": int(port), "user": None, "pass": None}
    elif len(parts) == 4:
        host, port, user, passwd = parts
        return {"host": host, "port": int(port), "user": user, "pass": passwd}
    else:
        return None

def parse_proxy_type(s: str) -> Optional[str]:
    s = s.lower()
    if s in ("http", "https", "socks4", "socks5", "auto"):
        return s
    return None

def get_proxy_url(proxy: Dict[str, Any], scheme: str) -> str:
    """Return a proxy URL for aiohttp/requests."""
    userinfo = f"{proxy['user']}:{proxy['pass']}@" if proxy['user'] and proxy['pass'] else ""
    return f"{scheme}://{userinfo}{proxy['host']}:{proxy['port']}"

async def get_origin_ip(session: aiohttp.ClientSession, timeout: int) -> Optional[str]:
    try:
        async with session.get(HTTPBIN_IP_URL, timeout=timeout) as resp:
            data = await resp.json()
            return data.get("origin")
    except Exception:
        return None

async def get_geo(ip: str, session: aiohttp.ClientSession, timeout: int) -> Optional[str]:
    try:
        async with session.get(GEO_API_URL.format(ip), timeout=timeout) as resp:
            data = await resp.json()
            return data.get("country", None)
    except Exception:
        return None

def classify_anonymity(origin_ip: str, proxy_ip: str, headers: Dict[str, Any]) -> str:
    """Classify proxy anonymity based on IP and headers."""
    if not proxy_ip or not origin_ip:
        return "unknown"
    if proxy_ip == origin_ip:
        return "transparent"
    via = headers.get("Via") or headers.get("via")
    xff = headers.get("X-Forwarded-For") or headers.get("x-forwarded-for")
    fwd = headers.get("Forwarded") or headers.get("forwarded")
    if via or xff or fwd:
        return "anonymous"
    return "elite"

async def tcp_connect_test(host: str, port: int, timeout: int) -> Tuple[bool, Optional[str], float]:
    """Test TCP connect to host:port. Returns (ok, error, latency_ms)."""
    loop = asyncio.get_running_loop()
    start = time.perf_counter()
    try:
        fut = loop.getaddrinfo(host, port)
        infos = await asyncio.wait_for(fut, timeout=timeout)
        for family, type_, proto, canonname, sockaddr in infos:
            try:
                s = socket.socket(family, type_, proto)
                s.setblocking(False)
                await asyncio.wait_for(loop.sock_connect(s, sockaddr), timeout=timeout)
                s.close()
                latency = (time.perf_counter() - start) * 1000
                return True, None, latency
            except Exception as e:
                continue
        return False, "TCP connect failed", (time.perf_counter() - start) * 1000
    except Exception as e:
        return False, str(e), (time.perf_counter() - start) * 1000

async def test_proxy(
    proxy: Dict[str, Any],
    scheme: str,
    origin_ip: str,
    timeout: int,
    retries: int,
    geo: bool,
    throughput: Optional[int],
    verbose: bool
) -> Dict[str, Any]:
    """Test a single proxy for connectivity, anonymity, latency, etc."""
    import socket
    result = {
        "proxy": get_proxy_url(proxy, scheme),
        "scheme_tested": scheme,
        "ok": False,
        "anonymity": None,
        "origin_ip": origin_ip,
        "proxy_reported_ip": None,
        "latency_ms": None,
        "country": None,
        "last_error": None,
        "tested_at": datetime.utcnow().isoformat()
    }
    # TCP connect test
    for attempt in range(retries + 1):
        ok, err, latency = await tcp_connect_test(proxy["host"], proxy["port"], timeout)
        if ok:
            result["latency_ms"] = round(latency, 2)
            break
        else:
            result["last_error"] = err
            await asyncio.sleep(2 ** attempt)
    if not ok:
        return result
    # HTTP/HTTPS/SOCKS test
    for attempt in range(retries + 1):
        try:
            if scheme.startswith("socks"):
                connector = ProxyConnector.from_url(get_proxy_url(proxy, scheme))
                async with aiohttp.ClientSession(connector=connector) as session:
                    start = time.perf_counter()
                    async with session.get(HTTPBIN_URL, timeout=timeout) as resp:
                        data = await resp.json()
                        latency = (time.perf_counter() - start) * 1000
                        result["latency_ms"] = round(latency, 2)
                        result["proxy_reported_ip"] = data.get("origin")
                        result["anonymity"] = classify_anonymity(origin_ip, data.get("origin"), resp.headers)
                        if geo and data.get("origin"):
                            result["country"] = await get_geo(data.get("origin"), session, timeout)
                        result["ok"] = True
                        break
            else:
                proxy_url = get_proxy_url(proxy, scheme)
                async with aiohttp.ClientSession() as session:
                    start = time.perf_counter()
                    async with session.get(HTTPBIN_URL, proxy=proxy_url, timeout=timeout) as resp:
                        data = await resp.json()
                        latency = (time.perf_counter() - start) * 1000
                        result["latency_ms"] = round(latency, 2)
                        result["proxy_reported_ip"] = data.get("origin")
                        result["anonymity"] = classify_anonymity(origin_ip, data.get("origin"), resp.headers)
                        if geo and data.get("origin"):
                            result["country"] = await get_geo(data.get("origin"), session, timeout)
                        result["ok"] = True
                        break
        except Exception as e:
            result["last_error"] = str(e)
            await asyncio.sleep(2 ** attempt)
    return result

async def test_proxy_auto(proxy: Dict[str, Any], origin_ip: str, timeout: int, retries: int, geo: bool, throughput: Optional[int], verbose: bool) -> Dict[str, Any]:
    """Try all proxy types for a proxy, return first successful."""
    for scheme in ("http", "https", "socks4", "socks5"):
        res = await test_proxy(proxy, scheme, origin_ip, timeout, retries, geo, throughput, verbose)
        if res["ok"]:
            return res
    return res  # last result

async def run_proxies(
    proxies: List[Dict[str, Any]],
    scheme: str,
    concurrency: int,
    timeout: int,
    retries: int,
    geo: bool,
    throughput: Optional[int],
    verbose: bool
) -> List[Dict[str, Any]]:
    """Run proxy tests concurrently."""
    results = []
    sem = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession() as session:
        origin_ip = await get_origin_ip(session, timeout)
    pbar = tqdm(total=len(proxies), desc="Testing proxies", ncols=80)
    async def worker(proxy):
        async with sem:
            try:
                if scheme == "auto":
                    res = await test_proxy_auto(proxy, origin_ip, timeout, retries, geo, throughput, verbose)
                else:
                    res = await test_proxy(proxy, scheme, origin_ip, timeout, retries, geo, throughput, verbose)
                results.append(res)
            except Exception as e:
                results.append({"proxy": get_proxy_url(proxy, scheme), "ok": False, "last_error": str(e)})
            finally:
                pbar.update(1)
    await asyncio.gather(*(worker(proxy) for proxy in proxies))
    pbar.close()
    return results

def save_csv(path: str, results: List[Dict[str, Any]]):
    with open(path, "w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "proxy", "scheme_tested", "ok", "anonymity", "origin_ip", "proxy_reported_ip", "latency_ms", "country", "last_error", "tested_at"
        ])
        writer.writeheader()
        for row in results:
            writer.writerow(row)

def save_json(path: str, results: List[Dict[str, Any]]):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

def save_alive(path: str, results: List[Dict[str, Any]]):
    with open(path, "w", encoding="utf-8") as f:
        for row in results:
            if row.get("ok"):
                f.write(f"{row['proxy']}\n")

def load_proxies_from_file(path: str) -> List[Dict[str, Any]]:
    proxies = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            p = parse_proxy_line(line)
            if p:
                proxies.append(p)
    return proxies

def load_proxies_from_args(args: argparse.Namespace) -> List[Dict[str, Any]]:
    proxies = []
    if args.proxy:
        for item in args.proxy.split(","):
            p = parse_proxy_line(item)
            if p:
                proxies.append(p)
    return proxies

def main():
    parser = argparse.ArgumentParser(description="Async Proxy Checker (HTTP, HTTPS, SOCKS4/5)")
    parser.add_argument("-i", "--input", help="Proxy list file (default: stdin)")
    parser.add_argument("-p", "--proxy", help="Single proxy or comma-separated list (host:port or host:port:user:pass)")
    parser.add_argument("-t", "--type", default="auto", help="Proxy type: http, https, socks4, socks5, auto (default)")
    parser.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Max concurrency (default 100)")
    parser.add_argument("-T", "--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout seconds (default 8)")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Retry count (default 2)")
    parser.add_argument("--geo", action="store_true", help="Enable IP geolocation lookup")
    parser.add_argument("--save-csv", help="Save results as CSV")
    parser.add_argument("--save-json", help="Save results as JSON")
    parser.add_argument("--save-alive", help="Save only alive proxies to file")
    parser.add_argument("--throughput", type=int, nargs="?", const=100, help="Throughput test (download size KB, default 100)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--quiet", action="store_true", help="Quiet mode")
    args = parser.parse_args()

    setup_logging(args.verbose, args.quiet)
    logging.info("Proxy Checker started.")

    proxies = []
    if args.input:
        proxies = load_proxies_from_file(args.input)
    proxies += load_proxies_from_args(args)
    if not proxies:
        print("No proxies provided. Use -i or -p. See --help.")
        sys.exit(2)

    scheme = parse_proxy_type(args.type) or "auto"
    if scheme == "auto":
        logging.info("Auto-detecting proxy type.")
    else:
        logging.info(f"Using proxy type: {scheme}")

    try:
        results = asyncio.run(run_proxies(
            proxies,
            scheme,
            args.concurrency,
            args.timeout,
            args.retries,
            args.geo,
            args.throughput,
            args.verbose
        ))
    except KeyboardInterrupt:
        print("Interrupted by user.")
        sys.exit(130)

    # Output
    alive = [r for r in results if r.get("ok")]
    print(f"\nTested {len(results)} proxies. Alive: {len(alive)}.\n")
    # Table output
    try:
        from tabulate import tabulate
        print(tabulate([
            [r["proxy"], r["scheme_tested"], r["ok"], r["anonymity"], r["latency_ms"], r["country"], r["last_error"]]
            for r in results
        ], headers=["Proxy", "Type", "OK", "Anonymity", "Latency", "Country", "Error"], tablefmt="github"))
    except ImportError:
        for r in results:
            print(f"{r['proxy']}\t{r['scheme_tested']}\t{r['ok']}\t{r['anonymity']}\t{r['latency_ms']}\t{r['country']}\t{r['last_error']}")

    if args.save_csv:
        save_csv(args.save_csv, results)
        print(f"Results saved to {args.save_csv}")
    if args.save_json:
        save_json(args.save_json, results)
        print(f"Results saved to {args.save_json}")
    if args.save_alive:
        save_alive(args.save_alive, results)
        print(f"Alive proxies saved to {args.save_alive}")

    # Exit code: number of failed proxies (0 = all ok)
    sys.exit(len(results) - len(alive))

if __name__ == "__main__":
    main()
