#!/usr/bin/env python3
"""Low-impact public website monitor. Not a booking bot or availability scraper."""
import argparse
import hashlib
import json
import logging
import random
import sqlite3
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.robotparser import RobotFileParser

BASE = Path(__file__).resolve().parent
CONFIG = BASE / 'targets.json'
AGENT = 'AgencyResearchMonitor/0.1 (respectful public-page archiver; contact: configure-before-use)'
MAX_BYTES = 1_000_000
TIMEOUT = 12


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def init_db(conn):
    conn.execute('''CREATE TABLE IF NOT EXISTS checks (
        id INTEGER PRIMARY KEY, checked_at TEXT, name TEXT, url TEXT,
        outcome TEXT, http_status INTEGER, elapsed_ms INTEGER,
        sha256 TEXT, detail TEXT)''')
    conn.commit()


def record(conn, name, url, outcome, code, elapsed, digest='', detail=''):
    conn.execute('INSERT INTO checks (checked_at,name,url,outcome,http_status,elapsed_ms,sha256,detail) VALUES (?,?,?,?,?,?,?,?)',
                 (now(), name, url, outcome, code, int(elapsed*1000), digest, detail[:500]))
    conn.commit()
    logging.info('%s: %s status=%s duration=%.1fs %s', name, outcome, code, elapsed, detail[:100])


def parse_retry_after(value):
    if not value:
        return 0
    try:
        return max(0, min(86400, int(value)))
    except ValueError:
        try:
            return max(0, min(86400, int((parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds())))
        except Exception:
            return 0


def load_robots(url, cache):
    parsed = urlsplit(url)
    host = f'{parsed.scheme}://{parsed.netloc}'
    if host in cache and time.monotonic() - cache[host][0] < 86400:
        return cache[host][1]
    robots_url = host + '/robots.txt'
    try:
        request = Request(robots_url, headers={'User-Agent': AGENT, 'Accept': 'text/plain'})
        with urlopen(request, timeout=TIMEOUT) as response:
            body = response.read(100_000).decode('utf-8', 'replace')
        parser = RobotFileParser()
        parser.parse(body.splitlines())
        cache[host] = (time.monotonic(), parser)
        return parser
    except Exception as exc:
        logging.warning('Cannot verify robots policy at %s (%s). Skipping host.', host, exc)
        cache[host] = (time.monotonic(), None)
        return None


def check(target, conn, robots_cache, cooldown):
    name, url = target['name'], target['url']
    if time.time() < cooldown.get(url, 0):
        record(conn, name, url, 'COOLDOWN', None, 0, detail='Respecting Retry-After or error backoff')
        return
    robots = load_robots(url, robots_cache)
    if robots is None or not robots.can_fetch(AGENT, url):
        record(conn, name, url, 'SKIPPED_ROBOTS', None, 0, detail='Access not verified as permitted')
        return
    started = time.monotonic()
    try:
        request = Request(url, headers={'User-Agent': AGENT, 'Accept': 'text/html,application/xhtml+xml'})
        with urlopen(request, timeout=TIMEOUT) as response:
            code = response.status
            actual_url = response.geturl()
            # Redirects to another host/path must also be allowed by robots.txt.
            redirect_robots = load_robots(actual_url, robots_cache)
            if redirect_robots is None or not redirect_robots.can_fetch(AGENT, actual_url):
                record(conn, name, url, 'SKIPPED_REDIRECT', code, time.monotonic()-started)
                return
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type:
                record(conn, name, url, 'NON_HTML', code, time.monotonic()-started, detail=content_type)
                return
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                record(conn, name, url, 'TOO_LARGE', code, time.monotonic()-started)
                return
            digest = hashlib.sha256(body).hexdigest()
            prior = conn.execute('SELECT sha256 FROM checks WHERE name=? AND sha256<>"" ORDER BY id DESC LIMIT 1', (name,)).fetchone()
            if not prior or prior[0] != digest:
                output_dir = BASE / 'snapshots' / name
                output_dir.mkdir(parents=True, exist_ok=True)
                filename = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + digest[:10] + '.html'
                (output_dir / filename).write_bytes(body)
            record(conn, name, url, 'HTML_OK' if code == 200 else 'HTTP_OTHER', code,
                   time.monotonic()-started, digest, 'changed' if not prior or prior[0] != digest else 'unchanged')
    except HTTPError as exc:
        retry = parse_retry_after(exc.headers.get('Retry-After'))
        if exc.code in (429, 503):
            cooldown[url] = time.time() + max(3600, retry)
        record(conn, name, url, 'HTTP_ERROR', exc.code, time.monotonic()-started,
               detail=f'Retry-After={retry}s; cooldown on 429/503')
    except (TimeoutError, URLError, OSError) as exc:
        cooldown[url] = time.time() + 3600
        record(conn, name, url, 'NETWORK_ERROR', None, time.monotonic()-started, detail=str(exc))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--once', action='store_true', help='Run one low-impact pass and exit')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    config = json.loads(CONFIG.read_text(encoding='utf-8'))
    interval = max(1800, int(config.get('interval_seconds', 1800)))
    conn = sqlite3.connect(BASE / 'monitor.sqlite3')
    init_db(conn)
    robots_cache, cooldown = {}, {}
    logging.info('Monitoring %s public targets; minimum repeat interval %ss', len(config['targets']), interval)
    try:
        while True:
            for target in config['targets']:
                check(target, conn, robots_cache, cooldown)
                time.sleep(5)  # Avoid adjacent requests, including across related domains.
            if args.once:
                break
            time.sleep(interval + random.randint(0, 120))
    except KeyboardInterrupt:
        logging.info('Stopped')
    finally:
        conn.close()


if __name__ == '__main__':
    main()
