# Spanish government portal research monitor

A read-only **public HTML availability monitor**, not an appointment availability scraper, robot, or auto-booking system.

## What it does
- Every **at least 30 minutes**, checks four configured public URLs sequentially.
- Honors `robots.txt`, skips hosts if policy cannot be verified, and avoids retry storms.
- On HTTP 429/503, waits at least one hour before probing that URL again (and honors longer `Retry-After`).
- On network failures, delays further requests to the target.
- Saves changed public HTML snapshots under `snapshots/` (max 1 MB each).
- Records timestamps, HTTP responses, errors, elapsed times, and content hashes in SQLite.
- Does not access authentication forms, bypass anti-bot controls, reserve appointments, or infer actual appointment availability.

## Run
Python 3.10+; no external packages needed.

```bash
python3 monitor.py --once  # optional one-pass local validation
python3 monitor.py         # continuous; stop with Ctrl+C
```

For persistent operation on Linux, run it with a process supervisor such as `systemd`, ensuring the agency has permission for the selected endpoints. Do not reduce the 30-minute minimum without site authorization. The monitoring script is not running merely because you downloaded it.

## Inspect results

```bash
python3 - <<'PY'
import sqlite3
c = sqlite3.connect('monitor.sqlite3')
for row in c.execute('SELECT checked_at,name,outcome,http_status,elapsed_ms,detail FROM checks ORDER BY id DESC LIMIT 20'):
    print(row)
PY
```

## Known limitations
- There is no verified public appointment API in this project.
- Mercurio is an online immigration application portal, **not another instance of the appointment-booking site**.
- Public HTML does not reveal government backend source code.
- HTML may change because of dynamic tokens and therefore generate snapshots even without a meaningful page redesign.
- The script follows only public, unauthenticated pages; remove any URL that does not permit monitoring.
