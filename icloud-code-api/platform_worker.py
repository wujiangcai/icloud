"""Periodic IMAP synchronizer for the multi-tenant platform.

Run this as a separate process from Uvicorn so a slow IMAP server cannot block
HTTP workers and so only one scheduler owns the polling loop.
"""

from __future__ import annotations

import os
import signal
import time
from datetime import datetime, timezone

from platform_app import env_int, sync_all_mailboxes


INTERVAL_SECONDS = env_int("PLATFORM_WORKER_INTERVAL_SECONDS", 30, 10, 3600)
STOP = False


def stop_worker(_signum: int, _frame: object) -> None:
    global STOP
    STOP = True


def main() -> None:
    signal.signal(signal.SIGINT, stop_worker)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop_worker)
    print(f"platform worker started; interval={INTERVAL_SECONDS}s", flush=True)
    while not STOP:
        started = time.monotonic()
        try:
            results = sync_all_mailboxes()
            ok = sum(1 for item in results if item.get("ok"))
            print(
                f"{datetime.now(timezone.utc).isoformat()} sync complete: "
                f"mailboxes={len(results)} ok={ok} failed={len(results) - ok}",
                flush=True,
            )
        except Exception as exc:  # keep the scheduler alive after a DB/IMAP error
            print(f"worker cycle failed: {type(exc).__name__}: {exc}", flush=True)
        elapsed = time.monotonic() - started
        wait_for = max(1.0, INTERVAL_SECONDS - elapsed)
        end = time.monotonic() + wait_for
        while not STOP and time.monotonic() < end:
            time.sleep(min(1.0, end - time.monotonic()))
    print("platform worker stopped", flush=True)


if __name__ == "__main__":
    main()
