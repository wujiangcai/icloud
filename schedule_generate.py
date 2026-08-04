#!/usr/bin/env python3
"""Run the recurring Hide My Email generation job.

The first successful run creates four aliases. Later successful runs create
five aliases. The state is kept under ``icloud-code-api/data`` so a scheduled
task can be restarted without losing its place.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
API_DIR = ROOT / "icloud-code-api"
GENERATOR_DIR = ROOT / "hidemyemail-generator"
GENERATOR_PYTHON = GENERATOR_DIR / ".venv" / "Scripts" / "python.exe"
GENERATOR_SCRIPT = API_DIR / "generate_and_import.py"
DATA_DIR = API_DIR / "data"
STATE_PATH = DATA_DIR / "hme_schedule_state.json"
LOCK_PATH = DATA_DIR / "hme_schedule.lock"
LOG_PATH = DATA_DIR / "hme_schedule.log"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def read_state() -> dict[str, object]:
    if not STATE_PATH.exists():
        return {"completed_runs": 0}
    try:
        value = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"completed_runs": 0}
    return value if isinstance(value, dict) else {"completed_runs": 0}


def write_state(state: dict[str, object]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temporary = STATE_PATH.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    temporary.replace(STATE_PATH)


def acquire_lock() -> bool:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            LOCK_PATH,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
    except FileExistsError:
        try:
            if time.time() - LOCK_PATH.stat().st_mtime > 2 * 60 * 60:
                LOCK_PATH.unlink()
                return acquire_lock()
        except OSError:
            pass
        return False

    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(f"pid={os.getpid()}\nstarted={now_iso()}\n")
    return True


def release_lock() -> None:
    try:
        LOCK_PATH.unlink()
    except FileNotFoundError:
        pass


def safe_log_text(text: str) -> str:
    """Keep generated addresses and API credentials out of the scheduler log."""
    text = re.sub(
        r"[A-Za-z0-9._%+\-]+@icloud\.com",
        "<alias>@icloud.com",
        text,
        flags=re.IGNORECASE,
    )
    return re.sub(
        r'("(?:api_key|credential)"\s*:\s*")[^"]*',
        r'\1<redacted>',
        text,
        flags=re.IGNORECASE,
    )


def append_log(text: str) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(safe_log_text(text))
        if not text.endswith("\n"):
            handle.write("\n")


def run_once(
    *,
    initial_count: int,
    recurring_count: int,
    success_delay: int,
    failure_delay: int,
    max_failures: int,
    timeout_minutes: int,
    force_count: int | None = None,
) -> int:
    if not acquire_lock():
        append_log(f"[{now_iso()}] skipped: another scheduled run is active")
        return 0

    try:
        state = read_state()
        try:
            completed_runs = max(0, int(state.get("completed_runs", 0)))
        except (TypeError, ValueError):
            completed_runs = 0
        count = (
            force_count
            if force_count is not None
            else (initial_count if completed_runs == 0 else recurring_count)
        )
        if count < 1:
            append_log(f"[{now_iso()}] error: count must be at least 1")
            return 2

        if not GENERATOR_PYTHON.exists():
            append_log(f"[{now_iso()}] error: Python runtime not found: {GENERATOR_PYTHON}")
            return 2
        if not GENERATOR_SCRIPT.exists():
            append_log(f"[{now_iso()}] error: generator script not found: {GENERATOR_SCRIPT}")
            return 2

        command = [
            str(GENERATOR_PYTHON),
            str(GENERATOR_SCRIPT),
            "--count",
            str(count),
            "--success-delay",
            str(max(0, success_delay)),
            "--failure-delay",
            str(max(0, failure_delay)),
        ]
        append_log(
            f"[{now_iso()}] starting run: count={count}, completed_runs={completed_runs}\n"
        )
        environment = {
            **os.environ,
            "HME_MAX_FAILURES": str(max(0, max_failures)),
        }
        try:
            completed = subprocess.run(
                command,
                cwd=str(API_DIR),
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(1, timeout_minutes) * 60,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            append_log(
                f"[{now_iso()}] timed out after {timeout_minutes} minutes\n"
                + (exc.stdout or "")
            )
            return 1

        append_log(completed.stdout or "")
        if completed.returncode != 0:
            append_log(f"[{now_iso()}] run failed: exit={completed.returncode}\n")
            return completed.returncode

        state.update(
            {
                "completed_runs": completed_runs + 1,
                "last_count": count,
                "last_success_at": now_iso(),
            }
        )
        write_state(state)
        append_log(f"[{now_iso()}] run completed successfully\n")
        return 0
    finally:
        release_lock()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run scheduled iCloud Hide My Email generation"
    )
    parser.add_argument("--scheduled", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--initial-count", type=int, default=4)
    parser.add_argument("--recurring-count", type=int, default=5)
    parser.add_argument("--success-delay", type=int, default=240)
    parser.add_argument("--failure-delay", type=int, default=600)
    parser.add_argument("--max-failures", type=int, default=3)
    parser.add_argument("--timeout-minutes", type=int, default=27)
    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Run a one-off fixed count without changing the first/recurring rule",
    )
    args = parser.parse_args()
    return run_once(
        initial_count=args.initial_count,
        recurring_count=args.recurring_count,
        success_delay=args.success_delay,
        failure_delay=args.failure_delay,
        max_failures=args.max_failures,
        timeout_minutes=args.timeout_minutes,
        force_count=args.count,
    )


if __name__ == "__main__":
    raise SystemExit(main())
