#!/usr/bin/env python3
"""one_worker_hook: Claude Code PreToolUse hook that blocks obvious parallel fan-out in Bash commands.

Blocks: pytest -n N / -n auto / --numprocesses, xargs -P (other than -P 1), GNU parallel, make -jN (N > 1 or bare -j),
two or more `&` background jobs in one command or a `&` inside a loop, and multiprocessing.Pool( / ProcessPoolExecutor( in inline code.
Override: start Claude Code with ONE_WORKER_OVERRIDE=1 in its environment (a human decision; the agent cannot set it per command).

Contract: reads the hook JSON on stdin; exit 0 = allow; exit 2 with a message on stderr = block (Claude Code shows the message to the
agent). Any error inside the hook allows the command (a broken hook must not wedge the agent).
"""
import json, os, re, sys

OVERRIDE = "ONE_WORKER_OVERRIDE"

_RULES = [
    (re.compile(r"(?:^|\s)-n\s*auto\b|--numprocesses(?:=|\s+)\S+|--dist(?:=|\s+)(?:load|each|worksteal)"), "pytest-xdist parallel workers"),
    (re.compile(r"\bpytest\b[^|;&]*\s-n\s*(?!0\b|1\b)\d+"), "pytest-xdist parallel workers"),
    (re.compile(r"\bxargs\b[^|;&]*\s-P\s*(?!1\b)\d+|\bxargs\b[^|;&]*--max-procs(?:=|\s+)(?!1\b)\d+"), "xargs -P parallel jobs"),
    (re.compile(r"(?:^|[;&|({]\s*|\b(?:nice|time|env)\s+(?:-n\s*\d+\s+)?)parallel\s"), "GNU parallel"),
    (re.compile(r"\bmake\b[^|;&]*\s-j\s*(?!1\b)(\d+|(?=\s|$))"), "make -j parallel build"),
    (re.compile(r"multiprocessing\.Pool\s*\(|\bPool\s*\(\s*(?:processes\s*=\s*)?\d|ProcessPoolExecutor\s*\("), "a multiprocessing pool"),
]


def _strip_quotes(cmd):
    """Blank out quoted strings so `&` inside quotes doesn't count (keeps length)."""
    return re.sub(r"'[^']*'|\"(?:\\.|[^\"\\])*\"", lambda m: " " * len(m.group()), cmd)


def _bg_jobs(cmd):
    c = _strip_quotes(cmd)
    c = re.sub(r"&&|\|&|[0-9]?>&[0-9-]?|&>>?|<&", " ", c)
    return c.count("&"), bool(re.search(r"&\s*(?:\n\s*)?done\b", c))


def check(cmd):
    """Returns a reason string if the command fans out, else None."""
    for rx, what in _RULES:
        if rx.search(cmd):
            return what
    n, in_loop = _bg_jobs(cmd)
    if in_loop:
        return "a background job (&) started inside a loop"
    if n >= 2:
        return "%d background jobs (&) in one command" % n
    return None


MESSAGE = """BLOCKED by one_worker_hook: this command starts %s.
Rule (ONE WORKER): every long job runs as exactly ONE process at `nice -n 19`, single-threaded:
  OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 VECLIB_MAXIMUM_THREADS=1 nice -n 19 <command>
No -n/xdist, no xargs -P, no parallel, no & fan-out, no process pools. Run the jobs one after another instead.
If a human has approved parallel work, they can restart Claude Code with %s=1."""


def main():
    try:
        ev = json.load(sys.stdin)
        if os.environ.get(OVERRIDE) == "1" or ev.get("tool_name") != "Bash":
            return 0
        why = check(str((ev.get("tool_input") or {}).get("command", "")))
    except Exception:  # never wedge the agent on a hook bug
        return 0
    if why:
        print(MESSAGE % (why, OVERRIDE), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
