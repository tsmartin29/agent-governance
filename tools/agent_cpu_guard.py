#!/usr/bin/env python3
"""agent_cpu_guard: keeps AI coding agents (Claude Code) from swamping a shared computer.

Each Claude Code process (`claude`) is an agent root; everything it starts is its tree. When a tree's workers use more than
--max-cores cores or more than --max-procs running processes, the guard renices them to 19, SIGSTOPs the excess (newest first),
logs the reason, and SIGCONTs them one at a time (oldest stopped first) when the tree and the machine have room again.

Never touched: the agent root itself, other users' processes, apps (anything inside a .app bundle or /Applications), MCP servers,
the guard and its ancestors, and any process listening on a protected port together with its ancestors and descendants.
--dry-run is the default: it prints what it WOULD do and changes nothing. --enforce acts. On exit an enforcing guard SIGCONTs
everything it stopped; `--release-all` does the same from a fresh shell.

Usage:  python3 agent_cpu_guard.py --once            # dry run, one look
        python3 agent_cpu_guard.py --enforce         # act, every --interval seconds
"""
import argparse, json, os, re, signal, subprocess, sys, time
from dataclasses import dataclass

# Ports whose listeners (and their process trees) are never touched. Add yours with --protect-port or AGENT_GUARD_PROTECT_PORTS="5000,8080".
PROTECTED_PORTS = tuple(int(x) for x in os.environ.get("AGENT_GUARD_PROTECT_PORTS", "").replace(" ", "").split(",") if x)
STATE_DIR = os.path.expanduser("~/.agent_cpu_guard")
_INFRA = re.compile(r"(\bmcp\b|mcp-server|modelcontextprotocol|server-filesystem)", re.I)
_APP = re.compile(r"^(/Applications/|/System/|%s/Applications/)" % re.escape(os.path.expanduser("~")))  # installed apps
_ROOT = re.compile(r"(^|/)claude(\s|$)|@anthropic-ai/claude-code")


@dataclass(frozen=True)
class Proc:
    pid: int
    ppid: int
    uid: int
    nice: int
    stat: str
    cpu_s: float
    start: str
    args: str

    @property
    def key(self):
        return "%d@%s" % (self.pid, self.start)

    @property
    def stopped(self):
        return "T" in self.stat


def _cpu_seconds(t):
    days = 0
    if "-" in t:
        d, t = t.split("-", 1)
        days = int(d)
    parts = [float(x) for x in t.split(":")]
    s = 0.0
    for x in parts:
        s = s * 60 + x
    return days * 86400 + s


def _start_epoch(start):
    try:
        return time.mktime(time.strptime(start, "%a %b %d %H:%M:%S %Y"))
    except ValueError:
        return 0.0


def snapshot():
    out = subprocess.run(["ps", "-axww", "-o", "pid=,ppid=,uid=,nice=,stat=,time=,lstart=,args="],
                         capture_output=True, text=True, check=True).stdout
    procs = {}
    for ln in out.splitlines():
        f = ln.split(None, 11)
        if len(f) < 11:
            continue
        try:
            p = Proc(int(f[0]), int(f[1]), int(f[2]), int(f[3]), f[4], _cpu_seconds(f[5]), " ".join(f[6:11]), f[11] if len(f) > 11 else "")
        except ValueError:
            continue
        procs[p.pid] = p
    return procs


def listeners():
    """{pid: set(ports)} for TCP listeners (lsof)."""
    try:
        out = subprocess.run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpn"], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    res, pid = {}, None
    for ln in out.splitlines():
        if ln.startswith("p"):
            pid = int(ln[1:])
        elif ln.startswith("n") and pid is not None and ":" in ln:
            try:
                res.setdefault(pid, set()).add(int(ln.rsplit(":", 1)[1]))
            except ValueError:
                pass
    return res


def children_map(procs):
    kids = {}
    for p in procs.values():
        kids.setdefault(p.ppid, []).append(p.pid)
    return kids


def descendants(pid, kids):
    out, todo = [], list(kids.get(pid, []))
    while todo:
        c = todo.pop()
        out.append(c)
        todo.extend(kids.get(c, []))
    return out


def ancestors(pid, procs):
    out = []
    while pid in procs and procs[pid].ppid not in (0, pid) and pid > 1:
        pid = procs[pid].ppid
        out.append(pid)
    return out


def _argv0(args):
    return args.split(" --")[0]


def agent_roots(procs):
    return sorted(p.pid for p in procs.values() if _ROOT.search(_argv0(p.args)) and not _APP.search(p.args))


def protected(procs, kids, listen, ports, me=None):
    """pids the guard must never touch."""
    me = os.getpid() if me is None else me
    uid = os.getuid()
    prot = {me, *ancestors(me, procs)}
    for pid, p in procs.items():
        if pid <= 1 or p.uid != uid or _APP.search(p.args) or _INFRA.search(p.args):
            prot.add(pid)
    for pid, ps in listen.items():
        if pid in procs and ps & set(ports):
            prot.add(pid)
            prot.update(ancestors(pid, procs))
            prot.update(descendants(pid, kids))
    return prot


def plan(workers, cores, stopped, max_cores=2.0, max_procs=8, load_ok=True):
    """Pure decision for one agent tree. workers: [Proc] (not protected), cores: {key: cores used}, stopped: {key: record} the guard
    stopped earlier. Returns [(action, Proc, reason)] with action in renice | stop | cont."""
    running = [p for p in workers if p.key not in stopped and not p.stopped]
    total = sum(cores.get(p.key, 0.0) for p in running)
    acts = []
    if len(running) > max_procs or total > max_cores + 1e-9:
        why = "agent tree uses %.2f cores and %d running processes (limits %g cores, %d processes)" % (total, len(running), max_cores, max_procs)
        acts += [("renice", p, why) for p in running if p.nice < 19]
        newest = sorted(running, key=lambda p: (_start_epoch(p.start), p.pid), reverse=True)
        n_excess = max(0, len(running) - max_procs)
        stop = newest[:n_excess]
        left = total - sum(cores.get(p.key, 0.0) for p in stop)
        for p in newest[n_excess:]:
            if left <= max_cores + 1e-9:
                break
            c = cores.get(p.key, 0.0)
            if c >= 0.05:
                stop.append(p)
                left -= c
        acts += [("stop", p, why) for p in stop]
        return acts
    mine = [p for p in workers if p.key in stopped]
    if mine and load_ok:
        p = min(mine, key=lambda p: stopped[p.key].get("stopped_at", 0))
        est = min(1.0, stopped[p.key].get("cores", 1.0))
        if len(running) + 1 <= max_procs and total + est <= 0.75 * max_cores:
            acts.append(("cont", p, "room again: %.2f cores, %d running" % (total, len(running))))
    return acts


class Guard:
    def __init__(self, enforce=False, max_cores=2.0, max_procs=8, ports=PROTECTED_PORTS, roots=None, state_dir=STATE_DIR,
                 sample=2.0, out=sys.stdout, verbose=False):
        self.enforce, self.max_cores, self.max_procs, self.ports = enforce, max_cores, max_procs, tuple(ports)
        self.roots, self.sample, self.out, self.verbose = roots, sample, out, verbose
        self.state_path = os.path.join(state_dir, "stopped.json")
        self.log_path = os.path.join(state_dir, "guard.log")
        self.state_dir = state_dir
        self.stopped = self._load()

    def _load(self):
        try:
            return json.load(open(self.state_path))
        except (OSError, ValueError):
            return {}

    def _save(self):
        if not self.enforce:
            return
        os.makedirs(self.state_dir, exist_ok=True)
        tmp = self.state_path + ".tmp"
        json.dump(self.stopped, open(tmp, "w"), indent=1, sort_keys=True)
        os.replace(tmp, self.state_path)

    def _log(self, rec):
        rec = dict(rec, t=time.strftime("%Y-%m-%d %H:%M:%S"), mode="enforce" if self.enforce else "dry-run")
        if self.enforce:
            os.makedirs(self.state_dir, exist_ok=True)
            with open(self.log_path, "a") as f:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
        print(("" if self.enforce else "WOULD ") + "%(action)s pid %(pid)s (agent %(agent)s): %(cmd)s -- %(reason)s" % rec, file=self.out)

    def tick(self):
        a = snapshot()
        t0 = time.time()
        time.sleep(self.sample)
        b = snapshot()
        dt = max(1e-3, time.time() - t0)
        cores = {p.key: max(0.0, (p.cpu_s - a[p.pid].cpu_s) / dt) for p in b.values() if p.pid in a and a[p.pid].start == p.start}
        kids = children_map(b)
        prot = protected(b, kids, listeners(), self.ports)
        roots = self.roots if self.roots is not None else agent_roots(b)
        # forget records whose process is gone or was reused
        alive = {p.key for p in b.values()}
        for k in [k for k in self.stopped if k not in alive]:
            del self.stopped[k]
        load_ok = os.getloadavg()[0] < 0.75 * (os.cpu_count() or 1)
        report = []
        for r in roots:
            if r not in b:
                continue
            tree = descendants(r, kids)
            workers = [b[c] for c in tree if c not in prot and c != r]
            if self.verbose:
                run = [p for p in workers if p.key not in self.stopped and not p.stopped]
                print("agent %d: %d processes in tree, %d workers (%d running, %.2f cores), %d protected" % (
                    r, len(tree), len(workers), len(run), sum(cores.get(p.key, 0.0) for p in run), len(tree) - len(workers)), file=self.out)
            for action, p, why in plan(workers, cores, self.stopped, self.max_cores, self.max_procs, load_ok):
                self._act(action, p, r, why, cores.get(p.key, 0.0))
                report.append((action, p.pid))
        self._save()
        return report

    def _act(self, action, p, root, why, c):
        self._log(dict(action=action, pid=p.pid, agent=root, cmd=p.args[:120], reason=why))
        if not self.enforce:
            return
        try:
            if action == "renice":
                os.setpriority(os.PRIO_PROCESS, p.pid, 19)
            elif action == "stop":
                os.kill(p.pid, signal.SIGSTOP)
                self.stopped[p.key] = dict(pid=p.pid, agent=root, stopped_at=time.time(), cores=c, reason=why)
            elif action == "cont":
                os.kill(p.pid, signal.SIGCONT)
                self.stopped.pop(p.key, None)
        except (ProcessLookupError, PermissionError) as e:
            self._log(dict(action="skip", pid=p.pid, agent=root, cmd=p.args[:120], reason="%s failed: %s" % (action, e)))

    def release_all(self):
        procs = snapshot()
        for k, rec in list(self.stopped.items()):
            p = procs.get(rec["pid"])
            if p is not None and p.key == k:
                if self.enforce:
                    try:
                        os.kill(p.pid, signal.SIGCONT)
                    except ProcessLookupError:
                        pass
                self._log(dict(action="cont", pid=p.pid, agent=rec.get("agent"), cmd=p.args[:120], reason="guard exiting / release-all"))
            if self.enforce:
                del self.stopped[k]
        self._save()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true", default=True, help="print what would happen (default)")
    g.add_argument("--enforce", action="store_true", help="actually renice / stop / continue")
    ap.add_argument("--once", action="store_true", help="one look, then exit")
    ap.add_argument("--release-all", action="store_true", help="SIGCONT everything the guard stopped, then exit")
    ap.add_argument("--max-cores", type=float, default=2.0)
    ap.add_argument("--max-procs", type=int, default=8)
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--sample", type=float, default=2.0, help="seconds between the two CPU samples")
    ap.add_argument("--protect-port", type=int, action="append", help="never touch listeners on this port (repeatable)")
    ap.add_argument("--root", type=int, action="append", help="treat this pid as an agent root instead of auto-detecting")
    ap.add_argument("--state-dir", default=STATE_DIR)
    a = ap.parse_args(argv)
    try:
        os.setpriority(os.PRIO_PROCESS, 0, 19)
    except OSError:
        pass
    gd = Guard(enforce=a.enforce, max_cores=a.max_cores, max_procs=a.max_procs,
               ports=PROTECTED_PORTS + tuple(a.protect_port or ()), roots=a.root, state_dir=a.state_dir, sample=a.sample,
               verbose=a.once)
    if a.release_all:
        gd.enforce = True
        gd.release_all()
        return 0

    def bye(*_):
        if gd.enforce:
            gd.release_all()
        sys.exit(0)

    signal.signal(signal.SIGTERM, bye)
    signal.signal(signal.SIGINT, bye)
    if not a.enforce:
        print("agent_cpu_guard: DRY RUN (nothing is changed; add --enforce to act). Limits: %g cores, %d processes per agent; "
              "protected ports %s" % (a.max_cores, a.max_procs, ", ".join(map(str, gd.ports)) or "none"))
    while True:
        r = gd.tick()
        if a.once:
            if not r:
                print("nothing to do: every agent tree is within limits")
            return 0
        time.sleep(a.interval)


if __name__ == "__main__":
    sys.exit(main())
