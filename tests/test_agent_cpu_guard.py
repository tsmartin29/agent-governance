"""Guard tests. Real-process tests use only harmless `sleep` children at nice 19 under a test-owned root, never real agent trees,
and kill every process they start."""
import io, os, pathlib, signal, socket, subprocess, sys, time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import agent_cpu_guard as g  # noqa: E402


def P(pid, start_min, nice=0, stat="S", args="python worker.py"):
    return g.Proc(pid, 1, os.getuid(), nice, stat, 0.0, "Fri Oct 30 02:%02d:00 2026" % start_min, args)


def test_proc_count_stops_newest_first():
    ws = [P(100 + i, i) for i in range(10)]
    acts = g.plan(ws, {}, {}, max_cores=2, max_procs=8)
    assert sorted(p.pid for a, p, _ in acts if a == "stop") == [108, 109]
    assert len([a for a, _, _ in acts if a == "renice"]) == 10
    assert all("10 running processes" in why for _, _, why in acts)


def test_cpu_stops_newest_busy_until_under_limit():
    ws = [P(200 + i, i, nice=19) for i in range(4)]
    cores = {ws[0].key: 0.9, ws[1].key: 0.9, ws[2].key: 0.9, ws[3].key: 0.0}
    acts = g.plan(ws, cores, {}, max_cores=2, max_procs=8)
    assert [(a, p.pid) for a, p, _ in acts] == [("stop", 202)]  # newest idle one skipped; already nice 19: no renice


def test_continue_when_room_and_never_when_busy():
    ws = [P(300, 0), P(301, 1, stat="T")]
    stopped = {ws[1].key: dict(stopped_at=1.0, cores=0.5)}
    assert [(a, p.pid) for a, p, _ in g.plan(ws, {ws[0].key: 0.2}, stopped)] == [("cont", 301)]
    assert g.plan(ws, {ws[0].key: 1.4}, stopped) == []  # 1.4 + 0.5 > 75% of 2 cores
    assert g.plan(ws, {ws[0].key: 0.2}, stopped, load_ok=False) == []


def test_within_limits_does_nothing():
    ws = [P(400 + i, i) for i in range(8)]
    assert g.plan(ws, {w.key: 0.2 for w in ws}, {}) == []


def test_protected_listeners_apps_and_mcp():
    procs = {
        1: g.Proc(1, 0, 0, 0, "S", 0, "x", "launchd"),
        10: g.Proc(10, 1, os.getuid(), 0, "S", 0, "x", "/x/claude --verbose"),
        11: g.Proc(11, 10, os.getuid(), 0, "S", 0, "x", "/bin/zsh -c serve"),
        12: g.Proc(12, 11, os.getuid(), 0, "S", 0, "x", "python -m http.server 19963"),
        13: g.Proc(13, 12, os.getuid(), 0, "S", 0, "x", "python helper"),
        14: g.Proc(14, 10, os.getuid(), 0, "S", 0, "x", "node mcp-server-foo"),
        15: g.Proc(15, 10, os.getuid(), 0, "S", 0, "x", "/Applications/Ableton Live 12 Suite.app/Contents/MacOS/Live"),
        16: g.Proc(16, 10, os.getuid() + 1, 0, "S", 0, "x", "other user"),
        17: g.Proc(17, 10, os.getuid(), 0, "S", 0, "x", "pytest -x"),
    }
    prot = g.protected(procs, g.children_map(procs), {12: {19963}}, (19963,), me=999999)
    assert {11, 12, 13, 14, 15, 16, 1} <= prot and 17 not in prot
    assert g.agent_roots(procs) == [10]


def _free_port():
    for port in range(29400, 29999):
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            s.close()
    raise RuntimeError("no free port in 29400-29999")


CHILD = r"""
import os, socket, subprocess, sys, time
port = int(sys.argv[1])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", port)); s.listen(1)
kids = []
for i in range(10):
    kids.append(subprocess.Popen(["sleep", "120"]))
    time.sleep(1.1)  # distinct start seconds so "newest" is well defined
print(" ".join(str(k.pid) for k in kids), flush=True)
time.sleep(120)
"""


@pytest.fixture
def tree():
    port = _free_port()
    root = subprocess.Popen(["nice", "-n", "19", sys.executable, "-c", CHILD, str(port)], stdout=subprocess.PIPE, text=True,
                            start_new_session=True)
    try:
        kids = [int(x) for x in root.stdout.readline().split()]
        yield root, kids, port
    finally:
        try:
            os.killpg(root.pid, signal.SIGCONT)
            os.killpg(root.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        root.wait(timeout=10)
        time.sleep(0.2)
        left = subprocess.run(["pgrep", "-g", str(root.pid)], capture_output=True, text=True).stdout.split()
        assert left == [], "test left processes running: %s" % left


def _stat(pid):
    return subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()


def test_real_tree_dry_run_changes_nothing(tree, tmp_path):
    root, kids, port = tree
    out = io.StringIO()
    gd = g.Guard(enforce=False, roots=[root.pid], state_dir=str(tmp_path), sample=0.2, out=out, ports=())
    gd.tick()
    assert "WOULD stop pid %d" % kids[-1] in out.getvalue()
    assert all("T" not in _stat(k) for k in kids) and not (tmp_path / "stopped.json").exists()


def test_real_tree_enforce_stop_and_release(tree, tmp_path):
    root, kids, port = tree
    # the root listens on a protected port: it and its descendants are untouchable
    gd = g.Guard(enforce=True, roots=[root.pid], state_dir=str(tmp_path), sample=0.2, out=io.StringIO(), ports=(port,))
    assert gd.tick() == []
    # same tree, port not protected: 10 sleep workers + the root python's own tree, limit 8 -> newest two stopped
    gd = g.Guard(enforce=True, roots=[root.pid], state_dir=str(tmp_path), sample=0.2, out=io.StringIO(), ports=())
    acts = gd.tick()
    stopped = sorted(pid for a, pid in acts if a == "stop")
    assert stopped == sorted(kids[-2:])
    assert all("T" in _stat(k) for k in stopped) and all("T" not in _stat(k) for k in kids[:-2])
    assert all(os.getpriority(os.PRIO_PROCESS, k) >= 19 for k in kids)
    log = (tmp_path / "guard.log").read_text()
    assert "running processes" in log and '"action": "stop"' in log
    gd.release_all()
    assert all("T" not in _stat(k) for k in kids) and gd.stopped == {}
