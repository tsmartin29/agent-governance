import json, os, pathlib, subprocess, sys

import pytest

HOOK = pathlib.Path(__file__).resolve().parents[1] / "hooks" / "one_worker_hook.py"
sys.path.insert(0, str(HOOK.parent))
from one_worker_hook import check  # noqa: E402

BLOCK = [
    "pytest -n auto tests/",
    "python -m pytest -q -n 8 tests/test_x.py",
    "pytest --numprocesses=4",
    "find . -name '*.wav' | xargs -P 8 -n 1 ffmpeg -i",
    "ls | xargs -P0 gzip",
    "parallel ./sim.sh ::: 1 2 3",
    "cat jobs | nice -n 19 parallel -j4 run",
    "make -j8",
    "make -j",
    "./a.sh & ./b.sh & wait",
    "for i in 1 2 3; do ./sim $i & done; wait",
    "python -c 'import multiprocessing; multiprocessing.Pool(8).map(f, xs)'",
    "python - <<EOF\nfrom concurrent.futures import ProcessPoolExecutor\nProcessPoolExecutor(8)\nEOF",
]
ALLOW = [
    "OMP_NUM_THREADS=1 nice -n 19 python -m pytest -q tests/test_x.py",
    "pytest -n 1 tests/",
    "make -j1 && make install",
    "ls -la 2>&1 | head -n 5",
    "cmd > out.log 2>&1 &",
    "git log -n 3 && git status",
    "echo 'a & b & c'",
    "xargs -n 1 echo < list.txt",
    "make test",
    "nice -n 19 ./run.sh",
    "grep -rn parallel docs/",
]


@pytest.mark.parametrize("cmd", BLOCK)
def test_blocks_fan_out(cmd):
    assert check(cmd), cmd


@pytest.mark.parametrize("cmd", ALLOW)
def test_allows_single_worker(cmd):
    assert check(cmd) is None, (cmd, check(cmd))


def run(ev, **env):
    e = {k: v for k, v in os.environ.items() if k != "ONE_WORKER_OVERRIDE"}
    e.update(env)
    return subprocess.run([sys.executable, str(HOOK)], input=json.dumps(ev), capture_output=True, text=True, env=e)


def test_hook_contract():
    r = run({"tool_name": "Bash", "tool_input": {"command": "pytest -n auto"}})
    assert r.returncode == 2 and "BLOCKED by one_worker_hook" in r.stderr and "ONE_WORKER_OVERRIDE=1" in r.stderr
    assert run({"tool_name": "Bash", "tool_input": {"command": "pytest -q"}}).returncode == 0
    assert run({"tool_name": "Bash", "tool_input": {"command": "pytest -n auto"}}, ONE_WORKER_OVERRIDE="1").returncode == 0
    assert run({"tool_name": "Read", "tool_input": {"file_path": "x"}}).returncode == 0
    r = subprocess.run([sys.executable, str(HOOK)], input="not json", capture_output=True, text=True)
    assert r.returncode == 0  # a hook bug never wedges the agent
