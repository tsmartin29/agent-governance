import json, pytest
from agent_governance.env import AIEnv, Rejected

K = b"op-key"

def env(tmp_path):
    e = AIEnv(str(tmp_path / "env.jsonl"), K)
    e.set_goal("reach every person", "staff_counted_pct", 100.0)
    return e

def test_rejects_user_content(tmp_path):
    e = env(tmp_path)
    with pytest.raises(Rejected):
        e.note("roster", name="Alex")
    with pytest.raises(Rejected):
        e.note("x", detail="call +1 555 010 0199")
    e.note("site run", staff_counted=1906, staff_total=2127)

def test_reload_and_tamper(tmp_path):
    e = env(tmp_path); e.note("a", n=1)
    assert AIEnv(e.path, K).reload().goal()["target"] == 100.0
    lines = open(e.path).read().splitlines(); d = json.loads(lines[0]); d["data"]["target"] = 50
    open(e.path, "w").write("\n".join([json.dumps(d, sort_keys=True)] + lines[1:]) + "\n")
    with pytest.raises(Rejected):
        AIEnv(e.path, K).reload()

def test_gate(tmp_path):
    e = env(tmp_path)
    e.correct("flash", "identify the board by its boot name before flashing", forbid={"board": "assumed"})
    e.record_error("assumed_identity", "know:board_boot_name", scope="flash")
    assert e.propose("flash", {"board": "booth"}, lambda p: 100)[0] == "request"
    assert e.propose("flash", {"board": "assumed"}, lambda p: 100, known=("board_boot_name",))[0] == "conflict"
    assert e.propose("plan", {"collectors": 91}, lambda p: 98.7)[0] == "withheld"
    assert e.propose("plan", {"collectors": 120}, lambda p: 100.0)[0] == "offer"
    assert [x["data"]["fact"] for x in e.entries if x["kind"] == "request"] == ["board_boot_name"]

def test_lessons_need_signoff(tmp_path):
    a, b = env(tmp_path), AIEnv(str(tmp_path / "b.jsonl"), K)
    board = str(tmp_path / "lessons.jsonl")
    a.lesson("ask which board is connected before flashing", "flash", "know:board_boot_name", board)
    assert b.active_lessons(board) == []
    b.signoff(board, "ask which board is connected before flashing")
    assert [l["scope"] for l in b.active_lessons(board)] == ["flash"]

def test_hashes_are_admitted_phone_numbers_are_not(tmp_path):
    e = env(tmp_path)
    e.note("ref", run="29f8704288996ff3ef7ff356af5f14c21917a0aa07b35de03967d0ca460c572d")
    with pytest.raises(Rejected):
        e.note("x", ref="15550100199")
