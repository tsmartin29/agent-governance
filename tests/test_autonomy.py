from agent_governance import env as ai_env
from agent_governance.env import AIEnv
from agent_governance.autonomy import DAY, Policy, accept, autonomy, cap, decide

K = b"op-key"


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def time(self):
        return self.t


def env(tmp_path, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(ai_env, "time", clock)
    e = AIEnv(str(tmp_path / "env.jsonl"), K)
    e.set_goal("reach every person", "counted_pct", 100.0)
    return e, clock


def earn(e, clock, scope, passes, accepts):
    for i in range(passes):
        clock.t += 60
        st, _ = e.propose(scope, {"n": i}, lambda p: 100.0, known=("run_id", "board"))
        assert st == "offer"
        if i < accepts:
            accept(e, e.entries[-1])


def test_fresh_scope_is_level_0(tmp_path, monkeypatch):
    e, clock = env(tmp_path, monkeypatch)
    lv = autonomy(e.entries, "plan", clock.t)
    assert lv.level == 0 and lv.mode == "propose_only"
    assert "level 1 needs 5 passes and 2 accepted" in lv.reason


def test_record_earns_level_1_then_2(tmp_path, monkeypatch):
    e, clock = env(tmp_path, monkeypatch)
    earn(e, clock, "plan", 5, 2)
    lv = autonomy(e.entries, "plan", clock.t)
    assert (lv.level, lv.passes, lv.accepted) == (1, 5, 2)
    assert lv.reason.startswith("level 1 because 5 verified")
    earn(e, clock, "plan", 7, 4)
    lv = autonomy(e.entries, "plan", clock.t)
    assert (lv.level, lv.passes, lv.accepted) == (2, 12, 6) and "no errors ever" in lv.reason
    assert autonomy(e.entries, "other_scope", clock.t).level == 0  # earned per scope


def test_withheld_and_unsigned_do_not_count(tmp_path, monkeypatch):
    e, clock = env(tmp_path, monkeypatch)
    for i in range(10):
        e.propose("plan", {"n": i}, lambda p: 50.0)  # below target: withheld, not a pass
    assert autonomy(e.entries, "plan", clock.t).passes == 0
    earn(e, clock, "plan", 5, 0)
    for x in [x for x in e.entries if x["kind"] == "proposal"][-5:]:
        e._append("accept", dict(proposal=x["h"]))  # agent "accepting" its own work: no signature
    lv = autonomy(e.entries, "plan", clock.t)
    assert (lv.level, lv.accepted) == (0, 0)


def test_error_drops_level_and_recency_matters(tmp_path, monkeypatch):
    e, clock = env(tmp_path, monkeypatch)
    earn(e, clock, "plan", 12, 6)
    assert autonomy(e.entries, "plan", clock.t).level == 2
    clock.t += 60
    e.record_error("unverified_claim", "know:run_id", scope="plan")
    lv = autonomy(e.entries, "plan", clock.t)
    assert lv.level == 0 and "error (unverified_claim)" in lv.reason and lv.passes == 0
    clock.t += 8 * DAY  # quiet window over, but the record restarts after the error
    assert autonomy(e.entries, "plan", clock.t).level == 0
    earn(e, clock, "plan", 5, 2)
    assert autonomy(e.entries, "plan", clock.t).level == 1
    earn(e, clock, "plan", 7, 4)
    assert autonomy(e.entries, "plan", clock.t).level == 1  # 12 passes but last error under 30 days ago
    clock.t += 31 * DAY
    assert autonomy(e.entries, "plan", clock.t).level == 2


def test_global_error_hits_every_scope(tmp_path, monkeypatch):
    e, clock = env(tmp_path, monkeypatch)
    earn(e, clock, "plan", 5, 2)
    e.record_error("assumed_identity", "know:board")  # scope "*"
    assert autonomy(e.entries, "plan", clock.t).level == 0


def test_life_safety_pinned_at_0(tmp_path, monkeypatch):
    e, clock = env(tmp_path, monkeypatch)
    for s in ("safety", "life_safety", "life_safety.escalation", "safety.alarm"):
        earn(e, clock, s, 12, 12)
        lv = autonomy(e.entries, s, clock.t + 60 * DAY)
        assert lv.level == 0 and "pinned" in lv.reason
    cap(e, "safety", 2)
    assert autonomy(e.entries, "safety", clock.t + 60 * DAY).level == 0  # not even an operator cap raises it


def test_operator_cap_and_decide(tmp_path, monkeypatch):
    e, clock = env(tmp_path, monkeypatch)
    earn(e, clock, "plan", 12, 6)
    assert decide(e.entries, "plan", clock.t, low_risk=True)[0] == "apply_and_report"
    assert decide(e.entries, "plan", clock.t, low_risk=False)[0] == "apply_after_notice"
    cap(e, "plan", 1)
    lv = autonomy(e.entries, "plan", clock.t)
    assert lv.level == 1 and "operator cap; record earns 2" in lv.reason
    cap(e, "plan", 0)
    assert decide(e.entries, "plan", clock.t, low_risk=True)[0] == "await_approval"


def test_deterministic_and_survives_reload(tmp_path, monkeypatch):
    e, clock = env(tmp_path, monkeypatch)
    earn(e, clock, "plan", 6, 3)
    a = autonomy(e.entries, "plan", clock.t).as_dict()
    b = autonomy(AIEnv(e.path, K).reload().entries, "plan", clock.t).as_dict()
    assert a == b and a["level"] == 1


def test_custom_policy(tmp_path, monkeypatch):
    e, clock = env(tmp_path, monkeypatch)
    earn(e, clock, "plan", 2, 1)
    p = Policy(l1_passes=2, l1_accepted=1, life_safety=frozenset({"brakes"}))
    assert autonomy(e.entries, "plan", clock.t, p).level == 1
    assert autonomy(e.entries, "brakes", clock.t, p).level == 0
