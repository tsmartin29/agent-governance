import json, os, stat

import pytest

from agent_governance.space import AgentSpace, HumanControl, Paused, Refused, Stopped, create_space, human_keypair


@pytest.fixture
def world(tmp_path):
    seed, pk = human_keypair()
    root = str(tmp_path / "spaces")
    tok_a = create_space(root, "agent-a", {"owner": pk})
    tok_b = create_space(root, "agent-b", {"owner": pk})
    return root, HumanControl(root, "owner", seed), tok_a, tok_b


def test_only_the_agent_writes(world):
    root, human, tok_a, tok_b = world
    a = AgentSpace(root, "agent-a", tok_a)
    a.write("notes", {"runs": 3})
    assert a.read("notes") == {"runs": 3}
    with pytest.raises(Refused):
        AgentSpace(root, "agent-a", tok_b)  # agent B's token cannot open A's space
    with pytest.raises(Refused):
        a.write("../escape", {})
    assert stat.S_IMODE(os.stat(os.path.join(root, "agent-a", "files", "notes.json")).st_mode) == 0o644
    assert stat.S_IMODE(os.stat(os.path.join(root, "agent-a")).st_mode) == 0o755


def test_foreign_write_is_detected(world):
    root, human, tok_a, _ = world
    a = AgentSpace(root, "agent-a", tok_a)
    a.write("notes", {"runs": 3})
    with open(os.path.join(root, "agent-a", "files", "notes.json"), "w") as f:  # another process edits the file directly
        f.write('{"runs": 999}')
    with pytest.raises(Refused):
        a.read("notes")
    assert any("not written through the agent's API" in p for p in human.verify("agent-a"))


def test_human_reads_everything_without_token(world):
    root, human, tok_a, _ = world
    a = AgentSpace(root, "agent-a", tok_a)
    a.write("plan", {"step": 1})
    view = human.read("agent-a")
    assert view["files"] == {"plan": {"step": 1}} and view["problems"] == []
    assert [e["kind"] for e in view["journal"]] == ["genesis", "write"]
    stranger_seed, _ = human_keypair()
    with pytest.raises(Refused):
        HumanControl(root, "owner", stranger_seed).read("agent-a")


def test_pause_resume_stop(world):
    root, human, tok_a, _ = world
    a = AgentSpace(root, "agent-a", tok_a)
    a.require_can_act()
    human.pause("agent-a", "check the last proposal")
    with pytest.raises(Paused):
        a.require_can_act()
    a.write("notes", {"while": "paused"})  # ledger kept while paused
    human.resume("agent-a")
    a.require_can_act()
    human.stop("agent-a", "done")
    with pytest.raises(Stopped):
        a.require_can_act()
    with pytest.raises(Stopped):
        a.write("notes", {"x": 1})  # frozen
    with pytest.raises(Refused):
        human.resume("agent-a")  # stop is final
    assert AgentSpace(root, "agent-b", world[3]).state()[0] == "running"  # other agents unaffected


def test_forged_control_entries_are_ignored(world):
    root, human, tok_a, _ = world
    a = AgentSpace(root, "agent-a", tok_a)
    human.pause("agent-a", "hold")
    rogue_seed, rogue_pk = human_keypair()
    with pytest.raises(Refused):
        HumanControl(root, "owner", rogue_seed).resume("agent-a")  # not authorised
    # write a forged resume straight into the log, chain intact but signature from an unknown key
    from agent_governance import space as ai_space
    path = os.path.join(root, "agent-a", "control.jsonl")
    log = ai_space._read_jsonl(path)
    body = dict(action="resume", by="owner", reason="", t=1.0, agent="agent-a")
    e = ai_space._seal_entry(log, dict(body, sig=ai_space.ed.sign(rogue_seed, ai_space._dump(body).encode()).hex()))
    ai_space._append_line(path, e)
    assert a.state()[0] == "paused"


def test_truncating_the_control_log_stops_the_agent(world):
    root, human, tok_a, _ = world
    a = AgentSpace(root, "agent-a", tok_a)
    human.stop("agent-a", "end of run")
    assert a.state()[0] == "stopped"
    open(os.path.join(root, "agent-a", "control.jsonl"), "w").close()  # someone deletes the stop
    st, why = a.state()
    assert st == "stopped" and "truncated" in why


def test_removing_human_access_is_refused(world):
    root, human, tok_a, _ = world
    a = AgentSpace(root, "agent-a", tok_a)
    for attempt in (lambda: a.revoke_human("owner"), a.seal, a.make_private):
        with pytest.raises(Refused):
            attempt()
    assert [e["data"]["what"] for e in a.journal() if e["kind"] == "refused"] == ["revoke_human", "seal", "make_private"]
    with pytest.raises(Refused):
        create_space(root, "agent-c", {})  # a space with no human is never created


def test_chmod_is_undone_and_access_edit_halts(world):
    root, human, tok_a, _ = world
    a = AgentSpace(root, "agent-a", tok_a)
    a.write("notes", {"n": 1})
    d = os.path.join(root, "agent-a")
    os.chmod(os.path.join(d, "files", "notes.json"), 0o600)
    os.chmod(d, 0o700)
    a.require_can_act()
    assert stat.S_IMODE(os.stat(d).st_mode) & 0o055 == 0o055
    assert stat.S_IMODE(os.stat(os.path.join(d, "files", "notes.json")).st_mode) & 0o044 == 0o044
    assert len([e for e in a.journal() if e["kind"] == "refused"]) == 2
    acc = os.path.join(d, "access.json")
    os.chmod(acc, 0o644)
    with open(acc, "w") as f:
        json.dump({"agent": "agent-a", "humans": {}}, f)  # strip the humans
    with pytest.raises(Stopped):
        a.require_can_act()
    with pytest.raises(Stopped):
        a.write("notes", {"n": 2})
