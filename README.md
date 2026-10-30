# Ten rules for governing AI agents

I run a team of AI coding agents on one Mac to build a safety product: radio nodes that get alerts to phones when cell and Wi-Fi are down. Running agents unsupervised for weeks taught me that **written instructions alone don't hold**. Every rule below exists because something went wrong without it, and each one is enforced by a mechanism, not a prompt.

1. **People's data stays with people.** Agents get counts and hashes, never message bodies, names or locations.
2. **Life-safety never waits on the AI.** Anything that protects a person runs on site, without the cloud or an agent in the path.
3. **Humans set the goal.** The goal is signed by a person and an agent can't change it; every proposal states its effect on the goal.
4. **Test before you claim.** No result counts without evidence from a test at the worst end of every range.
5. **Ask, don't guess.** "I need X to continue" is a valid answer, not a failure.
6. **Corrections bind.** When a human corrects an agent, the correction blocks conflicting work until it's lifted.
7. **Keep an honest record.** An append-only log of decisions, results and the agent's own mistakes with their causes, reloaded at the start of every session.
8. **Learn openly.** Mistakes become test cases; lessons go on a shared board and only take effect after a human signs off.
9. **Autonomy is earned and can be lost.** An agent's freedom in each area grows with its verified record and drops after an error.
10. **An agent's workspace is its own, never sealed.** No other process writes to it, and a human can always read it, pause it or stop it.

## What one night taught us

In a single session (Oct 29–30, 2026) agents, despite written rules:

- ran 26 parallel jobs on a laptop in use;
- left 24 orphaned processes running for hours;
- started a server on the port of a live service;
- leaked test data into a live roster;
- minted real license keys with a production signing key.

Rules 3, 7, 8 and 10 cover these only if they're enforced by the tool. So: hard per-agent CPU and process caps, teardown of everything an agent starts, fences around ports, data and devices, and no secrets unless granted. Details: [anthropics/claude-code#91081](https://github.com/anthropics/claude-code/issues/91081).

## Code

Python 3.9+, no dependencies. Each rule maps to a mechanism and a test:

| Rule | Mechanism | Module | Test |
|---|---|---|---|
| 1. Data stays with people | Boundary validator rejects names, message bodies, phone/device IDs, locations, long free text | `src/agent_governance/env.py` (`_check_no_user_content`) | `tests/test_env.py` |
| 2. Life safety never waits on the AI | Architectural: nothing here sits on a safety path; the environment only returns proposals, and rule 9 pins life-safety scopes at level 0 | (design) | `tests/test_autonomy.py::test_life_safety_pinned_at_0` |
| 3. Humans set the goal | Operator-signed goal record, verified on every reload; the agent has no write path to it | `env.py` (`set_goal`, `reload`) | `tests/test_env.py::test_reload_and_tamper` |
| 4. Test before you claim | Proposals run in a sandbox at the worst end of every range; below target they are withheld | `env.py` (`propose`) | `tests/test_env.py::test_gate` |
| 5. Ask, don't guess | Missing facts become logged requests, not guesses | `env.py` (`ask`, `propose`) | `tests/test_env.py::test_gate` |
| 6. Corrections bind | Signed corrections forbid parameter values in scope; conflicting proposals are returned as conflicts | `env.py` (`correct`, `propose`) | `tests/test_env.py::test_gate` |
| 7. Honest record | Hash-chained, append-only ledger; errors carry a cause and the check that would have caught them | `env.py` (`record_error`, `reload`) | `tests/test_env.py` |
| 8. Learn openly | Lessons go to a shared board and stay inactive until a human signs off | `env.py` (`lesson`, `signoff`, `active_lessons`) | `tests/test_env.py::test_lessons_need_signoff` |
| 9. Earned autonomy | Per-scope level 0/1/2 computed from the signed record (sandbox passes, operator accepts, error recency), with the reason in words; an error drops it to 0; operator caps | `src/agent_governance/autonomy.py` | `tests/test_autonomy.py` |
| 10. Own space, never sealed | Per-agent store: token-gated writes, 0644/0755 files, hash-chained journal; humans read, pause, resume and stop through an Ed25519-signed control log; removing human access is refused, and a tampered access list halts the agent | `src/agent_governance/space.py` | `tests/test_space.py` |

Two enforcement tools for the night described above:

- `tools/agent_cpu_guard.py` caps each Claude Code agent's process tree (default 2 cores, 8 running processes): renice to 19, SIGSTOP the newest excess, log why, SIGCONT when there is room. It never touches the agent process itself, other users' processes, apps in `/Applications`, MCP servers, or anything listening on a protected port (with its parents and children). Dry run is the default.
- `hooks/one_worker_hook.py` is a Claude Code `PreToolUse` hook that blocks obvious fan-out in Bash commands (`pytest -n auto`, `xargs -P`, GNU `parallel`, `make -j`, several `&` jobs, process pools) with a message explaining how to run the job as one worker.

Limits, stated plainly: agents that run as the same Unix account can still edit each other's files directly. The space detects that (hash and journal mismatch) rather than preventing it. For hard separation run each agent under its own account; the same permission bits then make it OS-enforced.

### Quick start

```python
from agent_governance import AIEnv, accept, autonomy, create_space, human_keypair, HumanControl, AgentSpace
import time

env = AIEnv("agent.jsonl", operator_key=b"operator secret")
env.set_goal("reach every person", "counted_pct", 100.0)            # rule 3: signed by the operator
status, detail = env.propose("plan", {"workers": 12}, sandbox=lambda p: 100.0)  # rule 4: measured before offered
accept(env, env.entries[-1])                                         # operator accepts the offer
print(autonomy(env.entries, "plan", time.time()).reason)             # rule 9: "level 0 because 1 verified ..."

seed, pk = human_keypair()                                           # rule 10
token = create_space("spaces", "agent-a", {"alex": pk})
AgentSpace("spaces", "agent-a", token).write("notes", {"runs": 1})
HumanControl("spaces", "alex", seed).pause("agent-a", "review first")
```

Run the tests one file at a time, single-threaded:

```sh
pip install pytest
for f in tests/test_*.py; do nice -n 19 python -m pytest -q "$f"; done
```

## Install the guard and the hook

Both are single files with no dependencies. Try each in dry-run mode first.

**CPU guard**

1. Look once, change nothing: `python3 tools/agent_cpu_guard.py --once`. It prints each agent tree it found and every action it WOULD take.
2. Protect your own servers: `--protect-port 5000 --protect-port 8080` (or `AGENT_GUARD_PROTECT_PORTS=5000,8080`).
3. Watch in dry run for a while: `python3 tools/agent_cpu_guard.py` (checks every 5 s; Ctrl-C to quit).
4. Enforce: `python3 tools/agent_cpu_guard.py --enforce`. Actions are logged to `~/.agent_cpu_guard/guard.log`. On exit it resumes everything it paused; if it was killed hard, run `python3 tools/agent_cpu_guard.py --release-all`.
5. Tune with `--max-cores` and `--max-procs`.

**One-worker hook**

1. Dry run: `echo '{"tool_name":"Bash","tool_input":{"command":"pytest -n auto"}}' | python3 hooks/one_worker_hook.py; echo "exit $?"` should print the block message and `exit 2`; the same with `pytest -q` exits 0.
2. Add it to `~/.claude/settings.json` (all projects) or `.claude/settings.json` (one project), with the absolute path to the file:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [ { "type": "command", "command": "python3 /absolute/path/to/agent-governance/hooks/one_worker_hook.py" } ] }
    ]
  }
}
```

3. Restart Claude Code and check `/hooks` lists it. To allow parallel work for a session, a human starts Claude Code with `ONE_WORKER_OVERRIDE=1`.

## License

MIT. See [LICENSE](LICENSE).

*Patent pending (U.S. provisionals 64/184,861 and 64/184,896). Shared to start a conversation. The code is MIT-licensed; the patents are not licensed beyond that.*
