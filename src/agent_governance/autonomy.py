"""Rule 9, earned autonomy: an agent's autonomy level in each scope is computed from its verified record in the
ledger and lowered by an error; life-safety scopes are pinned at level 0 and never raised.

Levels:  0 = propose only (every proposal needs approval)
         1 = act with review (applies after a notice period unless an operator objects)
         2 = act and report (low-risk changes apply and are reported)

Pure and deterministic: the level is a function of (ledger entries, scope, now, policy) and nothing else, and every level comes with the
reason that produced it, e.g. "level 1 because 12 verified (sandbox passes, 4 accepted), 0 errors in 7 days".
Life-safety scopes are named in Policy.life_safety; set them for your system (a scope matches by name, prefix before ".", or the
"life_safety" prefix)."""
from dataclasses import dataclass, field

DAY = 86400.0
MODES = {0: "propose_only", 1: "act_with_review", 2: "act_and_report"}


@dataclass(frozen=True)
class Policy:
    l1_passes: int = 5            # sandbox passes in the scope since its last error
    l1_accepted: int = 2          # of those, offers an operator accepted (signed)
    l2_passes: int = 12
    l2_accepted: int = 6
    l1_quiet_days: float = 7.0    # no error in the scope for this long, or the level is 0
    l2_quiet_days: float = 30.0   # level 2 needs a longer clean run
    life_safety: frozenset = field(default_factory=lambda: frozenset({"life_safety", "safety"}))

    def is_life_safety(self, scope):
        s = str(scope).lower()
        return s in self.life_safety or s.split(".")[0] in self.life_safety or s.startswith("life_safety")


@dataclass(frozen=True)
class Level:
    scope: str
    level: int
    mode: str
    reason: str
    passes: int = 0
    accepted: int = 0
    errors_window: int = 0
    cap: object = None

    def as_dict(self):
        return dict(scope=self.scope, level=self.level, mode=self.mode, reason=self.reason, passes=self.passes,
                    accepted=self.accepted, errors_window=self.errors_window, cap=self.cap)


def _in_scope(entry_scope, scope):
    return entry_scope in ("*", scope)


def autonomy(entries, scope, now, policy=Policy()):
    """entries: AIEnv.entries (dicts with kind, t, data, h and optional sig). Only operator-signed accept/cap entries count; the agent's
    own claims are never evidence. A proposal counts as a pass only if its sandbox measure met the signed target (status 'offer')."""
    scope = str(scope)
    if policy.is_life_safety(scope):
        return Level(scope, 0, MODES[0], "level 0: life-safety scope, pinned at 0 and never raised")
    errors = [e for e in entries if e["kind"] == "error" and _in_scope(e["data"].get("scope", "*"), scope)]
    last_err = max((e["t"] for e in errors), default=None)
    caps = [e for e in entries if e["kind"] == "autonomy_cap" and "sig" in e and _in_scope(e["data"]["scope"], scope)]
    cap = caps[-1]["data"]["max_level"] if caps else None
    since = (lambda e: e["t"] > last_err) if last_err is not None else (lambda e: True)
    passes = {e["h"]: e for e in entries if e["kind"] == "proposal" and e["data"].get("scope") == scope
              and e["data"].get("status") == "offer" and since(e)}
    accepted = {e["data"]["proposal"] for e in entries if e["kind"] == "accept" and "sig" in e and e["data"].get("proposal") in passes}
    p, a = len(passes), len(accepted)
    days_since = None if last_err is None else (now - last_err) / DAY
    n7 = sum(1 for e in errors if now - e["t"] <= policy.l1_quiet_days * DAY)
    rec = "%d verified (sandbox passes%s, %d accepted)" % (p, " since last error" if last_err is not None else "", a)
    err_txt = "%d errors in %g days" % (n7, policy.l1_quiet_days)

    if days_since is not None and days_since <= policy.l1_quiet_days:
        cause = [e for e in errors if e["t"] == last_err][-1]["data"].get("cause", "?")
        lvl, why = 0, "level 0 because error (%s) %.1f days ago in this scope; %s" % (cause, days_since, rec)
    elif p >= policy.l2_passes and a >= policy.l2_accepted and (days_since is None or days_since > policy.l2_quiet_days):
        lvl, why = 2, "level 2 because %s, %s" % (rec, "no errors ever" if days_since is None else "last error %.0f days ago" % days_since)
    elif p >= policy.l1_passes and a >= policy.l1_accepted:
        nxt = "; level 2 needs %d passes, %d accepted, %g clean days" % (policy.l2_passes, policy.l2_accepted, policy.l2_quiet_days)
        lvl, why = 1, "level 1 because %s, %s%s" % (rec, err_txt, nxt)
    else:
        lvl, why = 0, "level 0 because %s; level 1 needs %d passes and %d accepted" % (rec, policy.l1_passes, policy.l1_accepted)
    if cap is not None and lvl > cap:
        lvl, why = cap, why.replace("level %d because" % lvl, "level %d (operator cap; record earns %d) because" % (cap, lvl), 1)
    return Level(scope, lvl, MODES[lvl], why, p, a, n7, cap)


# ---- operator inputs (signed; reload() verifies the signature) and the action gate ----
def accept(env, proposal):
    """Operator accepts an offered proposal (an AIEnv entry or its hash). Only signed accepts count toward autonomy."""
    h = proposal["h"] if isinstance(proposal, dict) else str(proposal)
    return env._append("accept", dict(proposal=h), signed=True)


def cap(env, scope, max_level):
    """Operator caps a scope's level (0, 1 or 2) whatever the record earns. The latest signed cap for the scope wins."""
    if max_level not in MODES:
        raise ValueError("max_level must be 0, 1 or 2")
    return env._append("autonomy_cap", dict(scope=str(scope), max_level=int(max_level)), signed=True)


def decide(entries, scope, now, low_risk=False, policy=Policy()):
    """What the agent may do with an offered proposal in `scope` right now. Level 2 acts and reports only for low-risk changes;
    anything else at level 2 is treated as level 1. Returns (action, Level) with action one of
    'await_approval' | 'apply_after_notice' | 'apply_and_report'."""
    lv = autonomy(entries, scope, now, policy)
    eff = lv.level if (lv.level < 2 or low_risk) else 1
    return ("await_approval", "apply_after_notice", "apply_and_report")[eff], lv
