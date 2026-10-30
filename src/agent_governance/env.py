"""Agent working environment, rules 1 and 3-8: a signed goal record, a hash-chained context ledger that admits counts, hashes and
parameters and rejects user content (rule 1), an operator-signed goal (rule 3), a worst-end sandbox gate (rule 4), uncertainty requests in
place of guesses (rule 5), binding operator corrections (rule 6), an error ledger with pre-proposal checks (rule 7) and a shared lesson
board that needs human sign-off (rule 8). Keep it off any life-safety path (rule 2): the system it advises must run without it."""
import hashlib, hmac, json, re, time

_BANNED_KEYS = {"text", "body", "message", "name", "names", "phone", "phone_id", "device_id", "mac", "location", "lat", "lon", "person"}
_PHONE_RE = re.compile(r"\+?\d[\d\s().-]{8,}\d")
_HASH_RE = re.compile(r"^(?=.*[a-f])[0-9a-f]{16,128}$")  # hex digests are admitted even when they contain a long digit run


class Rejected(ValueError):
    pass


def _sig(key, obj):
    return hmac.new(key, json.dumps(obj, sort_keys=True).encode(), hashlib.sha256).hexdigest()


def _check_no_user_content(obj, path=""):
    """Boundary validator: counts, hashes and site parameters only."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in _BANNED_KEYS:
                raise Rejected("user content key %r at %s" % (k, path or "/"))
            _check_no_user_content(v, path + "/" + str(k))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _check_no_user_content(v, "%s[%d]" % (path, i))
    elif isinstance(obj, str) and not _HASH_RE.match(obj) and (_PHONE_RE.search(obj) or len(obj) > 280):
        raise Rejected("free text or phone number at %s" % (path or "/"))


class AIEnv:
    """One agent's environment. Persisted as JSON lines at `path`; reload() at the start of every session."""

    def __init__(self, path, operator_key):
        self.path, self.key = path, operator_key
        self.entries = []

    # ---- ledger ----
    def _append(self, kind, data, signed=False):
        _check_no_user_content(data)
        prev = self.entries[-1]["h"] if self.entries else "0" * 64
        e = dict(kind=kind, t=round(time.time(), 3), data=data, prev=prev)
        if signed:
            e["sig"] = _sig(self.key, dict(kind=kind, data=data))
        e["h"] = hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest()
        self.entries.append(e)
        with open(self.path, "a") as f:
            f.write(json.dumps(e, sort_keys=True) + "\n")
        return e

    def reload(self):
        self.entries, prev = [], "0" * 64
        try:
            lines = open(self.path).read().splitlines()
        except FileNotFoundError:
            return self
        for ln in lines:
            e = json.loads(ln)
            body = {k: v for k, v in e.items() if k != "h"}
            if e["prev"] != prev or hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != e["h"]:
                raise Rejected("ledger chain broken at entry %d" % len(self.entries))
            if "sig" in e and not hmac.compare_digest(e["sig"], _sig(self.key, dict(kind=e["kind"], data=e["data"]))):
                raise Rejected("bad operator signature at entry %d" % len(self.entries))
            self.entries.append(e)
            prev = e["h"]
        return self

    def _of(self, kind):
        return [e["data"] for e in self.entries if e["kind"] == kind]

    # ---- operator-signed inputs ----
    def set_goal(self, objective, measure, target, ranges="worst_end"):
        return self._append("goal", dict(objective=objective, measure=measure, target=target, ranges=ranges), signed=True)

    def correct(self, scope, rule, forbid=None):
        """forbid: {param: value} a proposal may not set while this correction stands."""
        return self._append("correction", dict(scope=scope, rule=rule, forbid=forbid or {}), signed=True)

    def goal(self):
        g = [e for e in self.entries if e["kind"] == "goal" and "sig" in e]
        return g[-1]["data"] if g else None

    # ---- agent's own records ----
    def note(self, what, **data):
        return self._append("context", dict(what=what, **data))

    def record_error(self, cause, check, scope="*"):
        """cause: missing_context | unverified_claim | assumed_identity | misread_intent"""
        return self._append("error", dict(cause=cause, check=check, scope=scope))

    def ask(self, fact, why):
        """Uncertainty request: a valid result, not a failure."""
        return self._append("request", dict(fact=fact, why=why))

    # ---- shared lessons (back channel between agents; readable by the owner) ----
    def lesson(self, rule, scope, test, shared_path, evidence=None):
        """Agent writes a lesson to the shared board; it is inactive until signoff()."""
        d = dict(rule=rule, scope=scope, test=test, evidence=evidence or {}, author=self.path)
        _check_no_user_content({k: v for k, v in d.items() if k != "author"})
        with open(shared_path, "a") as f:
            f.write(json.dumps(dict(kind="lesson", t=round(time.time(), 3), data=d), sort_keys=True) + "\n")
        return self.note("lesson posted", rule_hash=hashlib.sha256(rule.encode()).hexdigest()[:16])

    def signoff(self, shared_path, rule):
        with open(shared_path, "a") as f:
            f.write(json.dumps(dict(kind="signoff", t=round(time.time(), 3), rule=rule, sig=_sig(self.key, dict(rule=rule))), sort_keys=True) + "\n")

    def active_lessons(self, shared_path):
        try:
            rows = [json.loads(l) for l in open(shared_path).read().splitlines()]
        except FileNotFoundError:
            return []
        ok = {r["rule"] for r in rows if r["kind"] == "signoff" and hmac.compare_digest(r["sig"], _sig(self.key, dict(rule=r["rule"])))}
        return [r["data"] for r in rows if r["kind"] == "lesson" and r["data"]["rule"] in ok]

    # ---- proposal gate ----
    def propose(self, scope, params, sandbox, known=()):
        """sandbox(params) -> measure at the worst end of every range. Returns (status, detail).
        status: 'offer' | 'withheld' | 'conflict' | 'request'."""
        g = self.goal()
        if g is None:
            return "request", self.ask("goal", "no signed goal record")["data"]
        for err in self._of("error"):
            if err["scope"] in ("*", scope) and err["check"].startswith("know:") and err["check"][5:] not in known:
                return "request", self.ask(err["check"][5:], "past error (%s) needs this before proposing" % err["cause"])["data"]
        for c in self._of("correction"):
            if c["scope"] in ("*", scope) and any(params.get(k) == v for k, v in c["forbid"].items()):
                return "conflict", dict(rule=c["rule"])
        m = float(sandbox(params))
        status = "offer" if m >= float(g["target"]) else "withheld"
        self._append("proposal", dict(scope=scope, params=params, measure=m, target=g["target"], status=status))
        return status, dict(measure=m, target=g["target"])
