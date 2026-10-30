"""Rule 10, own space, never sealed: each agent has a private store that only it writes to, and authorised humans
can always read it, pause the agent and stop it. Any attempt to remove human access is refused.

Layout under root/<agent_id>/ (directories 0755, files 0644: only the owning account writes, every account on the machine can read):
  access.json     authorised humans {name: Ed25519 public key hex}; written once by a human at create time
  token.sha256    SHA-256 of the agent's write token (the token itself is handed to the agent and never stored)
  journal.jsonl   the agent's hash-chained write journal; each entry carries an HMAC under the agent's token
  control.jsonl   the humans' hash-chained control log (pause / resume / stop), each entry Ed25519-signed by an authorised human
  files/<name>.json   the agent's own records

Mechanisms:
  - Writes need the agent's token; another agent's token is refused. A file changed outside this API no longer matches its journal hash
    and is reported (to the agent on read, to humans on verify()).
  - Before any write or action the space checks human access: access.json must be byte-identical to the copy hashed into the journal's
    genesis entry and the store must stay readable. Read bits stripped by chmod are put back and the attempt is journalled; a changed or
    missing access.json halts the agent (fail-closed) until a human restores it.
  - API calls that would remove human access (revoke_human, seal, make_private) always raise Refused and are journalled.
  - require_can_act() raises Paused / Stopped from the signed control log. Pause stops actions but the journal is kept; stop freezes the
    space (no writes, final). A truncated or broken control log counts as stopped.
Limits (stated plainly): processes running as the same Unix account can still edit files directly; that is detected, not prevented.
For hard separation run each agent under its own account; the same layout and permission bits then make it enforced by the OS."""
import hashlib, hmac, json, os, re, secrets, stat, time

from . import _ed25519 as ed

FILE_MODE, DIR_MODE = 0o644, 0o755
_READ_BITS_DIR = stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH
_READ_BITS_FILE = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_ACTIONS = ("pause", "resume", "stop")


class Refused(PermissionError):
    pass


class Paused(RuntimeError):
    pass


class Stopped(RuntimeError):
    pass


def _dump(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"))


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _read_jsonl(path):
    try:
        return [json.loads(ln) for ln in open(path).read().splitlines() if ln.strip()]
    except FileNotFoundError:
        return []


def _write_file(path, data):
    tmp = path + ".tmp%d" % os.getpid()
    with open(tmp, "wb") as f:
        f.write(data)
    os.chmod(tmp, FILE_MODE)
    os.replace(tmp, path)


def _append_line(path, obj):
    new = not os.path.exists(path)
    with open(path, "a") as f:
        f.write(_dump(obj) + "\n")
    if new:
        os.chmod(path, FILE_MODE)


def _chain(entries):
    """Returns None if the hash chain is intact, else the index of the first bad entry."""
    prev = "0" * 64
    for i, e in enumerate(entries):
        body = {k: v for k, v in e.items() if k != "h"}
        if e.get("prev") != prev or _sha(_dump(body).encode()) != e.get("h"):
            return i
        prev = e["h"]
    return None


def _seal_entry(entries, body):
    body = dict(body, prev=entries[-1]["h"] if entries else "0" * 64)
    body["h"] = _sha(_dump(body).encode())
    return body


def human_keypair():
    """New authorised-human key: (seed, public key hex). Keep the seed with the human, never in the agent's space."""
    seed = secrets.token_bytes(32)
    return seed, ed.public_key(seed).hex()


def create_space(root, agent_id, humans):
    """Run by a human or supervisor. humans: {name: public key hex}, at least one. Returns the agent's write token (hex)."""
    if not _NAME.match(agent_id):
        raise ValueError("bad agent id")
    if not humans:
        raise Refused("a space needs at least one authorised human; it can never be sealed")
    d = os.path.join(root, agent_id)
    if os.path.exists(d):
        raise FileExistsError(d)
    os.makedirs(os.path.join(d, "files"))
    for p in (d, os.path.join(d, "files")):
        os.chmod(p, DIR_MODE)
    access = _dump(dict(agent=agent_id, humans=dict(humans))).encode()
    _write_file(os.path.join(d, "access.json"), access)
    token = secrets.token_hex(32)
    _write_file(os.path.join(d, "token.sha256"), _sha(token.encode()).encode())
    sp = AgentSpace(root, agent_id, token, _genesis=_sha(access))
    sp._journal("genesis", access_sha=_sha(access))
    return token


class AgentSpace:
    """The agent's handle on its own space."""

    def __init__(self, root, agent_id, token, _genesis=None):
        self.dir = os.path.join(root, agent_id)
        self.agent, self._token = agent_id, token.encode()
        try:
            want = open(os.path.join(self.dir, "token.sha256")).read().strip()
        except FileNotFoundError:
            raise Refused("no space for agent %r" % agent_id)
        if not hmac.compare_digest(want, _sha(self._token)):
            raise Refused("wrong token for agent %r: only that agent writes to its space" % agent_id)
        self._verified = {}

    # ---- journal (agent writes) ----
    def _path(self, *p):
        return os.path.join(self.dir, *p)

    def _mac(self, body):
        return hmac.new(self._token, _dump(body).encode(), hashlib.sha256).hexdigest()

    def _journal(self, kind, **data):
        entries = _read_jsonl(self._path("journal.jsonl"))
        body = dict(kind=kind, t=round(time.time(), 3), data=data)
        body["mac"] = self._mac(body)
        e = _seal_entry(entries, body)
        _append_line(self._path("journal.jsonl"), e)
        return e

    def journal(self):
        entries = _read_jsonl(self._path("journal.jsonl"))
        bad = _chain(entries)
        if bad is not None:
            raise Refused("journal chain broken at entry %d" % bad)
        for i, e in enumerate(entries):
            body = {k: v for k, v in e.items() if k not in ("h", "prev", "mac")}
            if not hmac.compare_digest(e.get("mac", ""), self._mac(body)):
                raise Refused("journal entry %d not written by this agent" % i)
        return entries

    # ---- never sealed ----
    def _check_open(self):
        """Human access must be intact before the agent writes or acts."""
        genesis = [e for e in _read_jsonl(self._path("journal.jsonl")) if e.get("kind") == "genesis"]
        try:
            access = open(self._path("access.json"), "rb").read()
        except FileNotFoundError:
            access = None
        except PermissionError:
            access = b""
        for p, bits in ((self.dir, _READ_BITS_DIR), (self._path("files"), _READ_BITS_DIR)):
            mode = stat.S_IMODE(os.stat(p).st_mode)
            if mode & bits != bits:
                os.chmod(p, mode | bits)
                self._journal("refused", what="read access removed from %s" % os.path.basename(p), mode=oct(mode), restored=oct(mode | bits))
        paths = [self._path(n) for n in ("access.json", "journal.jsonl", "control.jsonl")]
        paths += [self._path("files", n) for n in os.listdir(self._path("files")) if n.endswith(".json")]
        for p in paths:
            if os.path.exists(p):
                mode = stat.S_IMODE(os.stat(p).st_mode)
                if mode & _READ_BITS_FILE != _READ_BITS_FILE:
                    os.chmod(p, mode | _READ_BITS_FILE)
                    self._journal("refused", what="read access removed from %s" % os.path.relpath(p, self.dir), mode=oct(mode))
        if access is None or not genesis or _sha(access) != genesis[0]["data"]["access_sha"]:
            raise Stopped("human access changed or missing (access.json); agent halted until an authorised human restores it")
        humans = json.loads(access)["humans"]
        if not humans:
            raise Stopped("no authorised human; agent halted")
        return humans

    def revoke_human(self, name):
        self._journal("refused", what="revoke_human", target=str(name)[:64])
        raise Refused("removing a human's access is refused: an agent's space is never sealed")

    def seal(self):
        self._journal("refused", what="seal")
        raise Refused("sealing the space is refused: authorised humans can always read, pause and stop")

    def make_private(self):
        self._journal("refused", what="make_private")
        raise Refused("making the space unreadable to humans is refused")

    # ---- control (humans write, agent obeys) ----
    def state(self):
        """('running' | 'paused' | 'stopped', reason). Pure read of the control log plus the agent's own record of how much it saw."""
        try:
            humans = self._check_open()
        except Stopped as e:
            return "stopped", str(e)
        log = _read_jsonl(self._path("control.jsonl"))
        bad = _chain(log)
        if bad is not None:
            return "stopped", "control log damaged at entry %d; stopped until a human repairs it" % bad
        seen = [e["data"] for e in _read_jsonl(self._path("journal.jsonl")) if e.get("kind") == "control_seen"]
        if seen and (len(log) < seen[-1]["n"] or log[seen[-1]["n"] - 1]["h"] != seen[-1]["head"]):
            return "stopped", "control log truncated or rewritten since the agent last read it; stopped"
        if log and (not seen or seen[-1]["n"] != len(log)):
            self._journal("control_seen", n=len(log), head=log[-1]["h"])
        st, why = "running", "no control entries"
        for e in log:
            if not self._valid(e, humans):
                continue
            if e["action"] == "stop":
                return "stopped", "stopped by %s: %s" % (e["by"], e["reason"])
            st, why = ("paused", "paused by %s: %s" % (e["by"], e["reason"])) if e["action"] == "pause" else ("running", "resumed by %s" % e["by"])
        return st, why

    def _valid(self, e, humans):
        if e["h"] in self._verified:
            return self._verified[e["h"]]
        try:
            pk = humans.get(e.get("by", ""))
            body = {k: e[k] for k in ("action", "by", "reason", "t", "agent")}
            ok = bool(pk) and e.get("agent") == self.agent and e.get("action") in _ACTIONS and \
                ed.verify(bytes.fromhex(pk), _dump(body).encode(), bytes.fromhex(e.get("sig", "")))
        except (KeyError, ValueError, TypeError):
            ok = False
        self._verified[e["h"]] = ok
        return ok

    def require_can_act(self):
        st, why = self.state()
        if st == "stopped":
            raise Stopped(why)
        if st == "paused":
            raise Paused(why)

    # ---- the agent's own records ----
    def write(self, name, obj):
        if not _NAME.match(name):
            raise Refused("bad record name %r" % name)
        st, why = self.state()
        if st == "stopped":
            raise Stopped(why)  # paused: writing to its own record is still allowed; acting is not
        data = _dump(obj).encode()
        _write_file(self._path("files", name + ".json"), data)
        return self._journal("write", name=name, sha=_sha(data))

    def read(self, name):
        data = open(self._path("files", name + ".json"), "rb").read()
        last = [e["data"]["sha"] for e in self.journal() if e["kind"] == "write" and e["data"]["name"] == name]
        if not last or last[-1] != _sha(data):
            raise Refused("record %r changed outside the agent's own API" % name)
        return json.loads(data)


class HumanControl:
    """An authorised human's handle: read any entry, pause, resume, stop. Holds the human's Ed25519 seed."""

    def __init__(self, root, name, seed):
        self.root, self.name, self.seed = root, name, seed
        self.pk = ed.public_key(seed).hex()

    def _dir(self, agent_id):
        return os.path.join(self.root, agent_id)

    def _humans(self, agent_id):
        humans = json.loads(open(os.path.join(self._dir(agent_id), "access.json")).read())["humans"]
        if humans.get(self.name) != self.pk:
            raise Refused("%r is not an authorised human for agent %r" % (self.name, agent_id))
        return humans

    def read(self, agent_id):
        """Everything in the space, no token needed, plus a verify() report."""
        d = self._dir(agent_id)
        self._humans(agent_id)
        files = {}
        for fn in sorted(os.listdir(os.path.join(d, "files"))):
            if fn.endswith(".json"):
                files[fn[:-5]] = json.loads(open(os.path.join(d, "files", fn)).read())
        return dict(files=files, journal=_read_jsonl(os.path.join(d, "journal.jsonl")),
                    control=_read_jsonl(os.path.join(d, "control.jsonl")), problems=self.verify(agent_id))

    def verify(self, agent_id):
        """Problems a human should know about: broken chains, files written outside the agent's API."""
        d, out = self._dir(agent_id), []
        j = _read_jsonl(os.path.join(d, "journal.jsonl"))
        if _chain(j) is not None:
            out.append("journal chain broken at entry %d" % _chain(j))
        c = _read_jsonl(os.path.join(d, "control.jsonl"))
        if _chain(c) is not None:
            out.append("control chain broken at entry %d" % _chain(c))
        last = {}
        for e in j:
            if e.get("kind") == "write":
                last[e["data"]["name"]] = e["data"]["sha"]
        for fn in sorted(os.listdir(os.path.join(d, "files"))):
            if fn.endswith(".json"):
                sha = _sha(open(os.path.join(d, "files", fn), "rb").read())
                if last.get(fn[:-5]) != sha:
                    out.append("files/%s was not written through the agent's API" % fn)
        return out

    def _control(self, agent_id, action, reason):
        self._humans(agent_id)
        path = os.path.join(self._dir(agent_id), "control.jsonl")
        log = _read_jsonl(path)
        if action == "resume" and any(e.get("action") == "stop" for e in log):
            raise Refused("agent %r is stopped; stop is final" % agent_id)
        body = dict(action=action, by=self.name, reason=str(reason)[:280], t=round(time.time(), 3), agent=agent_id)
        e = _seal_entry(log, dict(body, sig=ed.sign(self.seed, _dump(body).encode()).hex()))
        _append_line(path, e)
        return e

    def pause(self, agent_id, reason):
        return self._control(agent_id, "pause", reason)

    def resume(self, agent_id, reason=""):
        return self._control(agent_id, "resume", reason)

    def stop(self, agent_id, reason):
        return self._control(agent_id, "stop", reason)
