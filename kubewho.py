#!/usr/bin/env python3
"""kubewho - effective kubeconfig resolver.

Which cluster+user+namespace will this shell's next kubectl command
target, and which file decided each value?

Merge model verified empirically against kubectl 1.34.0 (2026-10-23);
every rule below is tagged [observed-kubectl-1.34.0] unless noted.

Stdlib only. Read-only: never contacts a cluster, never executes
credential plugins, never prints secret values.
"""
from __future__ import annotations

import argparse
import base64
import datetime as _dt
import json
import os
import re
import stat
import sys

VERSION = "1.0.0"
OBSERVED_TAG = "[observed-kubectl-1.34.0]"

# ---------------------------------------------------------------------------
# Minimal YAML-subset parser (machine-emitted kubeconfig shape)
# ---------------------------------------------------------------------------

_SCALAR_BOOL = {"true": True, "false": False}
_SCALAR_NULL = {"null": None, "~": None}


def _strip_comment(line: str) -> str:
    """Remove a # comment that starts outside of quotes."""
    out = []
    q = None
    i = 0
    while i < len(line):
        ch = line[i]
        if q:
            out.append(ch)
            if ch == "\\" and i + 1 < len(line):
                out.append(line[i + 1])
                i += 1
            elif ch == q:
                q = None
        elif ch in ("'", '"'):
            q = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _parse_scalar(text: str):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        inner = text[1:-1]
        if text[0] == '"':
            inner = inner.replace('\\"', '"').replace("\\\\", "\\").replace("\\n", "\n")
        return inner
    low = text.lower()
    if low in _SCALAR_BOOL:
        return _SCALAR_BOOL[low]
    if low in _SCALAR_NULL:
        return _SCALAR_NULL[low]
    return text


class _Line:
    __slots__ = ("indent", "text", "lineno")

    def __init__(self, indent, text, lineno):
        self.indent = indent
        self.text = text
        self.lineno = lineno


def _lex(text: str):
    """Split into significant lines with indent; drop blanks/comments/markers."""
    lines = []
    for n, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped in ("---", "..."):
            continue
        if stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if "\t" in raw[:indent]:
            return None  # tabs for indentation: not our subset
        content = _strip_comment(raw).strip()
        if not content:
            continue
        lines.append(_Line(indent, content, n))
    return lines


class _Parser:
    def __init__(self, lines):
        self.lines = lines
        self.i = 0
        self.unparsed = []  # linenos we could not classify

    def peek(self):
        return self.lines[self.i] if self.i < len(self.lines) else None

    def parse_block(self, indent):
        """Parse a map or list block at the given indent. Returns (node, ok)."""
        first = self.peek()
        if first is None or first.indent != indent:
            return None, True
        if first.text.startswith("- ") or first.text == "-":
            return self.parse_list(indent)
        if re.match(r"^[^:]+:", first.text) or first.text.endswith(":"):
            return self.parse_map(indent)
        self.unparsed.append(first.lineno)
        self.i += 1
        return None, False

    def parse_map(self, indent):
        node = {}
        ok = True
        while True:
            ln = self.peek()
            if ln is None or ln.indent != indent:
                break
            m = re.match(r"^([^:]+):(.*)$", ln.text)
            if not m or ln.text.startswith("- "):
                self.unparsed.append(ln.lineno)
                self.i += 1
                ok = False
                continue
            key = m.group(1).strip().strip("'\"")
            rest = m.group(2).strip()
            self.i += 1
            if rest in ("|", ">", "|-", ">-", "|+", ">+"):
                node[key] = self.parse_block_scalar(indent, rest[0])
            elif rest == "":
                nxt = self.peek()
                if nxt is not None and nxt.indent > indent:
                    child, cok = self.parse_block(nxt.indent)
                    node[key] = child
                    ok = ok and cok
                elif (nxt is not None and nxt.indent == indent
                      and (nxt.text.startswith("- ") or nxt.text == "-")):
                    # YAML block sequence at the same indent as its key:
                    #   clusters:
                    #   - name: x
                    child, cok = self.parse_list(indent)
                    node[key] = child
                    ok = ok and cok
                else:
                    node[key] = None
            else:
                if "|" in rest or rest.startswith(("&", "*")):
                    # anchors/aliases and exotic scalars: not our subset
                    if rest.startswith(("&", "*")):
                        self.unparsed.append(ln.lineno)
                        ok = False
                        node[key] = None
                        continue
                node[key] = _parse_scalar(rest)
        return node, ok

    def parse_block_scalar(self, indent, style):
        chunks = []
        while True:
            ln = self.peek()
            if ln is None or ln.indent <= indent:
                break
            chunks.append(ln.text)
            self.i += 1
        if style == "|":
            return "\n".join(chunks) + ("\n" if chunks else "")
        return " ".join(chunks)

    def parse_list(self, indent):
        items = []
        ok = True
        while True:
            ln = self.peek()
            if ln is None or ln.indent != indent:
                break
            if not (ln.text.startswith("- ") or ln.text == "-"):
                break
            rest = ln.text[1:].strip()
            self.i += 1
            if rest == "":
                nxt = self.peek()
                if nxt is not None and nxt.indent > indent:
                    child, cok = self.parse_block(nxt.indent)
                    items.append(child)
                    ok = ok and cok
                else:
                    items.append(None)
            elif re.match(r"^[^:]+:", rest):
                # "- key: value" starts an inline map
                m = re.match(r"^([^:]+):(.*)$", rest)
                key = m.group(1).strip().strip("'\"")
                val = m.group(2).strip()
                sub = {}
                if val == "":
                    nxt = self.peek()
                    if nxt is not None and nxt.indent > indent:
                        child, cok = self.parse_block(nxt.indent)
                        sub[key] = child
                        ok = ok and cok
                    else:
                        sub[key] = None
                else:
                    sub[key] = _parse_scalar(val)
                # continuation lines of the map at deeper indent
                nxt = self.peek()
                if nxt is not None and nxt.indent > indent:
                    cont, cok = self.parse_map(nxt.indent)
                    sub.update(cont)
                    ok = ok and cok
                items.append(sub)
            else:
                items.append(_parse_scalar(rest))
        return items, ok


def parse_kubeconfig_yaml(text: str):
    """Parse the kubeconfig YAML subset.

    Returns (doc, unparsed_linenos). doc is a dict (possibly partial).
    """
    lines = _lex(text)
    if lines is None:
        return {}, ["tabs-for-indentation"]
    p = _Parser(lines)
    doc, _ = p.parse_block(lines[0].indent) if lines else (None, True)
    # trailing lines at a different indent than the root block
    while p.i < len(lines):
        p.unparsed.append(lines[p.i].lineno)
        p.i += 1
    return (doc if isinstance(doc, dict) else {}), sorted(set(p.unparsed))

# ---------------------------------------------------------------------------
# File list resolution  [observed-kubectl-1.34.0]
# ---------------------------------------------------------------------------


def resolve_file_list(kubeconfig_flag, env):
    """Return (files, source_desc, notes). files = list of absolute paths."""
    notes = []
    if kubeconfig_flag:
        # --kubeconfig replaces everything; kubectl hard-errors if missing
        path = os.path.abspath(os.path.expanduser(kubeconfig_flag))
        if not os.path.isfile(path):
            return None, "--kubeconfig flag", [
                f"--kubeconfig file not found: {path} (kubectl would error)"
            ]
        return [(path, path)], "--kubeconfig flag", notes
    raw = env.get("KUBECONFIG")
    if raw is not None and raw.strip() != "":
        files = []
        for part in raw.split(":"):
            part = part.strip()
            if not part:
                continue  # empty entries ignored [observed]
            # ~ is NOT expanded by kubectl [observed]; keep verbatim so a
            # later "missing" note shows what the user actually wrote
            if part.startswith("~"):
                files.append(("~unexpanded:" + part, part))
            else:
                files.append((os.path.abspath(part), part))
        return files, "$KUBECONFIG", notes
    default = os.path.expanduser("~/.kube/config")
    if os.path.isfile(default):
        return [(default, default)], "default ~/.kube/config", notes
    return [], "default ~/.kube/config", notes


# ---------------------------------------------------------------------------
# Merge with provenance  [observed-kubectl-1.34.0]
# ---------------------------------------------------------------------------


class MergedConfig:
    def __init__(self):
        # name -> (entry_dict, file, lineno)
        self.clusters = {}
        self.users = {}
        self.contexts = {}
        self.current_context = None  # (value, file, lineno)
        # (kind, name, winner_file, winner_line, loser_file, loser_line)
        self.shadowed = []
        self.current_context_shadowed = []  # (value, winner_file, loser_file)
        self.file_status = []  # (file, shown, status, detail)
        self.missing_files = []  # shown paths from $KUBECONFIG that don't exist


def _entry_lineno(doc_entries, name):
    # best-effort: we stored linenos alongside; fallback None
    return None


def _named_entries(doc, key):
    out = []
    items = doc.get(key)
    if not isinstance(items, list):
        return out
    for item in items:
        if isinstance(item, dict) and "name" in item:
            out.append(item)
    return out


def merge_files(file_entries, home):
    """file_entries: list of (abspath_or_marker, shown). Returns MergedConfig."""
    mc = MergedConfig()
    for abspath, shown in file_entries:
        if abspath.startswith("~unexpanded:"):
            mc.missing_files.append(shown)
            mc.file_status.append((shown, shown, "missing",
                                   "kubectl skips it (~ not expanded)"))
            continue
        if not os.path.isfile(abspath):
            # missing files are silently skipped by kubectl [observed]
            mc.missing_files.append(shown)
            mc.file_status.append((abspath, shown, "missing",
                                   "silently skipped by kubectl"))
            continue
        try:
            with open(abspath, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            mc.file_status.append((abspath, shown, "unreadable", str(exc)))
            continue
        doc, unparsed = parse_kubeconfig_yaml(text)
        # find linenos of named entries by scanning the raw text
        entry_lines = _index_entry_lines(text)
        if "tabs-for-indentation" in unparsed:
            status, detail = "partial", "tabs used for indentation (not parseable)"
        else:
            status = "ok" if not unparsed else "partial"
            detail = "" if not unparsed else (
                "unparsed lines: " + ", ".join(str(n) for n in unparsed))
        mc.file_status.append((abspath, shown, status, detail))

        for kind, store in (("cluster", mc.clusters), ("user", mc.users),
                            ("context", mc.contexts)):
            for item in _named_entries(doc, kind + "s"):
                name = item["name"]
                lineno = entry_lines.get((kind + "s", str(name)))
                if name in store:
                    wfile, wline = store[name][1], store[name][2]
                    mc.shadowed.append((kind, name, wfile, wline,
                                        abspath, lineno))
                else:
                    store[name] = (item, abspath, lineno)

        cc = doc.get("current-context")
        if isinstance(cc, str) and cc.strip():
            cc_line = _find_key_line(text, "current-context")
            if mc.current_context is None:
                mc.current_context = (cc.strip(), abspath, cc_line)
            else:
                mc.current_context_shadowed.append(
                    (cc.strip(), mc.current_context[1], abspath))
    return mc


def _index_entry_lines(text):
    """Map (section, name) -> lineno of the list item's first line.

    Handles both `- name: X` first and name-after-body orderings.
    Best-effort: used for file:line provenance only.
    """
    out = {}
    section = None
    item_start = None
    for n, raw in enumerate(text.splitlines(), 1):
        indent = len(raw) - len(raw.lstrip(" "))
        s = raw.strip()
        m = re.match(r"^(clusters|users|contexts):\s*$", s)
        if m:
            section = m.group(1)
            item_start = None
            continue
        if indent == 0 and section and not s.startswith("-"):
            # new top-level key: section over (unless another section)
            if not re.match(r"^(clusters|users|contexts):", s):
                section = None
            item_start = None
            continue
        if section and indent == 0 and s.startswith("-"):
            item_start = n
            continue
        if section and item_start and indent == 2:
            nm = re.match(r"^name:\s*(.+?)\s*$", s)
            if nm:
                out[(section, nm.group(1).strip().strip("'\""))] = item_start
                item_start = None  # one name per item
    return out


def _find_key_line(text, key):
    for n, raw in enumerate(text.splitlines(), 1):
        if re.match(r"^" + re.escape(key) + r"\s*:", raw.strip()):
            return n
    return None


# ---------------------------------------------------------------------------
# Auth-kind detection (values never printed)
# ---------------------------------------------------------------------------

SECRET_MASK = "<set>"


def auth_kind(user):
    """Return (kind, details_dict) for a user entry. Never includes secrets."""
    if not isinstance(user, dict):
        return "none", {}
    if user.get("token"):
        return "token", {"source": "token"}
    if user.get("username") or user.get("password"):
        return "basic-auth", {"source": "username/password (deprecated)"}
    if user.get("client-certificate-data") or user.get("client-certificate"):
        return "client-cert", {"source": "client-certificate-data"}
    if user.get("client-key-data") or user.get("client-key"):
        return "client-key-only", {"source": "client-key without certificate"}
    exc = user.get("exec")
    if isinstance(exc, dict):
        cmd = exc.get("command", "?")
        env_names = [e.get("name") for e in exc.get("env", [])
                     if isinstance(e, dict) and "name" in e]
        return "exec-plugin", {"command": cmd, "env_names": env_names,
                               "apiVersion": exc.get("apiVersion")}
    ap = user.get("auth-provider")
    if isinstance(ap, dict):
        return "auth-provider", {"name": ap.get("name", "?")}
    return "none", {}


def cert_expiry(user):
    """Return (not_after_datetime|None, note). Parses cert DER for dates only."""
    data = user.get("client-certificate-data") if isinstance(user, dict) else None
    if not data or not isinstance(data, str):
        return None, "no embedded cert"
    try:
        der = base64.b64decode(data.strip(), validate=True)
    except Exception:
        return None, "cert data not valid base64"
    # Heuristic scan for X.509 Validity times: UTCTime 0x17/13 or
    # GeneralizedTime 0x18/15. Real certs carry notBefore then notAfter.
    times = []
    for m in re.finditer(rb"\x17\r(.{13})", der):
        times.append((m.group(1), "utc"))
    for m in re.finditer(rb"\x18\x0f(.{15})", der):
        times.append((m.group(1), "gen"))
    if len(times) < 2:
        return None, "validity period not found in cert bytes"
    try:
        raw, kind = times[1]  # notAfter is the second
        raw = raw.decode("ascii")
        if kind == "utc":
            dt = _dt.datetime.strptime(raw, "%y%m%d%H%M%SZ")
        else:
            dt = _dt.datetime.strptime(raw, "%Y%m%d%H%M%SZ")
        return dt.replace(tzinfo=_dt.timezone.utc), ""
    except Exception:
        return None, "could not parse cert time"


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


class Finding:
    def __init__(self, code, severity, title, detail):
        self.code = code          # e.g. "K03"
        self.severity = severity  # "warn" | "info"
        self.title = title
        self.detail = detail

    def to_dict(self):
        return {"code": self.code, "severity": self.severity,
                "title": self.title, "detail": self.detail}


def resolve(mc, context_override):
    """Resolve the effective context. Returns (report_dict, findings)."""
    findings = []
    rep = {"files": [], "shadowed": [], "effective": None}

    for abspath, shown, status, detail in mc.file_status:
        rep["files"].append({"path": abspath, "shown": shown,
                             "status": status, "detail": detail})
        if status == "partial":
            findings.append(Finding(
                "K12", "warn", "kubeconfig partially parsed",
                f"{shown}: {detail}. kubectl itself would refuse this "
                f"file outright; results below cover only the parsed "
                f"portion."))
        elif status == "unreadable":
            findings.append(Finding(
                "K05", "warn", "kubeconfig unreadable",
                f"{shown}: {detail}"))
    for shown in mc.missing_files:
        findings.append(Finding(
            "K05", "info", "listed kubeconfig file missing",
            f"{shown}: kubectl silently skips missing files — usually a "
            f"typo in $KUBECONFIG."))
    for kind, name, wfile, wline, lfile, lline in mc.shadowed:
        rep["shadowed"].append(
            {"kind": kind, "name": name,
             "winner": f"{wfile}:{wline}" if wline else wfile,
             "loser": f"{lfile}:{lline}" if lline else lfile})
        findings.append(Finding(
            "K03", "warn",
            f"{kind} {name!r} shadowed by earlier file",
            f"First-file-wins merge {OBSERVED_TAG}: the {kind} entry in "
            f"{wfile}{':' + str(wline) if wline else ''} wins entirely; "
            f"the same-named entry in {lfile}{':' + str(lline) if lline else ''} "
            f"is dead config — even its non-conflicting fields are "
            f"discarded. Reorder $KUBECONFIG if the later file should win."))
    for value, wfile, lfile in mc.current_context_shadowed:
        findings.append(Finding(
            "K04", "warn", "current-context shadowed by earlier file",
            f"{wfile} sets current-context and wins; the value "
            f"{value!r} in {lfile} is ignored."))

    # --- context selection: explicit override > merged current-context
    ctx_name = context_override
    ctx_source = "positional/--context argument"
    if not ctx_name and mc.current_context:
        ctx_name, cfile, cline = mc.current_context
        ctx_source = f"current-context in {cfile}" + \
            (f":{cline}" if cline else "")
    if not ctx_name:
        findings.append(Finding(
            "K01", "warn", "no current context",
            "No current-context is set in any kubeconfig file "
            f"{OBSERVED_TAG}; kubectl would refuse ('current-context is "
            "not set'). Pass a context name or run "
            "`kubectl config use-context NAME`."))
        return rep, findings

    ctx_entry, ctx_file, ctx_line = mc.contexts.get(ctx_name, ({}, None, None))
    if ctx_file is None:
        findings.append(Finding(
            "K01", "warn", f"context {ctx_name!r} not defined",
            f"No context named {ctx_name!r} exists in the merged config."))
        return rep, findings
    ctx = ctx_entry.get("context", {}) if isinstance(ctx_entry, dict) else {}
    if not isinstance(ctx, dict):
        ctx = {}

    eff = {"context": ctx_name,
           "context_source": ctx_source,
           "context_file": f"{ctx_file}:{ctx_line}" if ctx_line else ctx_file,
           "namespace": ctx.get("namespace") or "default"}

    # --- cluster
    cname = ctx.get("cluster")
    cluster_entry, cfile, cline = mc.clusters.get(cname, ({}, None, None)) \
        if cname else ({}, None, None)
    if cname is None or cfile is None:
        findings.append(Finding(
            "K02", "warn", "dangling cluster reference",
            f"Context {ctx_name!r} names cluster {cname!r}, which is not "
            f"defined {OBSERVED_TAG}; kubectl would fail "
            f"('cannot locate cluster' class error)."))
        eff["cluster"] = {"name": cname, "resolved": False}
    else:
        cbody = cluster_entry.get("cluster", {})
        if not isinstance(cbody, dict):
            cbody = {}
        server = cbody.get("server", "")
        eff["cluster"] = {
            "name": cname, "resolved": True,
            "server": server,
            "file": f"{cfile}:{cline}" if cline else cfile,
        }
        if isinstance(server, str) and server.startswith("http://"):
            findings.append(Finding(
                "K11", "warn", "cleartext API server URL",
                f"Cluster {cname!r} uses http:// — credentials travel "
                f"unencrypted."))
        if cbody.get("insecure-skip-tls-verify") is True:
            findings.append(Finding(
                "K07", "warn", "TLS verification disabled",
                f"Cluster {cname!r} sets insecure-skip-tls-verify: true."))
        ca = cbody.get("certificate-authority")
        if ca and isinstance(ca, str):
            ca_path = ca if os.path.isabs(ca) else os.path.normpath(
                os.path.join(os.path.dirname(cfile), ca))
            eff["cluster"]["certificate_authority"] = ca_path
            if not os.path.isfile(ca_path):
                findings.append(Finding(
                    "K14", "warn", "certificate-authority file missing",
                    f"Cluster {cname!r} references {ca_path} "
                    f"(from {cfile}:{cline if cline else '?'}), which does "
                    f"not exist."))
        elif cbody.get("certificate-authority-data"):
            eff["cluster"]["certificate_authority"] = "embedded"

    # --- user
    uname = ctx.get("user")
    user_entry, ufile, uline = mc.users.get(uname, ({}, None, None)) \
        if uname else ({}, None, None)
    if uname is None or ufile is None:
        findings.append(Finding(
            "K02", "warn", "dangling user reference",
            f"Context {ctx_name!r} names user {uname!r}, which is not "
            f"defined {OBSERVED_TAG}; kubectl would fail "
            f"('cannot locate user {uname}' class error)."))
        eff["user"] = {"name": uname, "resolved": False}
    else:
        ubody = user_entry.get("user", {})
        kind, kdetails = auth_kind(ubody if isinstance(ubody, dict) else {})
        eff["user"] = {
            "name": uname, "resolved": True,
            "auth_kind": kind,
            "auth_detail": kdetails,
            "file": f"{ufile}:{uline}" if uline else ufile,
        }
        if kind == "basic-auth":
            findings.append(Finding(
                "K08", "warn", "basic-auth credentials present",
                f"User {uname!r} carries username/password; Kubernetes "
                f"removed basic-auth support — this credential is dead "
                f"config and should be removed."))
        elif kind == "exec-plugin":
            findings.append(Finding(
                "K09", "info", "exec credential plugin",
                f"User {uname!r} authenticates via external command "
                f"{kdetails.get('command')!r} (env names: "
                f"{', '.join(kdetails.get('env_names') or ['(none)'])}). "
                f"kubewho never executes it; if the plugin is missing or "
                f"expired, auth fails at kubectl time."))
        elif kind == "auth-provider":
            findings.append(Finding(
                "K10", "info", "legacy auth-provider block",
                f"User {uname!r} uses auth-provider "
                f"{kdetails.get('name')!r}; client-go treats this as "
                f"legacy/deprecated — prefer exec plugins."))
        elif kind == "client-cert":
            not_after, note = cert_expiry(ubody)
            if not_after:
                eff["user"]["cert_not_after"] = not_after.isoformat()
                now = _dt.datetime.now(_dt.timezone.utc)
                if not_after < now:
                    findings.append(Finding(
                        "K06", "warn", "client certificate expired",
                        f"User {uname!r}'s client certificate expired "
                        f"{not_after.date().isoformat()}."))
                elif not_after - now < _dt.timedelta(days=30):
                    findings.append(Finding(
                        "K06", "warn", "client certificate expiring soon",
                        f"User {uname!r}'s client certificate expires "
                        f"{not_after.date().isoformat()} (<30d)."))
            elif note and note != "no embedded cert":
                findings.append(Finding(
                    "K06", "info", "could not check cert expiry",
                    f"User {uname!r}: {note}."))
        elif kind == "none":
            findings.append(Finding(
                "K02", "warn", "user has no credentials",
                f"User {uname!r} defines no token, cert, exec plugin or "
                f"auth-provider — kubectl would attempt anonymous access."))

    # --- secret-bearing files world-readable
    for abspath, shown, status, _ in mc.file_status:
        if status not in ("ok", "partial") or abspath.startswith("~"):
            continue
        try:
            mode = os.stat(abspath).st_mode
        except OSError:
            continue
        if mode & (stat.S_IROTH | stat.S_IWOTH):
            # check whether the file actually carries secrets
            has_secret = any(
                name in mc.users and
                auth_kind((mc.users[name][0].get("user", {}) or {}))[0]
                in ("token", "basic-auth", "client-cert", "client-key-only")
                and mc.users[name][1] == abspath
                for name in mc.users)
            if has_secret:
                findings.append(Finding(
                    "K13", "warn", "secret-bearing kubeconfig is world-readable",
                    f"{shown} is readable by other users "
                    f"({oct(stat.S_IMODE(mode))}) and contains credentials. "
                    f"Consider chmod 600."))

    rep["effective"] = eff
    return rep, findings

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def render_text(rep, findings, file_source, context_override):
    L = []
    eff = rep.get("effective")
    if eff:
        L.append(f"context:   {eff['context']}")
        L.append(f"  source:   {eff['context_source']}")
        L.append(f"  defined:  {eff['context_file']}")
        cl = eff["cluster"]
        if cl["resolved"]:
            L.append(f"cluster:   {cl['name']}")
            L.append(f"  server:   {cl['server']}")
            L.append(f"  from:     {cl['file']}")
            if "certificate_authority" in cl:
                L.append(f"  CA:       {cl['certificate_authority']}")
        else:
            L.append(f"cluster:   {cl['name']}  (UNRESOLVED)")
        u = eff["user"]
        if u["resolved"]:
            L.append(f"user:      {u['name']}  [{u['auth_kind']}]")
            L.append(f"  from:     {u['file']}")
            if u["auth_kind"] in ("token", "basic-auth", "client-cert",
                                  "client-key-only"):
                # presence only — the value is never printed
                L.append(f"  credential: {SECRET_MASK}")
            if u["auth_kind"] == "exec-plugin":
                d = u["auth_detail"]
                L.append(f"  plugin:   {d.get('command')} "
                         f"(apiVersion {d.get('apiVersion')})")
        else:
            L.append(f"user:      {u['name']}  (UNRESOLVED)")
        L.append(f"namespace: {eff['namespace']}")
    else:
        L.append("(no effective context resolved)")
    L.append("")
    L.append(f"config source: {file_source}")
    for f in rep["files"]:
        mark = {"ok": "ok", "partial": "PARTIAL",
                "missing": "missing", "unreadable": "UNREADABLE"}[f["status"]]
        extra = f" — {f['detail']}" if f["detail"] else ""
        L.append(f"  [{mark}] {f['shown']}{extra}")
    if rep["shadowed"]:
        L.append("")
        L.append("shadowed entries (first-file-wins; losers are dead config):")
        for s in rep["shadowed"]:
            L.append(f"  {s['kind']} {s['name']!r}: winner {s['winner']}; "
                     f"ignored {s['loser']}")
    if findings:
        L.append("")
        L.append("findings:")
        for f in findings:
            tag = "WARN" if f.severity == "warn" else "info"
            L.append(f"  [{tag} {f.code}] {f.title}")
            for dline in f.detail.split("\n"):
                L.append(f"          {dline}")
    else:
        L.append("")
        L.append("no findings.")
    L.append("")
    L.append("Model: files+env only; kubectl --context/--kubeconfig/--cluster/"
             "--user/--namespace flags are unseen. Merge semantics "
             + OBSERVED_TAG + ".")
    return "\n".join(L)


def render_list(mc):
    L = ["contexts:"]
    cur = mc.current_context[0] if mc.current_context else None
    names = sorted(mc.contexts)
    if not names:
        L.append("  (none defined)")
        return "\n".join(L)
    for name in names:
        entry, f, line = mc.contexts[name]
        ctx = entry.get("context", {}) if isinstance(entry, dict) else {}
        ctx = ctx if isinstance(ctx, dict) else {}
        star = "*" if name == cur else " "
        L.append(f"  {star} {name}")
        L.append(f"      cluster={ctx.get('cluster')} user={ctx.get('user')} "
                 f"namespace={ctx.get('namespace') or 'default'}")
        L.append(f"      from {f}{':' + str(line) if line else ''}")
    return "\n".join(L)


def build_parser():
    p = argparse.ArgumentParser(
        prog="kubewho",
        description="Which cluster+user+namespace will this shell's kubectl "
                    "target, and which file decided each value? "
                    "Read-only; never contacts a cluster or runs plugins.")
    p.add_argument("context", nargs="?",
                   help="resolve this context instead of current-context")
    p.add_argument("--kubeconfig",
                   help="use this file only (replaces $KUBECONFIG, like kubectl)")
    p.add_argument("--list", action="store_true",
                   help="list all contexts with their source files")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--version", action="store_true", help="print version")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.version:
        print(f"kubewho {VERSION}")
        return 0

    files, file_source, notes = resolve_file_list(args.kubeconfig, os.environ)
    if files is None:
        # --kubeconfig pointed at a missing file: kubectl would hard-error
        print(f"kubewho: {notes[0]}", file=sys.stderr)
        return 2
    if not files:
        msg = ("kubewho: no kubeconfig files found "
               "(no --kubeconfig, $KUBECONFIG unset/empty, "
               "no ~/.kube/config) [K15]")
        if args.json:
            print(json.dumps({"error": msg, "code": "K15"}, indent=2))
        else:
            print(msg)
        return 2

    mc = merge_files(files, os.path.expanduser("~"))

    if args.list:
        if args.json:
            out = {"current_context":
                   mc.current_context[0] if mc.current_context else None,
                   "contexts": []}
            for name in sorted(mc.contexts):
                entry, f, line = mc.contexts[name]
                ctx = entry.get("context", {}) if isinstance(entry, dict) else {}
                ctx = ctx if isinstance(ctx, dict) else {}
                out["contexts"].append({
                    "name": name,
                    "cluster": ctx.get("cluster"), "user": ctx.get("user"),
                    "namespace": ctx.get("namespace") or "default",
                    "file": f, "line": line})
            print(json.dumps(out, indent=2))
        else:
            print(render_list(mc))
        return 0

    rep, findings = resolve(mc, args.context)
    if args.json:
        print(json.dumps({
            "file_source": file_source,
            "files": rep["files"],
            "shadowed": rep["shadowed"],
            "effective": rep["effective"],
            "findings": [f.to_dict() for f in findings],
        }, indent=2))
    else:
        print(render_text(rep, findings, file_source, args.context))

    if rep["effective"] is None:
        return 1
    if any(f.severity == "warn" for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
