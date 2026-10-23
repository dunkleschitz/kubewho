# DESIGN — kubewho

Effective kubeconfig resolver: which cluster+user+namespace will this
shell's next `kubectl` command target, and which file decided each value.

## The question

`kubectl config current-context` answers *what* (a context name).
`kubectl config view --minify` answers *what* (merged server/user).
Neither answers *which file decided it* — and the answer is
counterintuitive: kubeconfig files merge **first-file-wins per map key**,
so a same-named user/cluster/context in a later file is silently dead
config. Order in `$KUBECONFIG` is load-bearing. Wrong-cluster `apply`
disasters start here.

## Verified semantics (empirical, kubectl 1.34.0, 2026-10-23)

Against the real binary with crafted fixtures (`/tmp/kubeverify`):

- [observed] File list: `--kubeconfig PATH` (single file, replaces env,
  no merging) > `$KUBECONFIG` (colon-separated; empty entries dropped;
  relative entries resolve against CWD; `~` NOT expanded) > `~/.kube/
  config` default. Missing files are **silently skipped** (no error).
- [observed] Merge: for `clusters`/`users`/`contexts`, the **first file
  to define a name wins entirely** — even non-conflicting fields of a
  same-named entry in a later file are discarded (verified: token from
  f1's `admin` won; f3's same-named `admin` client-cert was dropped).
  First file to set non-empty `current-context` wins.
- [observed] Context selection: `--context` flag > merged
  `current-context`. No current-context anywhere → kubectl errors
  (`current-context is not set`).
- [observed] Dangling refs → kubectl errors at use time:
  `cannot locate user ghost` (same shape for clusters).
- [observed] Unparseable YAML in any listed file → hard error
  (`error loading config file ... yaml: ...`); the file does not
  partially merge.

## Hazard-first review

1. **Secrets.** kubeconfig users carry tokens, basic-auth passwords,
   client keys, exec-plugin env. Structural: kubewho NEVER prints a
   secret value — presence + kind only, constant mask. No `--show`
   flag exists (pgwho precedent). Cert expiry is derived from a
   base64 decode used only for the date; cert/key material never
   reaches output. Dedicated never-prints-secret test.
2. **Exec plugins.** The effective credential may come from an external
   command (`users[].user.exec.command`). kubewho reports the command
   name and env *names* only and NEVER executes it (dedicated
   never-executes test with a marker-dropping fixture, npmwho/agentwho
   precedent).
3. **No network.** kubectl itself is never invoked at runtime;
   resolution is pure file parsing. The empirical binary was a
   build-time verification instrument only. Dedicated no-subprocess
   test (no socket/http/urllib/subprocess imports in the resolver —
   `sys`/`os`/`json`/`base64`/`re`/`datetime`/`argparse` only).
4. **False-precision on merge.** The whole tool is the verified model
   above; every rule tagged [observed-kubectl-1.34.0]. CLI flags
   (`--context`, `--kubeconfig`, `--cluster`, `--user`, `--namespace`)
   are invisible to a static tool — bannered "effective over
   files+env; CLI flags unseen" (tfwho precedent).
5. **YAML without PyYAML (stdlib-only).** A hand parser is the riskiest
   part. Structural honesty: the parser handles the machine-emitted
   kubeconfig subset (nested maps, `- ` lists, `- name:` list-of-maps,
   `|`/`>` block scalars, quoted/plain scalars, `#` comments,
   `---` markers); anything else (anchors, flow collections, exotic
   indentation) is recorded as an **unparsed line with its line
   number**, the file is marked partial, and the coverage section
   reports it. Partial answers are never presented as complete
   (cronwho precedent). kubectl's own verdict on such files is an
   error — we say that explicitly.
6. **CA file paths.** `certificate-authority` is relative to the
   kubeconfig file's directory (same class as sshwho's relative-Include
   find). Resolved and checked for existence; a missing CA is a rule
   hit, not a crash.

## Scope v1

`kubewho [CONTEXT]` → effective cluster (server, CA status), user
(auth kind + source), namespace, each with file:line provenance; the
decision chain (file list order → merge winners → context selection).
`--list`: every context with its winner file. `--kubeconfig PATH`
override (replaces env, like kubectl). `--json`, `--version`.
Exit 0 resolved clean / 1 findings (incl. unresolvable context) /
2 usage or no config at all.

Rules K01–K15:
K01 no current-context (and no positional/flag override) — kubectl
    would refuse; K02 dangling cluster/user ref; K03 same-named
    entry shadowed by an earlier file (winner file:line + loser
    file:line — the headline footgun); K04 current-context shadowed
    by an earlier file's value; K05 listed file missing (kubectl
    silently skips — probably a typo); K06 client cert expired /
    expiring <30d; K07 insecure-skip-tls-verify; K08 basic-auth
    username+password present (k8s removed basic auth — dead
    credential); K09 exec-plugin user (external credential source,
    never executed); K10 auth-provider block present (legacy
    gcp/azure/oidc — deprecated path); K11 http:// server URL;
    K12 file partially parsed (unparsed lines listed); K13 secret-
    bearing file world-readable; K14 missing certificate-authority
    file; K15 no kubeconfig files found at all (exit 2).

Auth-kind precedence within one user entry: token > basic >
client-cert(-data or -file) > exec > auth-provider > none
([observed] from kubectl's own auth stacking docs; per-kind presence
reported, values masked).

## Non-goals

Writing/merging kubeconfigs (`kubectl config view --flatten` owns
that); switching contexts (kubectx); talking to clusters.
