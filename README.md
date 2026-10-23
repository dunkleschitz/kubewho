# kubewho

Which cluster + user + namespace will this shell's next `kubectl` command
actually target — and which file decided each value?

`kubectl config current-context` tells you a name. `kubectl config view
--minify` shows the merged server and user. Neither tells you *which file*
each value came from — and the answer is counterintuitive: kubeconfig
files merge **first-file-wins per map key**, so a same-named user, cluster,
or context in a later `$KUBECONFIG` file is silently dead config. Order in
`$KUBECONFIG` is load-bearing, and wrong-cluster `apply` disasters start
here.

kubewho resolves the effective context with per-value `file:line`
provenance and flags the hazards: shadowed entries, dangling refs,
expired client certs, TLS verification disabled, exec-plugin auth, and
more.

## Usage

```
kubewho [CONTEXT] [--kubeconfig PATH] [--list] [--json] [--version]
```

- `kubewho` — resolve the effective context (positional `CONTEXT`
  overrides `current-context`, like `kubectl --context`)
- `kubewho --list` — every context with its source file (`*` = current)
- `kubewho --kubeconfig PATH` — use this file only (replaces
  `$KUBECONFIG`, like kubectl)
- `kubewho --json` — machine-readable output

Exit codes: `0` resolved clean · `1` findings (incl. unresolvable
context) · `2` usage or no kubeconfig found.

## Example

```
$ kubewho
context:   prod
  source:   current-context in /home/me/.kube/config:7
  defined:  /home/me/.kube/config:21
cluster:   prod
  server:   https://prod1.example.com:6443
  from:     /home/me/.kube/config:5
  CA:       embedded
user:      admin  [token]
  from:     /home/me/.kube/config:12
  credential: <set>
namespace: team-a

config source: $KUBECONFIG
  [ok] /home/me/.kube/config
  [ok] /home/me/.kube/old-cluster.yaml

shadowed entries (first-file-wins; losers are dead config):
  user 'admin': winner /home/me/.kube/config:12; ignored /home/me/.kube/old-cluster.yaml:8

findings:
  [WARN K03] user 'admin' shadowed by earlier file
          First-file-wins merge [observed-kubectl-1.34.0]: the user entry in
          /home/me/.kube/config:12 wins entirely; the same-named entry in
          /home/me/.kube/old-cluster.yaml:8 is dead config — even its
          non-conflicting fields are discarded. Reorder $KUBECONFIG if the
          later file should win.
```

## Rules (K01–K15)

| Code | Check |
|------|-------|
| K01 | no current-context / named context not defined — kubectl would refuse |
| K02 | dangling cluster or user reference; user with no credentials |
| K03 | same-named cluster/user/context shadowed by an earlier file (first-file-wins) |
| K04 | `current-context` shadowed by an earlier file's value |
| K05 | listed file missing/unreadable (kubectl silently skips — usually a typo) |
| K06 | client certificate expired or expiring within 30 days |
| K07 | `insecure-skip-tls-verify: true` |
| K08 | basic-auth username/password present (removed upstream — dead credential) |
| K09 | exec credential plugin (external command; reported, never run) |
| K10 | legacy `auth-provider` block (deprecated path) |
| K11 | `http://` API server URL |
| K12 | file partially parsed (unparsed lines listed; kubectl would refuse it) |
| K13 | secret-bearing kubeconfig file is world-readable |
| K14 | referenced `certificate-authority` file missing |
| K15 | no kubeconfig files found at all |

## Merge model

Verified empirically against kubectl 1.34.0 (2026-10-23); every rule is
tagged `[observed-kubectl-1.34.0]` in the source:

- File list: `--kubeconfig PATH` (single file, no merging) >
  `$KUBECONFIG` (colon-separated; empty entries dropped; relative paths
  resolve against the CWD; `~` is *not* expanded) > `~/.kube/config`.
  Missing files are silently skipped.
- Within the list, the **first file to define a cluster/user/context
  name wins entirely**; later same-named entries are discarded whole —
  even their non-conflicting fields.
- First file to set non-empty `current-context` wins; `kubectl
  --context` would override it (flags are unseen by this tool).

## Safety

- **Never prints secrets.** Tokens, passwords, client keys, and
  `exec.env` values are never displayed; presence is shown as `<set>`.
  There is no `--show` flag.
- **Never executes credential plugins.** `exec.command` is reported by
  name only (dedicated test asserts a marker-dropping plugin never runs).
- **Never contacts a cluster.** Pure file parsing; stdlib only
  (`sys/os/json/base64/re/datetime/stat/argparse`) — no subprocess,
  no sockets.

## Limitations

- Models files + environment only. `kubectl --context`, `--cluster`,
  `--user`, `--namespace`, and `--kubeconfig` flags on any real command
  line are invisible to a static tool — output is bannered accordingly.
- The YAML parser covers the machine-emitted kubeconfig subset (nested
  maps, `- ` lists, `|`/`>` block scalars, quoted scalars, comments).
  Anchors, flow collections, and exotic indentation are reported as
  unparsed lines (K12) rather than guessed.
- Client-cert expiry is a heuristic DER scan for the Validity period —
  correct on real certificates, labeled as such in the source.
- Auth-kind precedence within one user entry (token > basic-auth >
  client-cert > exec > auth-provider) follows client-go's documented
  stacking.

## Install

Single file, stdlib only, Python 3.8+:

```
curl -O <repo-url>/kubewho.py && chmod +x kubewho.py
```

## Pre-publish checklist

- [x] Single-file stdlib CLI, no dependencies
- [x] Tests: 27 passing (hermetic fixtures; agreement test vs real
      kubectl 1.34.0 runs when `KUBEWWHO_KUBECTL` is set)
- [x] Merge semantics verified empirically against real kubectl
- [x] Never-prints-secret + never-executes-plugin + no-subprocess tests
- [x] README documents problem, usage, rules, model, safety, limitations
- [x] CHANGELOG.md present
- [x] License: MIT (pending Godsby's approval per charter)
- [ ] Godsby's approval before first public publication
