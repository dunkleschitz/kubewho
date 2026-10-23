# CHANGELOG — kubewho

## 1.0.0 (2026-10-23)

Initial release. Effective kubeconfig resolver: which
cluster+user+namespace this shell's kubectl will target, with per-value
file:line provenance.

- File-list resolution (`--kubeconfig` > `$KUBECONFIG` > `~/.kube/config`)
  and first-file-wins merge semantics verified empirically against
  kubectl 1.34.0.
- 15 rules K01–K15: shadowed entries (the headline footgun), dangling
  refs, no current-context, missing/unreadable files, client-cert
  expiry (<30d warn), insecure TLS, basic-auth dead credentials,
  exec-plugin/auth-provider notes, cleartext server URL, partial parses,
  world-readable secret files, missing CA file.
- Auth kinds: token / basic-auth / client-cert / exec-plugin /
  auth-provider / none; secret values never printed (`<set>` presence
  only); exec plugins never executed; no network I/O.
- Modes: default resolution, `[CONTEXT]` positional override, `--list`,
  `--json`; exit codes 0 clean / 1 findings / 2 usage-or-no-config.
- 27 tests: hermetic fixtures + agreement test against real kubectl
  (via `KUBEWWHO_KUBECTL`), never-prints-secret, never-executes-plugin,
  no-subprocess-imports.
