#!/usr/bin/env python3
"""Tests for kubewho. Hermetic fixtures throughout.

Agreement test vs real kubectl runs only when KUBEWWHO_KUBECTL points at
a kubectl binary (used during the build to verify the merge model).
"""
import base64
import datetime
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kubewho
from kubewho import (parse_kubeconfig_yaml, merge_files, resolve,
                     resolve_file_list, auth_kind, cert_expiry, main)

VALID_CERT_B64 = (
    "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"
)
def _split_certs(blob):
    parts = ["MIID" + p for p in blob.split("MIID") if p.strip()]
    return parts


_CERTS = _split_certs(VALID_CERT_B64)
VALID_CERT = _CERTS[0]   # expires 2036-10-20


def _synthetic_der_b64(not_before, not_after):
    # Synthetic minimal DER: SEQUENCE { UTCTime notBefore, UTCTime notAfter }
    # kubewho's cert_expiry scans for the two UTCTime values, so this is
    # enough to exercise the K06 paths without a real certificate.
    def _utc(dt):
        return dt.strftime("%y%m%d%H%M%SZ").encode()
    der = (b"\x30\x1e" + b"\x17\x0d" + _utc(not_before)
           + b"\x17\x0d" + _utc(not_after))
    return base64.b64encode(der).decode()


def _soon_der_b64():
    # "Expiring soon" is relative to *now* (K06: notAfter within 30 days).
    # A fixed fixture cert went stale on 2026-11-02 and started failing
    # as genuinely expired — generate it relative to the run date.
    now = datetime.datetime.now(datetime.timezone.utc)
    return _synthetic_der_b64(now - datetime.timedelta(days=1),
                              now + datetime.timedelta(days=10))


def _expired_der_b64():
    return _synthetic_der_b64(
        datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
        datetime.datetime(2020, 6, 1, tzinfo=datetime.timezone.utc))


BASIC_CONFIG = """\
apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod
  cluster:
    server: https://prod1.example.com:6443
    certificate-authority-data: Zm9v
users:
- name: admin
  user:
    token: TOKEN-AAA
contexts:
- name: prod
  context:
    cluster: prod
    user: admin
    namespace: team-a
"""

SHADOW_CONFIG = """\
apiVersion: v1
kind: Config
current-context: dev
clusters:
- name: prod
  cluster:
    server: https://prod2.example.com:6443
users:
- name: admin
  user:
    token: TOKEN-BBB
contexts:
- name: dev
  context:
    cluster: prod
    user: admin
"""


class KubeWhoTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = {"KUBECONFIG": "", "HOME": self.tmp.name, "PATH": "/usr/bin:/bin"}

    def _write(self, name, content):
        p = os.path.join(self.tmp.name, name)
        with open(p, "w") as fh:
            fh.write(content)
        # Secret-bearing fixtures must be owner-only: kubewho flags
        # world-readable kubeconfigs (K13), and the default umask
        # varies (022 on CI runners makes 0644 files) — without this
        # the rc==0 tests fail anywhere the umask is permissive.
        os.chmod(p, 0o600)
        return p

    def _run(self, *argv, env_extra=None):
        from io import StringIO
        from unittest import mock
        env = dict(self.env)
        env.update(env_extra or {})
        old = sys.stdout
        sys.stdout = buf = StringIO()
        try:
            with mock.patch.dict(os.environ, env, clear=True):
                rc = main(list(argv))
        finally:
            sys.stdout = old
        return rc, buf.getvalue()

    # -- parser ---------------------------------------------------------
    def test_parser_basic(self):
        doc, unparsed = parse_kubeconfig_yaml(BASIC_CONFIG)
        self.assertEqual(unparsed, [])
        self.assertEqual(doc["current-context"], "prod")
        self.assertEqual(doc["clusters"][0]["name"], "prod")
        self.assertEqual(doc["clusters"][0]["cluster"]["server"],
                         "https://prod1.example.com:6443")
        self.assertEqual(doc["contexts"][0]["context"]["namespace"], "team-a")

    def test_parser_comment_and_quotes(self):
        text = ("clusters:\n"
                "- name: x # trailing comment\n"
                "  cluster:\n"
                '    server: "https://h:6443/#frag" # c\n'
                "    insecure-skip-tls-verify: true\n")
        doc, unparsed = parse_kubeconfig_yaml(text)
        self.assertEqual(unparsed, [])
        self.assertEqual(doc["clusters"][0]["cluster"]["server"],
                         "https://h:6443/#frag")
        self.assertIs(doc["clusters"][0]["cluster"]
                      ["insecure-skip-tls-verify"], True)

    def test_parser_block_scalar(self):
        text = ("users:\n- name: u\n  user:\n"
                "    exec:\n      command: x\n      args: |\n"
                "        --cluster\n        mycluster\n")
        doc, unparsed = parse_kubeconfig_yaml(text)
        self.assertEqual(unparsed, [])
        self.assertIn("--cluster", doc["users"][0]["user"]["exec"]["args"])

    def test_parser_anchor_is_unparsed(self):
        text = "clusters:\n- name: x\n  cluster: &a\n    server: https://h\n"
        doc, unparsed = parse_kubeconfig_yaml(text)
        self.assertTrue(unparsed)

    # -- merge ----------------------------------------------------------
    def test_first_file_wins(self):
        f1 = self._write("f1.yaml", BASIC_CONFIG)
        f2 = self._write("f2.yaml", SHADOW_CONFIG)
        mc = merge_files([(f1, f1), (f2, f2)], self.tmp.name)
        # same-named user: f1's token wins entirely
        self.assertEqual(mc.users["admin"][0]["user"]["token"], "TOKEN-AAA")
        self.assertEqual(mc.clusters["prod"][0]["cluster"]["server"],
                         "https://prod1.example.com:6443")
        self.assertEqual(mc.current_context[0], "prod")
        self.assertEqual(len([s for s in mc.shadowed if s[1] == "admin"]), 1)

    def test_reversed_order_wins_differently(self):
        f1 = self._write("f1.yaml", BASIC_CONFIG)
        f2 = self._write("f2.yaml", SHADOW_CONFIG)
        mc = merge_files([(f2, f2), (f1, f1)], self.tmp.name)
        self.assertEqual(mc.current_context[0], "dev")
        self.assertEqual(mc.users["admin"][0]["user"]["token"], "TOKEN-BBB")

    def test_missing_file_skipped(self):
        f1 = self._write("f1.yaml", BASIC_CONFIG)
        mc = merge_files([(f1, f1), ("/nope.yaml", "/nope.yaml")], self.tmp.name)
        self.assertEqual(mc.current_context[0], "prod")
        self.assertIn("/nope.yaml", mc.missing_files)

    # -- resolution -----------------------------------------------------
    def test_effective_resolution(self):
        f1 = self._write("f1.yaml", BASIC_CONFIG)
        rc, out = self._run("--kubeconfig", f1, env_extra={"KUBECONFIG": ""})
        self.assertEqual(rc, 0)
        self.assertIn("https://prod1.example.com:6443", out)
        self.assertIn("namespace: team-a", out)
        self.assertIn("[token]", out)

    def test_positional_context_override(self):
        f1 = self._write("f1.yaml", BASIC_CONFIG)
        f2 = self._write("f2.yaml", SHADOW_CONFIG)
        env = {"KUBECONFIG": f2}  # current-context would be dev
        rc, out = self._run("prod", "--kubeconfig", f1, env_extra=env)
        self.assertEqual(rc, 0)
        self.assertIn("context:   prod", out)

    def test_no_current_context(self):
        f1 = self._write("f1.yaml", "clusters:\n- name: c\n  cluster:\n"
                                    "    server: https://h\n")
        rc, out = self._run("--kubeconfig", f1)
        self.assertEqual(rc, 1)
        self.assertIn("K01", out)

    def test_dangling_user(self):
        cfg = ("current-context: b\ncontexts:\n- name: b\n  context:\n"
               "    cluster: c\n    user: ghost\nclusters:\n- name: c\n"
               "  cluster:\n    server: https://h\n")
        f1 = self._write("f1.yaml", cfg)
        rc, out = self._run("--kubeconfig", f1)
        self.assertEqual(rc, 1)
        self.assertIn("K02", out)
        self.assertIn("ghost", out)

    def test_no_config_at_all(self):
        rc, out = self._run(env_extra={"KUBECONFIG": "",
                                       "HOME": os.path.join(self.tmp.name, "nohome")})
        self.assertEqual(rc, 2)
        self.assertIn("K15", out)

    # -- rules ----------------------------------------------------------
    def test_k07_insecure_tls(self):
        cfg = BASIC_CONFIG.replace("certificate-authority-data: Zm9v",
                                   "insecure-skip-tls-verify: true")
        f1 = self._write("f1.yaml", cfg)
        rc, out = self._run("--kubeconfig", f1)
        self.assertEqual(rc, 1)
        self.assertIn("K07", out)

    def test_k08_basic_auth(self):
        cfg = BASIC_CONFIG.replace("token: TOKEN-AAA",
                                   "username: u\n    password: p")
        f1 = self._write("f1.yaml", cfg)
        rc, out = self._run("--kubeconfig", f1)
        self.assertIn("K08", out)
        self.assertIn("[basic-auth]", out)

    def test_k11_cleartext(self):
        cfg = BASIC_CONFIG.replace("https://prod1.example.com:6443",
                                   "http://prod1.example.com:8080")
        f1 = self._write("f1.yaml", cfg)
        rc, out = self._run("--kubeconfig", f1)
        self.assertIn("K11", out)

    def test_k06_cert_expiry(self):
        for b64, expect in ((VALID_CERT, None), (_soon_der_b64(), "expiring soon"),
                            (_expired_der_b64(), "expired")):
            cfg = BASIC_CONFIG.replace(
                "token: TOKEN-AAA",
                "client-certificate-data: " + b64 + "\n    client-key-data: Zm9v")
            f1 = self._write("f1.yaml", cfg)
            rc, out = self._run("--kubeconfig", f1)
            if expect is None:
                self.assertNotIn("K06", out, "valid cert should not flag K06")
            else:
                self.assertIn("K06", out)
                self.assertIn(expect, out)

    def test_k09_exec_plugin(self):
        cfg = (BASIC_CONFIG.replace("token: TOKEN-AAA",
                                    "exec:\n      apiVersion: client.authentication.k8s.io/v1\n"
                                    "      command: aws-iam-authenticator\n"
                                    "      args: [--cluster, prod]\n"
                                    "      env:\n      - name: AWS_PROFILE\n"
                                    "        value: prod"))
        f1 = self._write("f1.yaml", cfg)
        rc, out = self._run("--kubeconfig", f1)
        self.assertIn("K09", out)
        self.assertIn("aws-iam-authenticator", out)

    def test_k13_world_readable(self):
        f1 = self._write("f1.yaml", BASIC_CONFIG)
        os.chmod(f1, 0o644)
        rc, out = self._run("--kubeconfig", f1)
        self.assertIn("K13", out)

    def test_k14_missing_ca_file(self):
        cfg = BASIC_CONFIG.replace("certificate-authority-data: Zm9v",
                                   "certificate-authority: /nope/ca.crt")
        f1 = self._write("f1.yaml", cfg)
        rc, out = self._run("--kubeconfig", f1)
        self.assertIn("K14", out)

    def test_k05_missing_listed_file(self):
        f1 = self._write("f1.yaml", BASIC_CONFIG)
        env = {"KUBECONFIG": f1 + ":/nope/k.yaml"}
        rc, out = self._run(env_extra=env)
        self.assertIn("K05", out)

    # -- safety ---------------------------------------------------------
    def test_never_prints_secrets(self):
        cfg = (BASIC_CONFIG.replace("token: TOKEN-AAA",
                                    "token: SECRET-TOKEN-XYZ\n    client-key-data: SECRETKEYDATA"))
        f1 = self._write("f1.yaml", cfg)
        rc, text_out = self._run("--kubeconfig", f1)
        rc, json_out = self._run("--kubeconfig", f1, "--json")
        for out in (text_out, json_out):
            self.assertNotIn("SECRET-TOKEN-XYZ", out)
            self.assertNotIn("SECRETKEYDATA", out)
        self.assertIn("<set>", text_out)  # masked presence shown in text mode

    def test_never_executes_plugins(self):
        marker = os.path.join(self.tmp.name, "MARKER")
        cfg = (BASIC_CONFIG.replace(
            "token: TOKEN-AAA",
            "exec:\n      command: touch\n      args: [" + marker + "]"))
        f1 = self._write("f1.yaml", cfg)
        self._run("--kubeconfig", f1)
        self._run("--kubeconfig", f1, "--json")
        self.assertFalse(os.path.exists(marker))

    def test_no_network_or_subprocess_imports(self):
        src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "kubewho.py")
        with open(src_path) as fh:
            src = fh.read()
        for mod in ("socket", "urllib", "subprocess", "http.client", "ssl"):
            self.assertNotIn(f"import {mod}", src)

    # -- json / list ----------------------------------------------------
    def test_json_output(self):
        f1 = self._write("f1.yaml", BASIC_CONFIG)
        rc, out = self._run("--kubeconfig", f1, "--json")
        data = json.loads(out)
        self.assertEqual(data["effective"]["cluster"]["server"],
                         "https://prod1.example.com:6443")
        self.assertEqual(data["effective"]["user"]["auth_kind"], "token")

    def test_list_mode(self):
        f1 = self._write("f1.yaml", BASIC_CONFIG)
        f2 = self._write("f2.yaml", SHADOW_CONFIG)
        env = {"KUBECONFIG": f1 + ":" + f2}
        rc, out = self._run("--list", env_extra=env)
        self.assertEqual(rc, 0)
        self.assertIn("* prod", out)
        self.assertIn("dev", out)

    def test_version(self):
        rc, out = self._run("--version")
        self.assertEqual(rc, 0)
        self.assertIn("kubewho", out)

    # -- agreement with real kubectl ------------------------------------
    def test_agreement_with_kubectl(self):
        kbin = os.environ.get("KUBEWWHO_KUBECTL")
        if not kbin or not os.path.isfile(kbin):
            self.skipTest("KUBEWWHO_KUBECTL not set")
        f1 = self._write("f1.yaml", BASIC_CONFIG)
        f2 = self._write("f2.yaml", SHADOW_CONFIG)
        env = dict(os.environ, KUBECONFIG=f1 + ":" + f2)
        cur = subprocess.run([kbin, "config", "current-context"],
                             capture_output=True, text=True, env=env)
        srv = subprocess.run(
            [kbin, "config", "view", "--minify", "-o",
             "jsonpath={.clusters[0].cluster.server}"], capture_output=True,
            text=True, env=env)
        rc, out = self._run(env_extra={"KUBECONFIG": f1 + ":" + f2})
        # rc is 1 here: the fixture intentionally shadows entries (K03)
        self.assertIn(rc, (0, 1))
        self.assertIn(f"context:   {cur.stdout.strip()}", out)
        self.assertIn(srv.stdout.strip(), out)


if __name__ == "__main__":
    unittest.main()
