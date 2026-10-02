from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ARTIFACT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT / "src"))

from cases import event  # noqa: E402
from reference_profile import (  # noqa: E402
    certificate_bytes,
    issue_reference_certificate,
    public_key_hex,
    verify_reference_certificate,
)


def key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(("unit-test:" + label).encode("ascii")).digest()
    )


class ReferenceProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = key("authority")
        self.long_a = key("long-a")
        self.long_b = key("long-b")
        self.eph_a = key("eph-a")
        self.eph_b = key("eph-b")
        self.authority_hex = public_key_hex(self.authority.public_key())
        self.context = {
            "domain": "AMS-CAUSAL-ROSTER-V1",
            "mode": "FRESH",
            "application": "test-application",
            "session": "session-1",
            "message": "approve-object-1",
            "namespace": "test-roster",
            "events": [
                event("a", "A", key=public_key_hex(self.long_a.public_key()), weight=4),
                event("b", "B", ["a"], key=public_key_hex(self.long_b.public_key()), weight=5),
            ],
            "lower": ["a"],
            "upper": ["a", "b"],
            "cut": ["a", "b"],
            "profile": [["A", "a"], ["B", "b"]],
        }
        self.cert = issue_reference_certificate(
            self.context,
            self.authority,
            {"a": self.long_a, "b": self.long_b},
            {"A": self.eph_a, "B": self.eph_b},
        )

    def assertMutationRejected(self, path: list[object], value: object) -> None:
        mutated = copy.deepcopy(self.cert)
        target = mutated
        for component in path[:-1]:
            target = target[component]  # type: ignore[index]
        target[path[-1]] = value  # type: ignore[index]
        self.assertFalse(verify_reference_certificate(mutated, self.authority_hex))

    def test_issue_verify_and_canonical_bytes(self):
        self.assertTrue(verify_reference_certificate(self.cert, self.authority_hex))
        encoded = certificate_bytes(self.cert, self.authority_hex)
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertEqual(json.loads(encoded), self.cert)
        self.assertNotIn(b" ", encoded)

    def test_wrong_history_trust_anchor_rejected(self):
        self.assertFalse(
            verify_reference_certificate(self.cert, public_key_hex(key("other").public_key()))
        )

    def test_history_signature_and_schema_mutations_rejected(self):
        sig = self.cert["history"]["signature"]
        self.assertMutationRejected(["history", "signature"], "00" + sig[2:])
        self.assertMutationRejected(["history", "scheme"], "UNKNOWN")
        mutated = copy.deepcopy(self.cert)
        mutated["history"]["extra"] = "x"
        self.assertFalse(verify_reference_certificate(mutated, self.authority_hex))

    def test_context_binding_rejects_every_application_identifier(self):
        for field in ("domain", "application", "session", "message", "namespace"):
            with self.subTest(field=field):
                self.assertMutationRejected(["context", field], self.cert["context"][field] + "!")

    def test_context_binding_rejects_event_view_and_profile_mutations(self):
        mutations = [
            (["context", "events", 0, "weight"], 99),
            (["context", "events", 0, "key"], public_key_hex(key("replacement").public_key())),
            (["context", "events", 1, "parents"], []),
            (["context", "lower"], []),
            (["context", "upper"], ["a"]),
            (["context", "cut"], ["a"]),
            (["context", "profile", 0, 0], "X"),
            (["context", "mode"], "HIST"),
        ]
        for path, value in mutations:
            with self.subTest(path=path):
                self.assertMutationRejected(path, value)

    def test_noncanonical_context_order_rejected(self):
        mutated = copy.deepcopy(self.cert)
        mutated["context"]["events"].reverse()
        self.assertFalse(verify_reference_certificate(mutated, self.authority_hex))
        mutated = copy.deepcopy(self.cert)
        mutated["context"]["profile"].reverse()
        self.assertFalse(verify_reference_certificate(mutated, self.authority_hex))

    def test_ephemeral_table_binds_identity_event_and_key(self):
        for column, value in (
            (0, "X"),
            (1, "b"),
            (2, public_key_hex(key("new-eph").public_key())),
        ):
            with self.subTest(column=column):
                self.assertMutationRejected(["ephemeral_table", 0, column], value)
        mutated = copy.deepcopy(self.cert)
        mutated["ephemeral_table"].reverse()
        self.assertFalse(verify_reference_certificate(mutated, self.authority_hex))

    def test_duplicate_ephemeral_key_rejected(self):
        self.assertMutationRejected(
            ["ephemeral_table", 1, 2], self.cert["ephemeral_table"][0][2]
        )

    def test_delegation_mutations_rejected(self):
        row = self.cert["delegations"][0]
        mutations = {
            "scheme": "OTHER",
            "identity": "X",
            "event": "b",
            "long_term_key": public_key_hex(key("other-long").public_key()),
            "signature": "00" + row["signature"][2:],
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                self.assertMutationRejected(["delegations", 0, field], value)
        mutated = copy.deepcopy(self.cert)
        mutated["delegations"].reverse()
        self.assertFalse(verify_reference_certificate(mutated, self.authority_hex))
        mutated = copy.deepcopy(self.cert)
        mutated["delegations"][0]["extra"] = "x"
        self.assertFalse(verify_reference_certificate(mutated, self.authority_hex))

    def test_base_signature_mutations_rejected(self):
        row = self.cert["base"]["signatures"][0]
        mutations = {
            "identity": "X",
            "event": "b",
            "ephemeral_key": public_key_hex(key("other-eph").public_key()),
            "signature": "00" + row["signature"][2:],
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                self.assertMutationRejected(["base", "signatures", 0, field], value)
        mutated = copy.deepcopy(self.cert)
        mutated["base"]["signatures"].reverse()
        self.assertFalse(verify_reference_certificate(mutated, self.authority_hex))
        mutated = copy.deepcopy(self.cert)
        mutated["base"]["signatures"] = mutated["base"]["signatures"][:-1]
        self.assertFalse(verify_reference_certificate(mutated, self.authority_hex))

    def test_certificate_schema_and_type_are_strict(self):
        self.assertMutationRejected(["type"], "OTHER")
        mutated = copy.deepcopy(self.cert)
        mutated["extra"] = "x"
        self.assertFalse(verify_reference_certificate(mutated, self.authority_hex))
        mutated = copy.deepcopy(self.cert)
        del mutated["base"]
        self.assertFalse(verify_reference_certificate(mutated, self.authority_hex))

    def test_noncanonical_hex_and_all_zero_keys_rejected(self):
        upper = self.cert["delegations"][0]["long_term_key"].upper()
        self.assertMutationRejected(["delegations", 0, "long_term_key"], upper)
        self.assertMutationRejected(["ephemeral_table", 0, 2], "00" * 32)
        self.assertMutationRejected(["history", "signature"], "00")

    def test_issuer_rejects_mismatched_or_missing_private_keys(self):
        with self.assertRaises(ValueError):
            issue_reference_certificate(
                self.context,
                self.authority,
                {"a": key("wrong"), "b": self.long_b},
                {"A": self.eph_a, "B": self.eph_b},
            )
        with self.assertRaises(ValueError):
            issue_reference_certificate(
                self.context,
                self.authority,
                {"a": self.long_a},
                {"A": self.eph_a, "B": self.eph_b},
            )
        with self.assertRaises(ValueError):
            issue_reference_certificate(
                self.context,
                self.authority,
                {"a": self.long_a, "b": self.long_b},
                {"A": self.eph_a},
            )

    def test_reference_profile_rejects_malformed_active_key_even_if_unselected(self):
        malformed = copy.deepcopy(self.context)
        malformed["events"].append(
            event("c", "C", ["b"], key="not-a-canonical-ed25519-key")
        )
        malformed["upper"] = ["a", "b", "c"]
        malformed["cut"] = ["a", "b", "c"]
        with self.assertRaises(ValueError):
            issue_reference_certificate(
                malformed,
                self.authority,
                {"a": self.long_a, "b": self.long_b},
                {"A": self.eph_a, "B": self.eph_b},
            )

    def test_reference_profile_rejects_cross_role_key_reuse(self):
        with self.assertRaisesRegex(ValueError, "ephemeral keys"):
            issue_reference_certificate(
                self.context,
                self.authority,
                {"a": self.long_a, "b": self.long_b},
                {"A": self.long_a, "B": self.eph_b},
            )
        authority_as_event = copy.deepcopy(self.context)
        authority_as_event["events"][0]["key"] = self.authority_hex
        with self.assertRaisesRegex(ValueError, "history key"):
            issue_reference_certificate(
                authority_as_event,
                self.authority,
                {"a": self.authority, "b": self.long_b},
                {"A": self.eph_a, "B": self.eph_b},
            )

    def test_reference_profile_rejects_cross_identity_long_term_key_alias(self):
        aliased = copy.deepcopy(self.context)
        aliased["events"][1]["key"] = public_key_hex(self.long_a.public_key())
        with self.assertRaisesRegex(ValueError, "two identities"):
            issue_reference_certificate(
                aliased,
                self.authority,
                {"a": self.long_a, "b": self.long_a},
                {"A": self.eph_a, "B": self.eph_b},
            )

    def test_identical_public_key_bytes_do_not_replace_event_identity(self):
        # Even when the same long-term key is reused across versions, the selected
        # event ID remains explicitly present in the table and signed delegation.
        rotated = copy.deepcopy(self.context)
        rotated["events"].append(
            event("a2", "A", ["a", "b"], key=public_key_hex(self.long_a.public_key()))
        )
        rotated["upper"] = ["a", "b", "a2"]
        rotated["cut"] = ["a", "b", "a2"]
        rotated["profile"] = [["A", "a2"]]
        cert = issue_reference_certificate(
            rotated,
            self.authority,
            {"a2": self.long_a},
            {"A": key("rotated-ephemeral")},
        )
        self.assertTrue(verify_reference_certificate(cert, self.authority_hex))
        self.assertEqual(cert["ephemeral_table"][0][1], "a2")

    def test_packaged_example_and_cli(self):
        cert_path = ARTIFACT / "examples" / "reference-certificate.json"
        key_path = ARTIFACT / "examples" / "reference-history-public-key.txt"
        packaged = json.loads(cert_path.read_text(encoding="ascii"))
        anchor = key_path.read_text(encoding="ascii").strip()
        self.assertTrue(verify_reference_certificate(packaged, anchor))
        proc = subprocess.run(
            [sys.executable, str(ARTIFACT / "verify_reference.py"), str(cert_path), str(key_path)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "VALID")

    def test_cli_rejects_noncanonical_wire_encoding(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert_path = Path(tmp) / "cert.json"
            key_path = Path(tmp) / "key.txt"
            cert_path.write_text(json.dumps(self.cert, indent=2), encoding="ascii")
            key_path.write_text(self.authority_hex + "\n", encoding="ascii")
            proc = subprocess.run(
                [sys.executable, str(ARTIFACT / "verify_reference.py"), str(cert_path), str(key_path)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("not canonical", proc.stderr)

    def test_cli_rejects_tampered_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert_path = Path(tmp) / "cert.json"
            key_path = Path(tmp) / "key.txt"
            bad = copy.deepcopy(self.cert)
            bad["context"]["message"] += "!"
            cert_path.write_text(json.dumps(bad), encoding="ascii")
            key_path.write_text(self.authority_hex, encoding="ascii")
            proc = subprocess.run(
                [sys.executable, str(ARTIFACT / "verify_reference.py"), str(cert_path), str(key_path)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertEqual(proc.stderr.strip(), "INVALID")

    def test_cli_rejects_duplicate_json_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert_path = Path(tmp) / "cert.json"
            key_path = Path(tmp) / "key.txt"
            canonical = certificate_bytes(self.cert, self.authority_hex).decode("ascii")
            # json.loads would otherwise keep the final member.  The strict wire
            # comparison must reject the duplicate-key representation.
            duplicate = canonical.replace(
                '{"base":', '{"type":"CAUSAL-ROSTER-CERTIFICATE-V1","base":', 1
            )
            cert_path.write_text(duplicate, encoding="ascii")
            key_path.write_text(self.authority_hex + "\n", encoding="ascii")
            proc = subprocess.run(
                [sys.executable, str(ARTIFACT / "verify_reference.py"), str(cert_path), str(key_path)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("not canonical", proc.stderr)

    def test_cli_rejects_oversized_input_before_json_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert_path = Path(tmp) / "cert.json"
            key_path = Path(tmp) / "key.txt"
            cert_path.write_bytes(b" " * (2 * 1024 * 1024 + 1))
            key_path.write_text(self.authority_hex + "\n", encoding="ascii")
            proc = subprocess.run(
                [sys.executable, str(ARTIFACT / "verify_reference.py"), str(cert_path), str(key_path)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("exceeds", proc.stderr)


if __name__ == "__main__":
    unittest.main()
