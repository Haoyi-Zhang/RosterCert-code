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
sys.path.insert(0, str(ARTIFACT))
sys.path.insert(0, str(ARTIFACT / "src"))

from cases import event  # noqa: E402
from reference_profile import (  # noqa: E402
    certificate_bytes,
    decode_public_key,
    issue_reference_certificate,
    public_key_hex,
    verify_reference_certificate,
)
from session import (canonical_json, history_payload, normalize_context,
                     normalize_ephemeral_table)  # noqa: E402
from verify_reference import _bounded_read  # noqa: E402


def key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(("boundary-test:" + label).encode("ascii")).digest()
    )


def legacy_unsafe_json(value: object) -> bytes:
    """The pre-fix serializer used for collision regression assertions only."""
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


class BoundaryTests(unittest.TestCase):
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
            "application": "boundary-application",
            "session": "boundary-session-1",
            "message": "approve",
            "namespace": "boundary-roster",
            "events": [
                event("a", "A", key=public_key_hex(self.long_a.public_key())),
                event("b", "B", ["a"], key=public_key_hex(self.long_b.public_key())),
            ],
            "lower": ["a"],
            "upper": ["a", "b"],
            "cut": ["a", "b"],
            "profile": [["A", "a"], ["B", "b"]],
        }

    def issue(self, context: dict | None = None):
        return issue_reference_certificate(
            self.context if context is None else context,
            self.authority,
            {"a": self.long_a, "b": self.long_b},
            {"A": self.eph_a, "B": self.eph_b},
        )

    def test_application_surrogate_alias_is_a_static_collision_but_outside_domain(self):
        scalar_application = "app-" + chr(0x1F600)
        surrogate_application = "app-" + chr(0xD83D) + chr(0xDE00)
        scalar_payload = legacy_unsafe_json({"application": scalar_application})
        surrogate_payload = legacy_unsafe_json({"application": surrogate_application})
        self.assertEqual(scalar_payload, surrogate_payload)
        miniature_signature = self.authority.sign(scalar_payload)
        # The legacy serializer therefore gave two Python values the same signed
        # miniature-certificate bytes. This is a static object-interface risk,
        # not evidence that a deployed network verifier was forged.
        self.authority.public_key().verify(miniature_signature, surrogate_payload)

        bad_context = copy.deepcopy(self.context)
        bad_context["application"] += chr(0x1F600)
        with self.assertRaises(ValueError):
            self.issue(bad_context)

        cert = self.issue()
        scalar = copy.deepcopy(cert)
        surrogate_pair = copy.deepcopy(cert)
        scalar["context"]["application"] = scalar_application
        surrogate_pair["context"]["application"] = surrogate_application
        # This equality documents the object-interface alias that motivated the
        # boundary repair. It is not represented as a network forgery result.
        scalar_raw = legacy_unsafe_json(scalar)
        self.assertEqual(scalar_raw, legacy_unsafe_json(surrogate_pair))
        self.assertFalse(verify_reference_certificate(scalar, self.authority_hex))
        self.assertFalse(verify_reference_certificate(surrogate_pair, self.authority_hex))
        with tempfile.TemporaryDirectory() as tmp:
            cert_path = Path(tmp) / "nonascii-identifier.json"
            anchor_path = Path(tmp) / "anchor.txt"
            cert_path.write_bytes(scalar_raw)
            anchor_path.write_text(self.authority_hex + "\n", encoding="ascii")
            proc = subprocess.run(
                [sys.executable, str(ARTIFACT / "verify_reference.py"),
                 str(cert_path), str(anchor_path)],
                check=False, capture_output=True, text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("INVALID", proc.stderr)

    def test_unicode_scalar_message_is_injective_and_surrogate_object_is_rejected(self):
        context = copy.deepcopy(self.context)
        context["message"] = "approve-" + chr(0x1F600)
        cert = self.issue(context)
        self.assertTrue(verify_reference_certificate(cert, self.authority_hex))
        raw = certificate_bytes(cert, self.authority_hex)
        self.assertTrue(raw.isascii())
        with tempfile.TemporaryDirectory() as tmp:
            cert_path = Path(tmp) / "unicode-message.json"
            anchor_path = Path(tmp) / "anchor.txt"
            cert_path.write_bytes(raw)
            anchor_path.write_text(self.authority_hex + "\n", encoding="ascii")
            proc = subprocess.run(
                [sys.executable, str(ARTIFACT / "verify_reference.py"),
                 str(cert_path), str(anchor_path)],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), "VALID")

        surrogate = copy.deepcopy(cert)
        surrogate["context"]["message"] = "approve-" + chr(0xD83D) + chr(0xDE00)
        self.assertEqual(legacy_unsafe_json(cert), legacy_unsafe_json(surrogate))
        self.assertFalse(verify_reference_certificate(surrogate, self.authority_hex))
        with self.assertRaises(ValueError):
            certificate_bytes(surrogate, self.authority_hex)
        bad_context = copy.deepcopy(context)
        bad_context["message"] = "approve-" + chr(0xD83D) + chr(0xDE00)
        with self.assertRaises(ValueError):
            self.issue(bad_context)

    def test_all_identifier_classes_require_printable_ascii(self):
        for field in ("domain", "application", "session", "namespace"):
            with self.subTest(field=field):
                bad = copy.deepcopy(self.context)
                bad[field] += chr(0x1F600)
                with self.assertRaises(ValueError):
                    normalize_context(bad)

        bad = copy.deepcopy(self.context)
        bad["events"][0]["id"] = "a" + chr(0x1F600)
        with self.assertRaises(ValueError):
            normalize_context(bad)
        bad = copy.deepcopy(self.context)
        bad["events"][0]["owner"] = "A" + chr(0x1F600)
        with self.assertRaises(ValueError):
            normalize_context(bad)
        bad = copy.deepcopy(self.context)
        bad["profile"][0][0] = "A" + chr(0x1F600)
        with self.assertRaises(ValueError):
            normalize_context(bad)

        table = [
            ["A", "a", public_key_hex(self.eph_a.public_key())],
            ["B", "b", public_key_hex(self.eph_b.public_key())],
        ]
        bad_table = copy.deepcopy(table)
        bad_table[0][1] = "a" + chr(0x1F600)
        with self.assertRaises(ValueError):
            normalize_ephemeral_table(self.context, bad_table)

    def test_unselected_ff_public_key_is_rejected_as_an_invalid_point(self):
        invalid_context = copy.deepcopy(self.context)
        invalid_context["events"].append(event("c", "C", ["b"], key="ff" * 32))
        invalid_context["upper"].append("c")
        invalid_context["cut"].append("c")
        with self.assertRaisesRegex(ValueError, "valid Ed25519 verification key"):
            self.issue(invalid_context)

        valid_context = copy.deepcopy(self.context)
        valid_c = key("long-c")
        valid_context["events"].append(
            event("c", "C", ["b"], key=public_key_hex(valid_c.public_key()))
        )
        valid_context["upper"].append("c")
        valid_context["cut"].append("c")
        cert = self.issue(valid_context)

        # Re-sign the modified history so rejection isolates local all-active-key
        # admission rather than merely detecting a stale checkpoint signature.
        bad_cert = copy.deepcopy(cert)
        bad_cert["context"]["events"][2]["key"] = "ff" * 32
        bad_cert["history"]["signature"] = self.authority.sign(
            history_payload(bad_cert["context"])
        ).hex()
        self.assertFalse(verify_reference_certificate(bad_cert, self.authority_hex))

        with tempfile.TemporaryDirectory() as tmp:
            cert_path = Path(tmp) / "invalid-unselected-active-key.json"
            anchor_path = Path(tmp) / "anchor.txt"
            cert_path.write_bytes(canonical_json(bad_cert) + b"\n")
            anchor_path.write_text(self.authority_hex + "\n", encoding="ascii")
            proc = subprocess.run(
                [sys.executable, str(ARTIFACT / "verify_reference.py"),
                 str(cert_path), str(anchor_path)],
                check=False, capture_output=True, text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("INVALID", proc.stderr)

    def test_identity_and_small_order_public_keys_are_rejected(self):
        for raw in (bytes([1]) + bytes(31), bytes(32)):
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                decode_public_key(raw.hex())

    def test_valid_generated_public_key_passes_strict_admission(self):
        # RFC 8032, Section 7.1, test vector 1 public key.
        rfc_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        self.assertIsNotNone(decode_public_key(rfc_key))
        encoded = public_key_hex(key("valid-public").public_key())
        self.assertIsNotNone(decode_public_key(encoded))

    def test_bounded_read_accepts_limit_and_rejects_limit_plus_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            exact = Path(tmp) / "exact.bin"
            excess = Path(tmp) / "excess.bin"
            exact.write_bytes(b"x" * 8)
            excess.write_bytes(b"x" * 9)
            self.assertEqual(_bounded_read(exact, 8, "test input"), b"x" * 8)
            with self.assertRaisesRegex(ValueError, "exceeds 8 bytes"):
                _bounded_read(excess, 8, "test input")

    def test_bounded_read_uses_one_handle_and_limit_plus_one_read(self):
        calls: list[int] = []
        opens: list[str] = []

        class ProbeHandle:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self, amount: int) -> bytes:
                calls.append(amount)
                return b"x" * amount

        class ProbePath:
            def open(self, mode: str):
                opens.append(mode)
                return ProbeHandle()

        with self.assertRaisesRegex(ValueError, "exceeds 8 bytes"):
            _bounded_read(ProbePath(), 8, "probe")  # type: ignore[arg-type]
        self.assertEqual(opens, ["rb"])
        self.assertEqual(calls, [9])

    def test_archived_reproduce_runner_refuses_without_starting_campaign(self):
        proc = subprocess.run(
            [sys.executable, str(ARTIFACT / "reproduce.py")],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("exact pre-V3 two-column session-codec source", proc.stderr)
        self.assertIn("no enumeration or ledger reservation was started", proc.stderr)


if __name__ == "__main__":
    unittest.main()
