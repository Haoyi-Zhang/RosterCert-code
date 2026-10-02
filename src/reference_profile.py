"""Executable Ed25519 reference profile for causal-roster certificates.

This is a transparent, linear-size baseline.  It authenticates a canonical history
checkpoint, verifies one long-term delegation per selected version, and verifies one
fresh Ed25519 signature per selected ephemeral key.  It deliberately does *not*
implement BGLS aggregation, constant-size registry compression, freshness discovery,
or production governance.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ed25519_points import validate_public_key_bytes
from session import (
    base_payload,
    canonical_json,
    delegation_payload,
    history_payload,
    normalize_context,
    normalize_ephemeral_table,
)

_CERTIFICATE_FIELDS = {
    "type", "context", "history", "ephemeral_table", "delegations", "base",
}
_HISTORY_FIELDS = {"scheme", "signature"}
_DELEGATION_FIELDS = {"scheme", "identity", "event", "long_term_key", "signature"}
_BASE_FIELDS = {"scheme", "signatures"}
_BASE_SIGNATURE_FIELDS = {"identity", "event", "ephemeral_key", "signature"}
_CERTIFICATE_TYPE = "CAUSAL-ROSTER-CERTIFICATE-V1"
_HISTORY_SCHEME = "ED25519-HISTORY-V1"
_DELEGATION_SCHEME = "ED25519-DELEGATION-V1"
_BASE_SCHEME = "ED25519-VECTOR-V1"


def public_key_hex(key: Ed25519PublicKey) -> str:
    """Encode a raw Ed25519 public key as canonical lower-case hexadecimal."""
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _signature_hex(signature: bytes) -> str:
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError("Ed25519 signature must be 64 bytes")
    return signature.hex()


def _decode_hex(value: Any, field: str, size: int) -> bytes:
    if (
        not isinstance(value, str)
        or len(value) != size * 2
        or value != value.lower()
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise ValueError(f"{field} is not canonical {size}-byte hexadecimal")
    return bytes.fromhex(value)


def decode_public_key(value: Any, field: str = "public key") -> Ed25519PublicKey:
    raw = _decode_hex(value, field, 32)
    try:
        validate_public_key_bytes(raw)
    except ValueError as exc:
        raise ValueError(f"{field} is not a valid Ed25519 verification key: {exc}") from exc
    return Ed25519PublicKey.from_public_bytes(raw)


def _verify_signature(public_hex: Any, signature_hex: Any, message: bytes,
                      *, field: str) -> None:
    public = decode_public_key(public_hex, f"{field} public key")
    signature = _decode_hex(signature_hex, f"{field} signature", 64)
    try:
        public.verify(signature, message)
    except InvalidSignature as exc:
        raise ValueError(f"invalid {field} signature") from exc


def _event_map(context: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {event["id"]: event for event in context["events"]}


def _validate_reference_event_keys(context: dict[str, Any]) -> None:
    """Enforce the Ed25519 profile's authenticated-key discipline.

    The generic roster semantics deliberately treat keys as opaque strings.  This
    concrete profile is stricter: every active event must contain a canonical raw
    Ed25519 public key, and the same key bytes may not name two different
    identities.  Reuse by one identity across version events remains valid because
    the signed statements also bind the exact event identifier.
    """
    owner_by_key: dict[str, str] = {}
    for event in context["events"]:
        if not event["active"]:
            continue
        decode_public_key(event["key"], f"event {event['id']} public key")
        previous = owner_by_key.setdefault(event["key"], event["owner"])
        if previous != event["owner"]:
            raise ValueError("one active Ed25519 key cannot represent two identities")


def _validate_role_separation(
    context: dict[str, Any], table: list[list[str]], history_public_key_hex: Any
) -> None:
    """Reject key-byte reuse across the three independently modelled roles."""
    history_public = decode_public_key(history_public_key_hex, "history public key")
    history_key = public_key_hex(history_public)
    long_term_keys = {event["key"] for event in context["events"] if event["active"]}
    ephemeral_keys = {row[2] for row in table}
    for index, ephemeral in enumerate(ephemeral_keys):
        decode_public_key(ephemeral, f"ephemeral public key {index}")
    if long_term_keys & ephemeral_keys:
        raise ValueError("ephemeral keys must be distinct from active long-term keys")
    if history_key in long_term_keys or history_key in ephemeral_keys:
        raise ValueError("history key must be distinct from signer keys")


def issue_reference_certificate(
    context: dict[str, Any],
    history_private_key: Ed25519PrivateKey,
    long_term_private_keys: Mapping[str, Ed25519PrivateKey],
    ephemeral_private_keys: Mapping[str, Ed25519PrivateKey],
) -> dict[str, Any]:
    """Issue a complete certificate for a validated context.

    ``long_term_private_keys`` is keyed by selected event ID, while
    ``ephemeral_private_keys`` is keyed by selected identity.  The function rejects
    a private key whose public key does not equal the corresponding authenticated
    event key.  Callers remain responsible for secure randomness, erasure, and key
    custody; deterministic keys are used only by the packaged example generator.
    """
    if not isinstance(history_private_key, Ed25519PrivateKey):
        raise ValueError("history_private_key must be an Ed25519 private key")
    normalized = normalize_context(context)
    _validate_reference_event_keys(normalized)
    profile = dict(normalized["profile"])
    if set(long_term_private_keys) != set(profile.values()):
        raise ValueError("long-term private-key set does not match selected events")
    if set(ephemeral_private_keys) != set(profile):
        raise ValueError("ephemeral private-key set does not match selected identities")

    events = _event_map(normalized)
    table: list[list[str]] = []
    for identity, event in normalized["profile"]:
        long_term_private = long_term_private_keys[event]
        ephemeral_private = ephemeral_private_keys[identity]
        if not isinstance(long_term_private, Ed25519PrivateKey):
            raise ValueError("long-term key is not Ed25519")
        if not isinstance(ephemeral_private, Ed25519PrivateKey):
            raise ValueError("ephemeral key is not Ed25519")
        expected_long_term = events[event]["key"]
        if public_key_hex(long_term_private.public_key()) != expected_long_term:
            raise ValueError("long-term private key does not match authenticated event")
        table.append([identity, event, public_key_hex(ephemeral_private.public_key())])
    table = normalize_ephemeral_table(normalized, table)
    authority_hex = public_key_hex(history_private_key.public_key())
    _validate_role_separation(normalized, table, authority_hex)

    history = {
        "scheme": _HISTORY_SCHEME,
        "signature": _signature_hex(
            history_private_key.sign(history_payload(normalized))
        ),
    }

    delegations: list[dict[str, str]] = []
    for identity, event in normalized["profile"]:
        private = long_term_private_keys[event]
        delegations.append({
            "scheme": _DELEGATION_SCHEME,
            "identity": identity,
            "event": event,
            "long_term_key": events[event]["key"],
            "signature": _signature_hex(
                private.sign(delegation_payload(normalized, table, identity))
            ),
        })

    common = base_payload(normalized, table)
    signatures: list[dict[str, str]] = []
    table_map = {row[0]: (row[1], row[2]) for row in table}
    for identity, event in normalized["profile"]:
        ephemeral_key = table_map[identity][1]
        signatures.append({
            "identity": identity,
            "event": event,
            "ephemeral_key": ephemeral_key,
            "signature": _signature_hex(ephemeral_private_keys[identity].sign(common)),
        })

    certificate: dict[str, Any] = {
        "type": _CERTIFICATE_TYPE,
        "context": normalized,
        "history": history,
        "ephemeral_table": table,
        "delegations": delegations,
        "base": {
            "scheme": _BASE_SCHEME,
            "signatures": signatures,
        },
    }
    # Internal round trip catches accidental issuer/verifier schema drift.
    if not verify_reference_certificate(certificate, authority_hex):
        raise RuntimeError("issued reference certificate failed self-verification")
    return certificate


def _normalize_certificate(certificate: Any) -> tuple[
    dict[str, Any], list[list[str]], list[dict[str, str]], list[dict[str, str]]
]:
    if not isinstance(certificate, dict) or set(certificate) != _CERTIFICATE_FIELDS:
        raise ValueError("certificate fields do not match schema")
    if certificate["type"] != _CERTIFICATE_TYPE:
        raise ValueError("unknown certificate type")

    context = normalize_context(certificate["context"])
    _validate_reference_event_keys(context)
    if certificate["context"] != context:
        raise ValueError("certificate context is not in canonical order")
    table = normalize_ephemeral_table(context, certificate["ephemeral_table"])
    if certificate["ephemeral_table"] != table:
        raise ValueError("ephemeral table is not in canonical order")

    history = certificate["history"]
    if not isinstance(history, dict) or set(history) != _HISTORY_FIELDS:
        raise ValueError("history object fields do not match schema")
    if history["scheme"] != _HISTORY_SCHEME:
        raise ValueError("unsupported history signature scheme")

    profile = context["profile"]
    events = _event_map(context)
    table_map = {row[0]: (row[1], row[2]) for row in table}

    delegations = certificate["delegations"]
    if not isinstance(delegations, list) or len(delegations) != len(profile):
        raise ValueError("delegation count does not match profile")
    expected_delegations: list[dict[str, str]] = []
    for row in delegations:
        if not isinstance(row, dict) or set(row) != _DELEGATION_FIELDS:
            raise ValueError("delegation fields do not match schema")
        for field in _DELEGATION_FIELDS:
            if not isinstance(row[field], str):
                raise ValueError("delegation values must be strings")
        if row["scheme"] != _DELEGATION_SCHEME:
            raise ValueError("unsupported delegation signature scheme")
        expected_delegations.append(row)
    if expected_delegations != sorted(expected_delegations, key=lambda r: r["identity"]):
        raise ValueError("delegations are not in canonical identity order")
    if [r["identity"] for r in expected_delegations] != [r[0] for r in profile]:
        raise ValueError("delegations do not match exact selected identities")
    for row in expected_delegations:
        identity = row["identity"]
        event, _ephemeral = table_map[identity]
        if row["event"] != event or dict(profile)[identity] != event:
            raise ValueError("delegation names the wrong version event")
        if row["long_term_key"] != events[event]["key"]:
            raise ValueError("delegation key differs from authenticated event key")
        decode_public_key(row["long_term_key"], "long-term public key")
        _decode_hex(row["signature"], "delegation signature", 64)

    base = certificate["base"]
    if not isinstance(base, dict) or set(base) != _BASE_FIELDS:
        raise ValueError("base object fields do not match schema")
    if base["scheme"] != _BASE_SCHEME:
        raise ValueError("unsupported base signature scheme")
    signatures = base["signatures"]
    if not isinstance(signatures, list) or len(signatures) != len(profile):
        raise ValueError("base-signature count does not match profile")
    expected_signatures: list[dict[str, str]] = []
    for row in signatures:
        if not isinstance(row, dict) or set(row) != _BASE_SIGNATURE_FIELDS:
            raise ValueError("base-signature fields do not match schema")
        for field in _BASE_SIGNATURE_FIELDS:
            if not isinstance(row[field], str):
                raise ValueError("base-signature values must be strings")
        expected_signatures.append(row)
    if expected_signatures != sorted(expected_signatures, key=lambda r: r["identity"]):
        raise ValueError("base signatures are not in canonical identity order")
    if [r["identity"] for r in expected_signatures] != [r[0] for r in profile]:
        raise ValueError("base signatures do not match exact selected identities")
    for row in expected_signatures:
        event, ephemeral = table_map[row["identity"]]
        if row["event"] != event or row["ephemeral_key"] != ephemeral:
            raise ValueError("base signature differs from the frozen ephemeral table")
        decode_public_key(row["ephemeral_key"], "ephemeral public key")
        _decode_hex(row["signature"], "base signature", 64)

    return context, table, expected_delegations, expected_signatures


def verify_reference_certificate(certificate: Any, history_public_key_hex: Any) -> bool:
    """Return ``True`` iff every semantic and Ed25519 check succeeds."""
    try:
        context, table, delegations, signatures = _normalize_certificate(certificate)
        _validate_role_separation(context, table, history_public_key_hex)
        _verify_signature(
            history_public_key_hex,
            certificate["history"]["signature"],
            history_payload(context),
            field="history",
        )
        for row in delegations:
            _verify_signature(
                row["long_term_key"],
                row["signature"],
                delegation_payload(context, table, row["identity"]),
                field=f"delegation for {row['identity']}",
            )
        common = base_payload(context, table)
        for row in signatures:
            _verify_signature(
                row["ephemeral_key"],
                row["signature"],
                common,
                field=f"base authorization for {row['identity']}",
            )
        return True
    except (ValueError, KeyError, TypeError, InvalidSignature, RecursionError):
        return False


def certificate_bytes(certificate: Any, history_public_key_hex: Any) -> bytes:
    """Serialize a verified snapshot using the reference canonical JSON codec.

    The defensive copy is taken *before* verification so a mutable or custom mapping
    cannot change between validation and serialization.  The wire-level CLI performs
    a separate byte-for-byte comparison against this encoding.
    """
    snapshot = deepcopy(certificate)
    if not verify_reference_certificate(snapshot, history_public_key_hex):
        raise ValueError("refusing to serialize an invalid certificate")
    return canonical_json(snapshot) + b"\n"
