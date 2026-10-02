"""Canonical statements for the session-separated causal-roster compiler.

This module validates the finite roster semantics and constructs the exact bytes
bound by the history checkpoint, long-term delegations, and one-session base
signatures.  It intentionally contains no cryptographic primitive; the executable
Ed25519 reference profile is implemented in :mod:`reference_profile`.
"""
from __future__ import annotations

import json
from typing import Any

from roster import Roster
from wire_profile import (
    MAX_IDENTIFIER,
    MAX_KEY_TEXT,
    MAX_MESSAGE,
    ascii_identifier,
    canonical_json,
    scalar_text,
)

_CONTEXT_FIELDS = {
    "domain", "mode", "application", "session", "message", "namespace",
    "events", "lower", "upper", "cut", "profile",
}
_MODES = {"HIST", "FRESH", "ROBUST"}


def _unique_names(value: Any, field: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a bounded nonempty-string list")
    for index, item in enumerate(value):
        ascii_identifier(item, f"{field}[{index}]", limit=MAX_IDENTIFIER)
    if len(value) != len(set(value)):
        raise ValueError(f"{field} contains duplicates")
    return value


def normalize_context(context: dict[str, Any]) -> dict[str, Any]:
    """Validate one exact semantic context and return its canonical object."""
    if not isinstance(context, dict) or set(context) != _CONTEXT_FIELDS:
        raise ValueError("session context fields do not match schema")
    for field in ("domain", "application", "session", "namespace"):
        ascii_identifier(context[field], field, limit=MAX_IDENTIFIER)
    scalar_text(context["message"], "message", allow_empty=True, limit=MAX_MESSAGE)
    mode = context["mode"]
    if mode not in _MODES:
        raise ValueError("unknown temporal mode")

    model = Roster(context["events"])
    lower = _unique_names(context["lower"], "lower")
    upper = _unique_names(context["upper"], "upper")
    lo = model.mask(lower)
    hi = model.mask(upper)
    model.bounds(lo, hi)

    raw_profile = context["profile"]
    if not isinstance(raw_profile, list) or not raw_profile:
        raise ValueError("profile must be a nonempty list of identity/event pairs")
    for index, row in enumerate(raw_profile):
        if not isinstance(row, list) or len(row) != 2:
            raise ValueError("profile must be a nonempty list of identity/event pairs")
        ascii_identifier(row[0], f"profile[{index}] identity", limit=MAX_IDENTIFIER)
        ascii_identifier(row[1], f"profile[{index}] event", limit=MAX_IDENTIFIER)
    identities = [row[0] for row in raw_profile]
    events = [row[1] for row in raw_profile]
    if len(identities) != len(set(identities)):
        raise ValueError("duplicate profile identity")
    if len(events) != len(set(events)):
        raise ValueError("one version event cannot represent two identities")
    profile = dict(raw_profile)

    cut = context["cut"]
    if mode == "HIST":
        cut_names = _unique_names(cut, "cut")
        cmask = model.mask(cut_names)
        if not model.ideal(cmask) or lo & ~cmask or cmask & ~hi:
            raise ValueError("historical cut is outside the ideal interval")
        if not model.authorized(cmask, profile):
            raise ValueError("profile is not current at the historical cut")
        normalized_cut: list[str] | None = sorted(cut_names)
    elif mode == "FRESH":
        cut_names = _unique_names(cut, "cut")
        if model.mask(cut_names) != hi:
            raise ValueError("fresh mode must name the upper cut")
        if not model.authorized(hi, profile):
            raise ValueError("profile is not current at the upper cut")
        normalized_cut = sorted(cut_names)
    else:
        if cut is not None:
            raise ValueError("robust mode uses a typed null cut")
        if not model.universal(lo, hi, profile):
            raise ValueError("profile is not authorized throughout the interval")
        normalized_cut = None

    normalized_events = sorted(
        (dict(e, parents=sorted(e["parents"])) for e in context["events"]),
        key=lambda e: e["id"],
    )
    return {
        "domain": context["domain"],
        "mode": mode,
        "application": context["application"],
        "session": context["session"],
        "message": context["message"],
        "namespace": context["namespace"],
        "events": normalized_events,
        "lower": sorted(lower),
        "upper": sorted(upper),
        "cut": normalized_cut,
        "profile": sorted(raw_profile),
    }


def history_payload(context: dict[str, Any]) -> bytes:
    """Bytes authenticated by the reference history authority.

    The authority signs the protocol domain, namespace, complete event DAG, and
    declared view bounds.  The application/session/message and selected profile remain bound by
    the session statement and delegations, not by the history authority.
    """
    normalized = normalize_context(context)
    return canonical_json({
        "type": "CAUSAL-ROSTER-HISTORY-V1",
        "domain": normalized["domain"],
        "namespace": normalized["namespace"],
        "events": normalized["events"],
        "lower": normalized["lower"],
        "upper": normalized["upper"],
    })


def normalize_ephemeral_table(context: dict[str, Any], table: Any) -> list[list[str]]:
    """Require one identity/version/key triple for every selected profile entry."""
    normalized = normalize_context(context)
    if not isinstance(table, list):
        raise ValueError("ephemeral table must contain identity/event/key triples")
    for index, row in enumerate(table):
        if not isinstance(row, list) or len(row) != 3:
            raise ValueError("ephemeral table must contain identity/event/key triples")
        ascii_identifier(row[0], f"ephemeral_table[{index}] identity", limit=MAX_IDENTIFIER)
        ascii_identifier(row[1], f"ephemeral_table[{index}] event", limit=MAX_IDENTIFIER)
        scalar_text(row[2], f"ephemeral_table[{index}] key", limit=MAX_KEY_TEXT)
    identities = [row[0] for row in table]
    events = [row[1] for row in table]
    keys = [row[2] for row in table]
    expected = normalized["profile"]
    if len(identities) != len(set(identities)):
        raise ValueError("duplicate ephemeral-table identity")
    if sorted([row[:2] for row in table]) != expected:
        raise ValueError("ephemeral table does not match the exact signer profile")
    if len(events) != len(set(events)):
        raise ValueError("duplicate ephemeral-table event")
    if len(keys) != len(set(keys)):
        raise ValueError("ephemeral public keys must be session-unique")
    return sorted(table)


def session_statement(context: dict[str, Any], table: Any) -> bytes:
    """Bytes jointly fixed before delegations and base signing begin."""
    normalized = normalize_context(context)
    ephemerals = normalize_ephemeral_table(context, table)
    return canonical_json({
        "type": "CAUSAL-ROSTER-SESSION-V3",
        "context": normalized,
        "ephemeral_table": ephemerals,
    })


def delegation_payload(context: dict[str, Any], table: Any, identity: str) -> bytes:
    """Exact bytes signed by the selected long-term version key."""
    normalized = normalize_context(context)
    ephemerals = normalize_ephemeral_table(context, table)
    profile = dict(normalized["profile"])
    table_map = {row[0]: (row[1], row[2]) for row in ephemerals}
    if identity not in profile or identity not in table_map:
        raise ValueError("identity is not selected")
    event, ephemeral_key = table_map[identity]
    if event != profile[identity]:
        raise ValueError("ephemeral table names the wrong version event")
    return canonical_json({
        "type": "CAUSAL-ROSTER-DELEGATION-V3",
        "session_statement": json.loads(session_statement(context, table)),
        "identity": identity,
        "event": event,
        "ephemeral_key": ephemeral_key,
    })


def base_payload(context: dict[str, Any], table: Any) -> bytes:
    """Exact common message supplied to every one-session base signer."""
    normalized = normalize_context(context)
    ephemerals = normalize_ephemeral_table(context, table)
    return canonical_json({
        "type": "CAUSAL-ROSTER-BASE-V3",
        "session_statement": json.loads(session_statement(context, table)),
        "selected_profile": normalized["profile"],
        "ephemeral_table": ephemerals,
    })


def verify_symbolic_session(
    context: dict[str, Any],
    table: Any,
    issued_delegations: dict[str, bytes],
    issued_base_authorizations: dict[str, bytes],
) -> bool:
    """Equality-only model of the two authorization layers.

    This helper catches omitted or inconsistently serialized fields.  It is not
    evidence of a signature or unforgeability; use ``reference_profile.py`` for
    executable signature verification.
    """
    try:
        normalized = normalize_context(context)
        selected = [row[0] for row in normalized["profile"]]
        if set(issued_delegations) != set(selected):
            return False
        if set(issued_base_authorizations) != set(selected):
            return False
        common = base_payload(context, table)
        return all(
            issued_delegations[identity]
            == delegation_payload(context, table, identity)
            and issued_base_authorizations[identity] == common
            for identity in selected
        )
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return False
