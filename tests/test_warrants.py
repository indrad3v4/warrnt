"""Tests for the order issuer."""

import os
"""Brick 1 - the order: a signed, TTL-bounded identity."""
from warrnt.models import WarrantSpec
from warrnt.warrants import WarrantIssuer, refresh_state, remaining


def make_issuer(now=None):
    return WarrantIssuer(key=b"unit-test-key", now=now)


def spec(**over):
    base = dict(id="W-1", agent="a", role="R", scope="s", ttl=100.0,
                rules=[])
    base.update(over)
    return WarrantSpec(**base)


def test_signed_warrant_verifies():
    issuer = make_issuer()
    warrant = issuer.issue(spec())
    assert warrant.sig
    assert issuer.signature_ok(warrant) is True


def test_tampering_with_scope_breaks_signature():
    issuer = make_issuer()
    warrant = issuer.issue(spec(scope="read-only"))
    warrant.scope = "read-only + wire 1,000,000 PLN"     # edit after signing
    assert issuer.signature_ok(warrant) is False


def test_tampering_with_a_rule_breaks_signature():
    issuer = make_issuer()
    warrant = issuer.issue(spec())
    warrant.rules = []
    warrant.rules.append(__import__("warrnt.models", fromlist=["Rule"]).Rule(tool="x"))
    assert issuer.signature_ok(warrant) is False


def test_ttl_elapses():
    clock = {"t": 1000.0}
    issuer = make_issuer(now=lambda: clock["t"])
    warrant = issuer.issue(spec(ttl=50.0))
    assert remaining(warrant, clock["t"]) == 50.0
    clock["t"] += 60
    assert remaining(warrant, clock["t"]) == 0.0
    assert refresh_state(warrant, clock["t"]) == "expired"


def test_token_is_bound_to_agent_and_warrant():
    issuer = make_issuer()
    a = issuer.token_for("agent-a", "W-1")
    b = issuer.token_for("agent-a", "W-2")
    c = issuer.token_for("agent-b", "W-1")
    assert a != b and a != c and len(a) == 24
    assert issuer.token_for("agent-a", "W-1") == a      # deterministic


def test_issuer_persists_key_to_file(tmp_path):
    path = tmp_path / "issuer.key"
    first = WarrantIssuer.from_env_or_file(str(path))
    second = WarrantIssuer.from_env_or_file(str(path))
    assert path.exists()
    assert first.key == second.key
    # POSIX file modes do not exist on Windows - chmod is a no-op and st_mode reports 666. The
    # claim under test is "the key is written private where private is a thing".
    if os.name != "nt":
        assert oct(path.stat().st_mode)[-3:] == "600"
