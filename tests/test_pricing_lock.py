"""Tests for the pricing lock file manager (release_gate.pricing.lock)."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from release_gate.pricing.lock import PricingLock, compute_models_hash, LOCK_VERSION


MODELS = {
    "openai/gpt-4-turbo": {"input_per_1m": 10.0, "output_per_1m": 30.0, "provider": "openai"},
    "anthropic/claude-3-opus": {"input_per_1m": 15.0, "output_per_1m": 75.0, "provider": "anthropic"},
}


def test_write_and_load_roundtrip(tmp_path):
    path = str(tmp_path / "pricing.lock.json")
    payload = PricingLock.write(path, MODELS, source="openrouter")
    assert payload["version"] == LOCK_VERSION
    assert payload["source"] == "openrouter"
    assert "fetched_at" in payload
    loaded = PricingLock.load(path)
    assert loaded["models"] == MODELS


def test_load_missing_returns_none(tmp_path):
    assert PricingLock.load(str(tmp_path / "nope.json")) is None
    assert PricingLock.load(None) is None


def test_hash_detects_tampering(tmp_path):
    path = str(tmp_path / "pricing.lock.json")
    PricingLock.write(path, MODELS, source="static")
    lock = PricingLock.load(path)
    assert PricingLock.is_intact(lock) is True

    # Tamper with a price without updating the hash.
    lock["models"]["openai/gpt-4-turbo"]["input_per_1m"] = 0.01
    assert PricingLock.is_intact(lock) is False


def test_hash_is_stable_regardless_of_key_order():
    a = {"x": {"input_per_1m": 1.0}, "y": {"input_per_1m": 2.0}}
    b = {"y": {"input_per_1m": 2.0}, "x": {"input_per_1m": 1.0}}
    assert compute_models_hash(a) == compute_models_hash(b)


def test_age_days(tmp_path):
    old = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat().replace("+00:00", "Z")
    lock = {"fetched_at": old, "models": MODELS}
    age = PricingLock.age_days(lock)
    assert age is not None and 44 < age < 46


def test_age_days_unknown():
    assert PricingLock.age_days({"models": {}}) is None


def test_get_model_exact_and_prefixed():
    lock = {"models": MODELS}
    assert PricingLock.get_model(lock, "openai/gpt-4-turbo")["input_per_1m"] == 10.0
    # Bare id should match a provider-prefixed key.
    assert PricingLock.get_model(lock, "gpt-4-turbo")["input_per_1m"] == 10.0
    assert PricingLock.get_model(lock, "does-not-exist") is None
