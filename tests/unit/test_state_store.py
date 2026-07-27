from __future__ import annotations

from pathlib import Path

from poisonhound.core.state_store import StateStore


def test_get_or_create_seed_persists_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "state.json"

    seed_a = StateStore(path).get_or_create_seed()
    seed_b = StateStore(path).get_or_create_seed()

    assert seed_a == seed_b
    assert path.is_file()


def test_get_or_create_seed_creates_parent_directories(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dir" / "state.json"

    StateStore(path).get_or_create_seed()

    assert path.is_file()


def test_corrupted_state_file_starts_fresh(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text("not valid json{{{", encoding="utf-8")

    seed = StateStore(path).get_or_create_seed()

    assert isinstance(seed, bytes)
    assert len(seed) == 32


def test_missing_file_returns_empty_dict(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "does-not-exist.json")

    assert store.load() == {}
