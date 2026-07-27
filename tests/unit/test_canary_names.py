from __future__ import annotations

import os

from poisonhound.net.canary_names import (
    generate_canary_name,
    generate_canary_names,
    generate_seed,
    to_nbns_name,
)


def test_generate_canary_name_is_deterministic_for_same_seed() -> None:
    seed = b"fixed-seed-for-test"

    first = generate_canary_name("ph-canary", seed, 0)
    second = generate_canary_name("ph-canary", seed, 0)

    assert first == second
    assert first.startswith("ph-canary-")


def test_different_index_produces_different_name() -> None:
    seed = b"fixed-seed-for-test"

    names = generate_canary_names("ph-canary", seed, count=5)

    assert len(set(names)) == 5


def test_different_seed_produces_different_name() -> None:
    name_a = generate_canary_name("ph-canary", b"seed-a", 0)
    name_b = generate_canary_name("ph-canary", b"seed-b", 0)

    assert name_a != name_b


def test_generated_names_do_not_collide_across_many_seeds() -> None:
    names = {generate_canary_name("ph-canary", os.urandom(32), 0) for _ in range(1000)}

    assert len(names) == 1000


def test_generate_seed_returns_32_random_bytes() -> None:
    seed = generate_seed()

    assert isinstance(seed, bytes)
    assert len(seed) == 32
    assert seed != generate_seed()


def test_to_nbns_name_truncates_and_uppercases() -> None:
    long_name = "ph-canary-abcdef123456"

    nbns_name = to_nbns_name(long_name)

    assert nbns_name == "PH-CANARY-ABCDE"
    assert len(nbns_name) == 15
    assert nbns_name == nbns_name.upper()
