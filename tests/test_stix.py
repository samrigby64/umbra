"""Tests for STIX 2.1 export.

The property that matters most is determinism: a customer polling this on a
schedule must get the same STIX id for the same indicator every time, or their
TIP accumulates duplicates of the same wallet — silently, and on their side.
"""


from umbra.db import Database
from umbra.models import Actor, ActorIdentifier, Ioc
from umbra.stix import build_bundle


async def _db(tmp_path):
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'stix.db'}")
    await db.create_all()
    return db


async def _seed(db):
    async with db.session() as s:
        s.add_all([
            Ioc(page_url="http://m.onion/", ioc_type="btc", value="1BvBMSEYstWetqTFn5Au4m4GFg7"),
            Ioc(page_url="http://m.onion/", ioc_type="pgp_fp", value="A" * 40),
            Ioc(page_url="http://m.onion/", ioc_type="onion", value="abc.onion"),
            Ioc(page_url="http://m.onion/", ioc_type="cve", value="CVE-2021-44228"),
            Ioc(page_url="http://m.onion/", ioc_type="email", value="victim@acme.com"),
            Ioc(page_url="http://m.onion/", ioc_type="contact_email", value="v@protonmail.com"),
        ])
        await s.commit()


def _by_type(bundle, stix_type):
    return [o for o in bundle["objects"] if o["type"] == stix_type]


async def test_bundle_shape_and_object_mapping(tmp_path):
    db = await _db(tmp_path)
    await _seed(db)
    bundle = await build_bundle(db)

    assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")
    assert all(o.get("spec_version") == "2.1" for o in bundle["objects"] if o["type"] != "bundle")
    assert len(_by_type(bundle, "identity")) == 1

    patterns = {o["pattern"] for o in _by_type(bundle, "indicator")}
    assert "[cryptocurrency-wallet:value = '1BvBMSEYstWetqTFn5Au4m4GFg7']" in patterns
    assert "[x-pgp-key:fingerprint = '" + "A" * 40 + "']" in patterns
    assert "[domain-name:value = 'abc.onion']" in patterns
    assert "[email-addr:value = 'v@protonmail.com']" in patterns

    # CVEs become vulnerability SDOs, not indicators — they describe a weakness,
    # not something you would match traffic against.
    vulns = _by_type(bundle, "vulnerability")
    assert len(vulns) == 1 and vulns[0]["name"] == "CVE-2021-44228"
    assert vulns[0]["external_references"][0]["external_id"] == "CVE-2021-44228"
    await db.dispose()


async def test_ids_are_deterministic_across_exports(tmp_path):
    """Re-exporting must not create duplicates in the customer's TIP."""
    db = await _db(tmp_path)
    await _seed(db)

    first = await build_bundle(db)
    second = await build_bundle(db)
    assert first == second

    ids = [o["id"] for o in first["objects"]]
    assert len(ids) == len(set(ids))  # no duplicates within a bundle either
    await db.dispose()


async def test_same_value_from_two_pages_is_one_indicator(tmp_path):
    """A wallet seen on twenty pages is one indicator, not twenty."""
    db = await _db(tmp_path)
    async with db.session() as s:
        s.add_all([
            Ioc(page_url=f"http://p{i}.onion/", ioc_type="btc", value="SAME") for i in range(5)
        ])
        await s.commit()

    bundle = await build_bundle(db)
    assert len(_by_type(bundle, "indicator")) == 1
    await db.dispose()


async def test_attribution_only_excludes_victim_data(tmp_path):
    """A feed a customer treats as actor infrastructure must not carry breach
    victims — mislabelling that propagates into their tooling."""
    db = await _db(tmp_path)
    await _seed(db)

    bundle = await build_bundle(db, attribution_only=True)
    values = " ".join(o["pattern"] for o in _by_type(bundle, "indicator"))
    assert "v@protonmail.com" in values      # operator contact: attribution
    assert "victim@acme.com" not in values   # breach victim: not
    assert "abc.onion" not in values         # link graph, not an identifier
    await db.dispose()


async def test_actors_are_linked_to_their_indicators(tmp_path):
    """Without relationships a TIP receives a bag of unrelated atoms and the
    clustering work is thrown away at the boundary."""
    db = await _db(tmp_path)
    async with db.session() as s:
        s.add(Ioc(page_url="http://m.onion/", ioc_type="btc", value="WALLET1"))
        s.add(Actor(id=1, label="btc:WALLET1", page_count=3))
        s.add(ActorIdentifier(actor_id=1, ioc_type="btc", value="WALLET1"))
        await s.commit()

    bundle = await build_bundle(db)
    actors = _by_type(bundle, "threat-actor")
    rels = _by_type(bundle, "relationship")
    assert len(actors) == 1 and "3 page(s)" in actors[0]["description"]
    assert len(rels) == 1
    assert rels[0]["relationship_type"] == "indicates"
    assert rels[0]["target_ref"] == actors[0]["id"]
    assert rels[0]["source_ref"].startswith("indicator--")
    await db.dispose()


async def test_quotes_in_a_value_cannot_break_the_pattern(tmp_path):
    """Extracted values are attacker-controlled text; an unescaped quote would
    produce a syntactically invalid pattern that the customer's parser rejects."""
    db = await _db(tmp_path)
    async with db.session() as s:
        s.add(Ioc(page_url="http://m.onion/", ioc_type="handle", value="o'brien"))
        await s.commit()

    bundle = await build_bundle(db)
    pattern = _by_type(bundle, "indicator")[0]["pattern"]
    assert pattern == "[user-account:account_login = 'o\\'brien']"
    await db.dispose()


async def test_unmapped_types_are_omitted_not_guessed(tmp_path):
    db = await _db(tmp_path)
    async with db.session() as s:
        s.add(Ioc(page_url="http://m.onion/", ioc_type="pgp", value="present"))
        await s.commit()

    bundle = await build_bundle(db)
    assert _by_type(bundle, "indicator") == []
    await db.dispose()


async def test_limit_is_honoured(tmp_path):
    db = await _db(tmp_path)
    async with db.session() as s:
        s.add_all([
            Ioc(page_url="http://m.onion/", ioc_type="btc", value=f"ADDR{i}") for i in range(20)
        ])
        await s.commit()

    bundle = await build_bundle(db, limit=5)
    assert len(_by_type(bundle, "indicator")) == 5
    await db.dispose()
