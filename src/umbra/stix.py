"""STIX 2.1 export — hand the intelligence to the tools customers already run.

Enterprise CTI teams do not want another dashboard; they want indicators inside
MISP, OpenCTI, or whatever TIP they already operate. Exporting a proprietary JSON
shape means every customer writes glue before they get any value, which is where
evaluations stall. STIX is the format those tools speak natively.

**Identifiers are deterministic.** STIX object IDs here are UUIDv5 derived from
the object's value under the standard STIX namespace, so exporting the same
indicator twice produces the same ID both times. With random IDs, every scheduled
pull would land as a fresh object and a customer's TIP would fill with duplicates
of the same wallet — the failure is silent, cumulative, and lands on them rather
than us.

**On custom object types.** STIX 2.1 has no core observable for a cryptocurrency
wallet or a PGP key, which are two of the most valuable things this system
extracts. Rather than drop them or force them into a type that means something
else, they are emitted as the custom types OpenCTI and MISP already recognise.
That is a deliberate trade of strict spec purity for actually landing in the
tools people use; the mapping is documented in :data:`PATTERN_BUILDERS`.
"""

from __future__ import annotations

import datetime as dt
import uuid

import sqlalchemy as sa

from .db import Database
from .models import Actor, ActorIdentifier, Ioc

# RFC 4122 namespace defined by the STIX 2.1 spec for deterministic SCO ids.
STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

PRODUCER_NAME = "Umbra"

# ioc_type -> (STIX pattern template, indicator_type label)
#
# domain-name, email-addr and user-account are core STIX 2.1 observables.
# cryptocurrency-wallet and x-pgp-key are not: no core equivalent exists, and
# these are the identifiers that actually link dark-web actors, so they are
# emitted using the names the major TIPs already understand.
PATTERN_BUILDERS: dict[str, tuple[str, str]] = {
    "onion": ("[domain-name:value = '{value}']", "anonymous-service"),
    "email": ("[email-addr:value = '{value}']", "compromised"),
    "contact_email": ("[email-addr:value = '{value}']", "attribution"),
    "jabber": ("[email-addr:value = '{value}']", "attribution"),
    "handle": ("[user-account:account_login = '{value}']", "attribution"),
    "btc": ("[cryptocurrency-wallet:value = '{value}']", "attribution"),
    "eth": ("[cryptocurrency-wallet:value = '{value}']", "attribution"),
    "xmr": ("[cryptocurrency-wallet:value = '{value}']", "attribution"),
    "pgp_fp": ("[x-pgp-key:fingerprint = '{value}']", "attribution"),
}

# Types that describe *who is selling* rather than who was breached. Exported
# with attribution semantics; victim data (plain `email`) deliberately is not,
# because labelling a breach victim as actor infrastructure is a mistake that
# propagates into the customer's own tooling and is hard to walk back.
ATTRIBUTION_TYPES = ("btc", "eth", "xmr", "pgp_fp", "contact_email", "jabber", "handle")


def _ts(value: dt.datetime | None) -> str:
    moment = value or dt.datetime.now(dt.timezone.utc)
    if moment.tzinfo is None:  # SQLite drops tzinfo on round-trip
        moment = moment.replace(tzinfo=dt.timezone.utc)
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _id(stix_type: str, seed: str) -> str:
    return f"{stix_type}--{uuid.uuid5(STIX_NAMESPACE, seed)}"


def _escape(value: str) -> str:
    """STIX patterns are single-quoted; a stray quote would break the pattern."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _identity() -> dict:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": _id("identity", f"producer:{PRODUCER_NAME}"),
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "name": PRODUCER_NAME,
        "identity_class": "system",
        "description": "Dark-web collection and enrichment platform",
    }


def _indicator(ioc: Ioc, created_by: str) -> dict | None:
    builder = PATTERN_BUILDERS.get(ioc.ioc_type)
    if builder is None:
        return None
    template, label = builder
    pattern = template.format(value=_escape(ioc.value))
    created = _ts(ioc.created_at)
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _id("indicator", f"{ioc.ioc_type}:{ioc.value}"),
        "created_by_ref": created_by,
        "created": created,
        "modified": created,
        "name": f"{ioc.ioc_type}: {ioc.value[:80]}",
        "description": f"Observed on {ioc.page_url}" if ioc.page_url else None,
        "indicator_types": [label],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": created,
        "labels": [f"umbra:{ioc.ioc_type}"],
    }


def _vulnerability(value: str, created_by: str, created: str) -> dict:
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": _id("vulnerability", f"cve:{value.upper()}"),
        "created_by_ref": created_by,
        "created": created,
        "modified": created,
        "name": value.upper(),
        "external_references": [{"source_name": "cve", "external_id": value.upper()}],
    }


def _threat_actor(actor: Actor, created_by: str, identifier_count: int) -> dict:
    created = _ts(actor.created_at)
    return {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": _id("threat-actor", f"actor:{actor.label}"),
        "created_by_ref": created_by,
        "created": created,
        "modified": created,
        "name": actor.label or f"actor-{actor.id}",
        "description": (
            f"Cluster of {identifier_count} reused identifier(s) "
            f"observed across {actor.page_count or 0} page(s). "
            "Inferred co-occurrence cluster, not verified identity or evidence of criminal conduct. "
            "Analyst link reviews are available in Umbra; they do not establish attribution."
        ),
        "threat_actor_types": ["unknown"],
        "labels": ["umbra:resolved-cluster"],
    }


def _relationship(source: str, target: str, kind: str, created: str, created_by: str) -> dict:
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": _id("relationship", f"{kind}:{source}:{target}"),
        "created_by_ref": created_by,
        "created": created,
        "modified": created,
        "relationship_type": kind,
        "source_ref": source,
        "target_ref": target,
    }


async def build_bundle(
    db: Database,
    ioc_type: str | None = None,
    attribution_only: bool = False,
    limit: int = 10_000,
) -> dict:
    """Build a STIX 2.1 bundle of indicators, actors and their relationships."""
    identity = _identity()
    created_by = identity["id"]
    objects: list[dict] = [identity]
    seen: set[str] = {identity["id"]}

    def add(obj: dict | None) -> str | None:
        if obj is None or obj["id"] in seen:
            return obj["id"] if obj else None
        seen.add(obj["id"])
        objects.append({k: v for k, v in obj.items() if v is not None})
        return obj["id"]

    async with db.session() as session:
        stmt = sa.select(Ioc)
        if ioc_type:
            stmt = stmt.where(Ioc.ioc_type == ioc_type)
        elif attribution_only:
            stmt = stmt.where(Ioc.ioc_type.in_(ATTRIBUTION_TYPES))
        iocs = (await session.execute(stmt.limit(limit))).scalars().all()

        actors = (await session.execute(sa.select(Actor))).scalars().all()
        identifiers = (await session.execute(sa.select(ActorIdentifier))).scalars().all()

    indicator_ids: dict[tuple[str, str], str] = {}
    for ioc in iocs:
        if ioc.ioc_type == "cve":
            add(_vulnerability(ioc.value, created_by, _ts(ioc.created_at)))
            continue
        obj = _indicator(ioc, created_by)
        if obj is None:
            continue  # unmapped type: better omitted than mis-typed
        add(obj)
        indicator_ids[(ioc.ioc_type, ioc.value)] = obj["id"]

    # Link each actor to the indicators that resolved it, so a TIP can pivot from
    # a wallet to the cluster instead of receiving a bag of unrelated atoms.
    by_actor: dict[int, list[ActorIdentifier]] = {}
    for identifier in identifiers:
        by_actor.setdefault(identifier.actor_id, []).append(identifier)

    for actor in actors:
        owned = by_actor.get(actor.id, [])
        actor_obj = _threat_actor(actor, created_by, len(owned))
        actor_id = add(actor_obj)
        for identifier in owned:
            indicator_id = indicator_ids.get((identifier.ioc_type, identifier.value))
            if indicator_id:
                add(_relationship(
                    indicator_id, actor_id, "indicates", actor_obj["created"], created_by
                ))

    return {
        "type": "bundle",
        # The bundle itself is a transient container, so its id is derived from
        # its contents: the same export twice is byte-identical, which makes it
        # cacheable and diffable on the customer's side.
        "id": _id("bundle", ";".join(sorted(seen))),
        "objects": objects,
    }
