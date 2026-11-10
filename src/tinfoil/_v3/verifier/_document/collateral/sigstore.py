"""Sigstore reference-values collateral: release bundles and freshness witnesses."""

from __future__ import annotations

from dataclasses import dataclass

from tinfoil._v3.verifier import _json
from tinfoil._v3.verifier._document.collateral.entry import Entry, unmarshal_data


class MissingMemberError(ValueError):
    """A collateral entry without a member that verification needs."""


@dataclass(frozen=True, slots=True)
class SigstoreRef:
    """A reference-values entry: a Sigstore bundle and the release that it names.

    ``repo`` and ``tag`` are informational; trust comes from verifying
    ``bundle`` against the expected signing identity and ``digest``.
    """

    repo: str
    tag: str
    digest: str
    bundle: _json.JsonValue


@dataclass(frozen=True, slots=True)
class Freshness:
    """A freshness witness: the independently signed bundle that attests that a reference-values artifact was recently
    published."""

    format: str
    bundle: _json.JsonValue


_REF_MEMBERS = ("repo", "tag", "digest", "sigstore_bundle")
_FRESHNESS_MEMBERS = ("sigstore_bundle",)


def decode_sigstore_ref(entry: Entry) -> SigstoreRef:
    data = unmarshal_data(entry, entry.format, _REF_MEMBERS)
    # The tag is an optional hint and the repo is checked by provenance where
    # it matters; the digest and the bundle are what verification needs.
    digest = _json.string(data, "digest")
    if digest == "":
        raise MissingMemberError(f"{entry.format} collateral entry {entry.id!r} is missing digest")
    bundle = _require_bundle(entry, data)
    return SigstoreRef(repo=_json.string(data, "repo"), tag=_json.string(data, "tag"), digest=digest, bundle=bundle)


def decode_freshness(entry: Entry) -> Freshness:
    data = unmarshal_data(entry, entry.format, _FRESHNESS_MEMBERS)
    return Freshness(format=entry.format, bundle=_require_bundle(entry, data))


def _require_bundle(entry: Entry, data: _json.JsonObject) -> _json.JsonValue:
    """Reject an entry whose sigstore_bundle member is missing or null.

    Whether a present bundle verifies is for provenance to judge.
    """
    bundle = _json.raw(data, "sigstore_bundle")
    if bundle is None:
        raise MissingMemberError(f"{entry.format} collateral entry {entry.id!r} is missing sigstore_bundle")
    return bundle
