"""Adapter self-description for `tinfoil-conformance capabilities`; the suite
uses it to gate which fixtures apply. Same shape across languages
(schemas/v3/capabilities.schema.json)."""

from .run import SCHEMA_VERSION, SUPPORTED_STAGES

SDK_NAME = "tinfoil-python"


def capabilities() -> dict:
    # All five stages with every synthetic-root seam; the python product
    # client pins TLS, so channel_binding is "tls-spki" (Go parity).
    return {
        "schema_version": SCHEMA_VERSION,
        "sdk": SDK_NAME,
        "v3": {
            "supported": True,
            "stages_supported": list(SUPPORTED_STAGES),
            "synthetic_roots": {"amd": True, "intel": True, "sigstore": True},
            "freshness_enforced": True,
            "live_verify": True,
            "channel_binding": "tls-spki",
        },
    }
