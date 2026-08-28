"""Adapter self-description for `tinfoil-conformance capabilities`; the suite
uses it to gate which fixtures apply. Same shape across languages
(schemas/v3/capabilities.schema.json)."""

from .run import SCHEMA_VERSION, SUPPORTED_STAGES

SDK_NAME = "tinfoil-python"


def capabilities() -> dict:
    # stages_supported tracks run.SUPPORTED_STAGES so this stays truthful as
    # the verifier slices land. Integration finalizes: all five stages,
    # synthetic_roots all true, freshness_enforced true, live_verify true,
    # channel_binding "tls-spki" (PORTING.md).
    return {
        "schema_version": SCHEMA_VERSION,
        "sdk": SDK_NAME,
        "v3": {
            "supported": True,
            "stages_supported": list(SUPPORTED_STAGES),
            "synthetic_roots": {"amd": False, "intel": False, "sigstore": False},
            "freshness_enforced": False,
            "live_verify": False,
            "channel_binding": "none",
        },
    }
