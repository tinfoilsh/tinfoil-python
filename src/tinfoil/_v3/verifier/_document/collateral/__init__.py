"""The collateral entries that a v3 attestation document carries and their strict decoding.

Collateral is unendorsed transport: every entry is authenticated by its own
signature chain during verification, so a decoded entry is not trusted and a
tampered one can only cause rejection.
"""
