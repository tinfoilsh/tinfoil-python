"""The collateral entries that a v3 attestation document carries and their strict decoding.

Collateral is untrusted transport. Decoding checks shape only; trust comes
later, from the check that applies to each entry: vendor certificate chains
for hardware endorsements, signed bundles for reference values, and the
caller's own policy for plain config. A decoded entry is therefore never
trusted by itself, and a tampered one can only cause rejection.
"""
