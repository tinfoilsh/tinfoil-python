# Agent Notes

## TLS pinning reviews

- Treat TLS pinning as an HTTPS-only property. Plain `http://` requests are not attested TLS connections and should not be reported as certificate-pinning bypasses; only report them when a code path that promises HTTPS fails to reject plaintext.
- A real TLS pinning bypass is an HTTPS request that can complete without the peer certificate public key matching the attested TLS public-key fingerprint.
- Review proxy and redirect behavior carefully, but distinguish fail-closed behavior from bypasses.

## EHBP bundle reviews

- EHBP request-body security is bound to the attested HPKE key. The bundled enclave certificate carries domain, HPKE, and attestation-hash bindings; it is not expected to be chain-trusted or to prove the attested TLS public key in EHBP mode.
