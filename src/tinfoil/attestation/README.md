# verifier-python

Python port of Google's Golang implementation of AMD SEV-SNP verification logic for remote attestation.

This current implementation focuses on Genoa processors and on report signed using a VCEK key.

Support for other family of processor and keys will come later.

## Run the test

```
python test_attestation.py
```
## Wish list

- Caching for certificates
- Check against an external AMD root of trust
- Only use one x509 library
- Support more architectures than Genoa
- Support revocation lists
- Improve error handling