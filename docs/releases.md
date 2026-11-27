# Releases

Tagged releases publish static Linux binaries (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`), a CycloneDX SBOM and a docs archive. All of them are listed in `SHA256SUMS.txt`, which is signed with cosign keyless; the archives also carry SLSA build provenance. To verify a download and pin it by sha256:

```sh
cosign verify-blob \
  --certificate-identity-regexp '^https://github\.com/pulseengine/zwinger/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --bundle SHA256SUMS.txt.cosign.bundle SHA256SUMS.txt
sha256sum --check --ignore-missing SHA256SUMS.txt
gh attestation verify zwinger-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz --repo pulseengine/zwinger
```
