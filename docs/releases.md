# Releases

Tagged releases publish static Linux binaries (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`), a macOS binary for Apple silicon (`aarch64-apple-darwin`, ad-hoc signed, Seatbelt backend), a CycloneDX SBOM and a docs archive. All of them are listed in `SHA256SUMS.txt`, which is signed with cosign keyless; the archives also carry SLSA build provenance. To verify a download and pin it by sha256:

```sh
cosign verify-blob \
  --certificate-identity-regexp '^https://github\.com/pulseengine/zwinger/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --bundle SHA256SUMS.txt.cosign.bundle SHA256SUMS.txt
sha256sum --check --ignore-missing SHA256SUMS.txt
gh attestation verify zwinger-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz --repo pulseengine/zwinger
```

On macOS use `shasum -a 256 --check --ignore-missing SHA256SUMS.txt`. The binary is signed ad hoc, not with a Developer ID, so a copy downloaded through a browser carries the quarantine attribute and Gatekeeper refuses it. Downloads made with `curl` or `gh release download` carry no quarantine attribute. Verify the sums as above, and then run the binary.
