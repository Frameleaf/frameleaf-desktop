# Desktop release design

FD-2 restores the existing GitHub-hosted Windows/macOS/Linux checks and starts
installer release automation from current `main`, as selected by the owner.
CodeRabbit remains unchanged. Windows signing is not yet acquired; the owner
authorizes creating a Developer ID Application certificate in Apple Developer.

The initial release workflow accepts a matching version tag and a successful
main-branch factory-runtime artifact run. Existing package verification checks
the factory signature, inventory, epoch, source and native target. Build jobs
only have read access and obtain OS signing credentials from a main-only GitHub
environment. A separate write-enabled job creates a draft prerelease with
checksums only after every selected target succeeds.

Implementation choices: macOS ARM64 and Linux x86-64 by default, Windows x86-64
with the `all` selection, and Linux-only for independent qualification. Signed
factory runtime production is a separate prerequisite; the existing receipt-only
CPU workflow is not a factory upload. The Ed25519 private key stays in Infisical.
There is no unsigned fallback, automatic publication, auto-updater, public tag,
release-version promise or native-host draft-stack integration in this change.

macOS Developer ID identity, notarization and embedded runtime integrity must
pass. Windows verifies app/installer Authenticode signatures against its selected
certificate. Installed-device acceptance remains required before publication.

Scope: new release workflow, small tested version/matrix validation helper,
operator documentation and LF checkout policy for measured source bytes and
existing Windows source-based tests. No application behavior changes.
