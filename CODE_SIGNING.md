# Code signing policy

Project: **REMOVEDOR DEL WPS MINSEG**, version 3.1.1. Repository: [EAHV09/REMOVEDOR-WPS-MINSEG](https://github.com/EAHV09/REMOVEDOR-WPS-MINSEG).

**Pending application/acceptance. No SignPath-signed release is currently available.** The program's Apache-2.0 license is separate from Authenticode signing. The planned certificate identity is SignPath Foundation, not an institutional MINSEG certificate. Eligibility and signing policy are decided by the Foundation.

## Roles

| Role | Maintainer |
|---|---|
| Author, committer and reviewer | [EAHV09](https://github.com/EAHV09) |
| Release and signing approver | [EAHV09](https://github.com/EAHV09) |
| Security contact | Maintainer through GitHub private vulnerability reporting when enabled; never post sensitive reports publicly |

All maintainers must enable MFA on GitHub and SignPath before signing. External contributions require maintainer review. The signing submitter token cannot approve signing requests. If the Foundation requires an additional reviewer/approver, signing remains disabled until that role is staffed.

## Release process

1. Review the source commit, build scripts, dependencies, licenses and test results.
2. Use GitHub-hosted Windows runners, the pinned SDK, locked NuGet dependencies and actions pinned to commit hashes.
3. Manually request signatures for the two project-owned PowerShell helpers. Verify their certificate and timestamp before embedding them unchanged.
4. Build the EXE from the same commit with those signed helpers. Submit the GitHub artifact for a second manually approved signature.
5. Verify the final product/version, certificate, timestamp and SHA-256. Keep commit, build and signing-request evidence.
6. Perform the Windows/Office/antivirus pilot before calling a release production-ready.

Only manual runs on this repository's main branch may request signing. Signing also requires the `signpath-release` environment and `SIGNPATH_ENABLED=true`. These are not substitutes for Foundation-side origin verification and manual approval. No automatic public release is made by the signing workflow.

Third-party runtime binaries are not re-signed as project-owned code. The local unsigned 3.1.1 EXE is a test candidate, not the artifact to submit through the GitHub connector. Building in CI and applying signatures will produce a different file hash.

## Proposed attribution after acceptance

The following attribution applies only once service is approved and active:

> Free code signing provided by [SignPath.io](https://signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).

## Privacy

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it. Windows trust verification and third-party uninstallers have their own communications. See [PRIVACY.md](PRIVACY.md).

[Foundation conditions](https://signpath.org/terms.html) · [Setup](docs/signpath/PASO-A-PASO.md)
