# Release Automation

CTF Hunter separates ordinary validation, package production, release signing,
and repository publication into distinct GitHub Actions trust boundaries. Every
external action is pinned to an immutable commit SHA. The repository's own
workflow policy check rejects floating action tags, unexpected actions, release
credentials in pull-request jobs, and any APT workflow that attempts to rebuild
the package.

Run the local policy checks with:

```bash
python3 scripts/verify-workflows.py
python3 scripts/check-release-metadata.py
python3 scripts/verify-service-lifecycle.py
scripts/verify-systemd-units.sh
```

## Workflow boundaries

`ci.yml` runs for pull requests and pushes to `develop`, `master`, and release
branches. It has read-only repository access, receives no secrets, creates the
pinned Debian 12 builder, and runs Rust formatting, tests, Clippy, Svelte checks,
frontend tests, the frontend production build, native release compilation,
systemd syntax checks, service-policy checks, and release metadata checks.

`package.yml` runs on release branches and by manual request. It also has only
read access and no secrets. It produces two clean Debian 12 builds, compares the
main and debug packages byte for byte, runs Debian and Kali lifecycle tests,
checks BTF failure behavior, generates unsigned internal checksum/SBOM evidence,
and uploads a short-lived internal artifact. The extended `reprotest` matrix is
available through the manual `run_reprotest` input.

`release.yml` runs only when a version tag is pushed. It rejects a lightweight
tag, a tag that does not match the frozen version, a non-merge release commit,
or a commit not contained in `master`. The unprivileged build job rebuilds twice,
repeats package gates, generates the SPDX SBOM and checksum manifest, and creates
GitHub provenance and SBOM attestations. It has no signing key and cannot create
a Release.

The final job references the protected `release-signing` environment. Only after
approval does it receive signing material and `contents: write`. It verifies the
source tag signature, signs the already-attested checksum manifest, reverifies
all checksums and attestations, and creates a **draft** GitHub Release. Existing
assets are accepted only if byte-identical; the workflow never overwrites them
and never makes the draft public.

`publish-apt.yml` is manual-only. It checks out the automation from `master`,
downloads the already-released `.deb`, verifies its OpenPGP signature, expected
SHA-256, tag-bound GitHub provenance, and then publishes an immutable aptly
snapshot to `testing`. A real APT installation test must pass before the separate
`apt-stable` environment can approve promotion of that exact snapshot. There is
no compiler or package-build command in this workflow.

APT publication remains deliberately fail-closed while
`apt_repository_enabled = false` in `release/metadata.toml`. Phase 10I will add
the final HTTPS repository identity only after hosting, DNS, the archive key,
and the publisher have been provisioned.

## Required GitHub configuration

Protect `.github/workflows/`, `release/`, Debian packaging, and publication
scripts through the checked-in `CODEOWNERS` rules and branch protection on
`master` and `develop`. Dependabot checks the pinned GitHub Actions monthly on
`develop`; a proposed SHA change must also update and pass the reviewed allowlist
in `scripts/verify-workflows.py`.

Create a protected environment named `release-signing` with required reviewers,
self-review disabled, tag deployment restricted to `v*.*.*`, and administrator
bypass disabled where the GitHub plan supports it. Configure:

| Name | Kind | Purpose |
| --- | --- | --- |
| `TAG_GPG_PUBLIC_KEY` | secret | Armored public key used to verify the signed source tag |
| `TAG_GPG_FINGERPRINT` | variable | Full primary fingerprint expected for the tag key |
| `RELEASE_GPG_PRIVATE_KEY` | secret | Armored dedicated release-signing private key export |
| `RELEASE_GPG_PASSPHRASE` | secret | Passphrase for the release-signing key |
| `RELEASE_GPG_FINGERPRINT` | variable | Full primary fingerprint expected for release signatures |

The private key should be a restricted signing subkey dedicated to release
checksums, not the owner's general-purpose primary key. Rotate by adding the new
public key to the documented trust path before using it, never by replacing an
existing tag or release asset.

GitHub artifact attestations require the repository to be public, or a GitHub
plan that supports attestations for private repositories. The production tag
must not be pushed until that prerequisite is satisfied.

## Required APT publisher

The APT jobs intentionally target a single-purpose self-hosted runner carrying
the labels `self-hosted`, `linux`, `x64`, and `ctf-hunter-apt`. Pull requests
never run on it. The runner requires current GitHub Runner software, `gh`, GnuPG,
aptly, Podman, persistent aptly state, and access to the configured publication
endpoint. Archive private keys and storage credentials stay on the publisher;
they are not uploaded to GitHub.

Create protected `apt-testing` and `apt-stable` environments. Both should restrict
deployment to the protected production branch; `apt-stable` must require a human
reviewer, prevent self-review, and disallow bypass. Configure these environment
values:

| Name | Kind | Purpose |
| --- | --- | --- |
| `RELEASE_GPG_PUBLIC_KEY` | secret | Armored public key for the GitHub Release checksum signature |
| `RELEASE_GPG_FINGERPRINT` | variable | Expected checksum-signing fingerprint |
| `APTLY_CONFIG` | variable | Absolute path to the publisher's protected aptly configuration |
| `APTLY_PUBLISH_TARGET` | variable | Aptly endpoint and prefix, for example `s3:ctf-hunter:` |
| `APTLY_GPG_KEY` | variable | Fingerprint of the runner-resident APT archive signing subkey |
| `APTLY_GPG_PASSPHRASE_FILE` | variable | Optional protected runner-local passphrase-file path |
| `APTLY_ORIGIN` | variable | Stable `Origin` value for Release metadata |
| `APTLY_LABEL` | variable | Stable `Label` value for Release metadata |
| `APT_REPOSITORY_URL` | variable | Public HTTPS base URL used by the installation test |

The aptly configuration and state must be shared by the `testing` and `stable`
jobs. The workflow's concurrency lock prevents two promotions from mutating that
state simultaneously. Testing and stable use separate signed distributions, but
both reference the same immutable snapshot name derived from the release tag and
the full package SHA-256.

## First-release operation

1. Require successful `CI` and `Package validation` checks on the release merge.
2. Run the package workflow manually once with `run_reprotest` enabled.
3. Complete the host-authorized systemd and live-capture tests from the release
   policy.
4. Merge the release branch into `master` with an explicit merge commit.
5. Create the signed annotated tag only on that commit and push it once.
6. Review and approve `release-signing`; inspect the resulting draft and its
   checksum signature, SBOM, and provenance.
7. Publish the GitHub draft only after the Phase 10G/10H acceptance gates.
8. Leave APT disabled until Phase 10I provisions the external publisher. Then
   dispatch `Publish APT snapshot` with the immutable tag and package SHA-256,
   validate `testing`, and approve `stable` without rebuilding.
