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

`ci.yml` runs for pull requests and pushes to `develop` and `master`. Its fast
policy job always validates release metadata, service policy, systemd units,
workflow pins, and the CI-policy unit tests. Pull requests limited to reviewed
workflow, Renovate, policy-test, and documentation paths stop there. Source,
dependency, build, packaging, and unknown changes fail closed into the complete
Debian 12 native gate. Pushes to protected branches always run the complete gate.
Both jobs have read-only repository access and receive no secrets.

`package.yml` runs only by manual request, avoiding a duplicate of the full
release-candidate package build on every release or hotfix push. It has only read
access and no secrets. It produces two clean Debian 12 builds, compares the
main and debug packages byte for byte, runs Debian and Kali lifecycle tests,
checks BTF failure behavior, generates unsigned internal checksum/SBOM evidence,
and uploads a short-lived internal artifact. The extended `reprotest` matrix is
available through the manual `run_reprotest` input. It stages a filtered source
tree outside the checkout, excludes all generated build state, uses a disk-backed
temporary root, pins both perturbed builds to the already-prepared release-builder
store, and installs `disorderfs` for the file-ordering perturbation.

`release-candidate.yml` runs only when `hotfix/0.1.1` is pushed. The workflow
repeats the complete source gates,
reclaims only their generated Cargo and frontend workspace artifacts, builds
`0.1.1~rc1-1` twice, validates the Debian/Kali lifecycle and BTF
diagnostics, and uploads the exact unsigned RC evidence. Public repositories
also receive GitHub provenance and SBOM attestations. A separate job behind the
`release-candidate` environment may stage those already-validated bytes as the
immutable draft prerelease
`v0.1.1-rc1`; it never publishes the draft or replaces a different existing
asset. The RC tag is also required to resolve directly to the commit that
produced the validated bytes. The staging job creates or verifies that lightweight
RC reference before creating the draft with `--verify-tag`; it does not depend
on deferred automatic tag creation by a draft release. An empty orphaned draft
from an interrupted staging attempt may be adopted only after its tag and target
are rebound to the current validated commit; a draft carrying assets is never
silently retargeted.

`release.yml` runs only when a version tag is pushed. It rejects a lightweight
tag, a tag that does not match the frozen version, a non-merge release commit,
or a commit not contained in `master`. The unprivileged build job rebuilds twice,
reclaims generated source-gate artifacts before the package builds, repeats
package gates, generates the SPDX SBOM and checksum manifest, and creates
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

Protect `.github/workflows/`, `renovate.json`, `release/`, Debian packaging, and
publication scripts through the checked-in `CODEOWNERS` rules and branch
protection on `master` and `develop`. Renovate checks the pinned GitHub Actions
monthly and opens pull requests only against `develop`; a proposed SHA change
must remain on the reviewed action allowlist, use a full commit SHA, remain
consistent across workflows, and pass `scripts/verify-workflows.py`. The verifier
deliberately does not duplicate the old SHA, so a legitimate Renovate update can
validate itself. Renovate never automerges these changes.

The repository configuration is intentionally limited to the `github-actions`
manager, retains full commit-SHA pins and their version comments, waits seven
days after a release, and limits concurrent dependency pull requests to five.
Install the Renovate GitHub App only after this configuration reaches the
default branch and the release branch has also been merged back into `develop`.
Because the configuration already exists on `master`, Renovate can use it
directly instead of proposing a separate onboarding configuration.

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

Create a separate environment named `release-candidate`. Restrict it to the
`hotfix/0.1.1` branch and disable administrator bypass where the repository plan
supports that control. Add a required reviewer when another trusted maintainer is
available; a sole-maintainer repository must not enable a self-review policy that
makes the environment impossible to approve. This environment needs no secrets.
Set the environment variable `CTF_HUNTER_RC_STAGING=enabled`; its absence makes
draft staging fail closed. The job's only write authority is the
repository-scoped token used to stage a draft prerelease.

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

## Hotfix 0.1.1 operation

1. Require a successful `CI` check on the hotfix branch. Source changes still
   execute the complete native gate; workflow- or documentation-only pull
   requests use the policy-only fast path.
2. Run `Package validation` manually once with `run_reprotest` enabled. It is
   deliberately not an automatic required pull-request check because the
   release-candidate workflow repeats the complete isolated package build.
3. Configure the `release-candidate` environment for `hotfix/0.1.1`, push the
   branch, approve the protected staging job, and inspect the resulting RC1 draft.
4. Complete the host-authorized systemd and live-capture tests from the release
   policy.
5. Merge the hotfix branch into `master` with an explicit merge commit.
6. Create the signed annotated tag only on that commit and push it once.
7. Review and approve `release-signing`; inspect the resulting draft and its
   checksum signature, SBOM, and provenance.
8. Publish the GitHub draft only after the Phase 10G/10H acceptance gates.
9. Merge the hotfix branch back into `develop`, then delete it after both merges.
10. Leave APT disabled until Phase 10I provisions the external publisher. Then
   dispatch `Publish APT snapshot` with the immutable tag and package SHA-256,
   validate `testing`, and approve `stable` without rebuilding.
