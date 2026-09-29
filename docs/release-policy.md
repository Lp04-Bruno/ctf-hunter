# Release Policy

This document defines the release contract for CTF Hunter `0.1.0`. Changes to this
contract require review on the active release branch and must pass
`python3 scripts/check-release-metadata.py`.

## Release identity

- Product: CTF Hunter
- Upstream version: `0.1.0`
- Initial Debian version: `0.1.0-1`
- Debian release-candidate form: `0.1.0~rc1-1`
- Architecture: `amd64`
- Desktop identifier: `dev.ctfhunter.desktop`
- Debian package and installed application name: `ctf-hunter`
- Executables: `ctf-hunter`, `ctf-hunterd`, `ctf-hunterctl`, and
  `ctf-hunter-capture`
- Repository and homepage: <https://github.com/Lp04-Bruno/ctf-hunter>
- Bug reports: <https://github.com/Lp04-Bruno/ctf-hunter/issues>
- Maintainer: Lp04-Bruno
  <88251364+lp04-Bruno@users.noreply.github.com>
- License: MIT or Apache-2.0, at the recipient's option
- Copyright: 2026 Lp04-Bruno

The initial public distribution channel is GitHub Releases. A signed APT repository
is deliberately deferred until its domain, hosting, archive-signing key, rollback
retention, and protected publication environment have been provisioned. Deferring
APT publication does not change the package name or versioning scheme.

## Release freeze

The `release/0.1.0` branch is cut from the completed `develop` branch. It accepts only:

- release metadata and packaging;
- build, installation, upgrade, removal, and publication automation;
- documentation needed to operate or verify the release;
- fixes for defects that block a release gate.

New product features continue on feature branches based on `develop` and must not be
merged into `release/0.1.0`. Release fixes are merged back into `develop` when the
release branch closes.

## Supported platform contract

Release binaries are built on Debian 12 Bookworm for `amd64`, never on Kali Rolling.
The package is validated on Debian 12 and current Kali Linux before publication. The
desktop runtime uses GTK 3 and WebKitGTK 4.1.

Terminal capture additionally requires a Linux kernel that exposes compatible BTF,
the required fentry targets, and the `CAP_BPF` and `CAP_PERFMON` capability model.
Unsupported capture prerequisites must produce an actionable diagnostic; they must
not prevent file collection, manual analysis, or access to stored findings.

Package configuration creates the `ctf-hunter` system group and starts the
privileged system helper without selecting a desktop account. The packaged GUI
starts its own unprivileged user daemon when required. Terminal capture remains a
one-time, explicitly authorized opt-in: the fixed-purpose setup helper may add
only the account identified by polkit, and a new login session activates that
membership. Maintainer scripts never infer `$SUDO_USER` or edit a user's groups.

The installed package must not require Rust, Cargo, a nightly toolchain, Node.js, npm,
kernel headers, or a compiler. Runtime shared-library dependencies are derived from
the final binaries during Debian packaging.

## Versioning contract

Application releases use semantic versions. Debian revisions are independent package
revisions appended after a hyphen. Debian prereleases use a tilde so that APT orders
them before the final release:

```text
0.1.0~rc1-1 < 0.1.0-1 < 0.1.0-2 < 0.1.1-1
```

The workspace, Tauri configuration, npm package metadata, npm lockfile, release
metadata, and Debian changelog must agree before a package is built. Published tags
and release artifacts are immutable. A post-release correction receives a new patch
version or Debian revision; an existing tag is never moved.

## Database and rollback contract

Version `0.1.0` supports database schema generation 4. The daemon intentionally
refuses to open a database whose schema is newer than it supports.

Binary package downgrade is supported only while the old and new packages use the
same database schema generation. Before a later release adds a migration, that release
must introduce and test a pre-migration backup/restore mechanism, an export/import
path, or an explicitly documented compatibility window.

Package removal and purge never delete databases, sessions, findings, configuration,
or other data below a user's home directory. In particular,
`~/.local/share/ctf-hunter` remains owner-controlled. Package-owned runtime files
below `/run` may be removed safely.

## Git Flow release contract

The final release sequence is:

1. Merge `release/0.1.0` into `master` with an explicit merge commit.
2. Create signed annotated tag `v0.1.0` on that merge commit.
3. Build the immutable release from that tag.
4. Merge `release/0.1.0` back into `develop` with an explicit merge commit.
5. Delete the release branch only after both merges succeed.

The tag signing identity is Lp04-Bruno
<88251364+lp04-Bruno@users.noreply.github.com>. A signing key must be configured
before the tag is created. Private signing material is never stored in the repository,
workflow artifacts, or local project notes.
