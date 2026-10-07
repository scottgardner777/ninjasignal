# Security Policy

## Scope

`ninjasignal` is a read-only client for public, open data feeds. It uses no
credentials, writes nothing, and contacts only its configured host (default
`https://ninjalabz.io`) over HTTPS. It ships with no runtime dependencies.

## Reporting a vulnerability

Please report security issues **privately** via GitHub Security Advisories
("Report a vulnerability" on the repository's **Security** tab) rather than a
public issue. We aim to acknowledge within a few days.

Helpful to include: the version, a minimal reproduction, and the impact you see.

## Out of scope

- The Ninja Labz backend, feeds infrastructure, or data content (report those
  through the Ninja Labz site, not this repo).
- The proprietary predictive methods behind the feeds — not part of this package.
