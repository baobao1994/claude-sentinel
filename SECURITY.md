# Security Policy

## Scope

`claude-sentinel` is a local, read-only diagnostic tool. It does not run a
server for other users, does not accept remote input, and does not store
credentials.

## Reporting

Please open a private security advisory (GitHub → Security → Advisories) rather
than a public issue for:

- credential leakage;
- local report/DB permission issues;
- the browser probe accepting non-local or token-less submissions;
- command injection or path traversal in collectors;
- dependency vulnerabilities with a concrete exploit path.

Do not include real OAuth tokens, `sessionKey` values, IP addresses, or full
reports in a public issue.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Design boundaries

- The browser probe binds `127.0.0.1` only and requires a one-time random token.
- The web dashboard binds `127.0.0.1` by default, uses a per-process token and
  same-origin checks for `POST /api/scan`, and emits no CORS headers.
- three.js is vendored locally (MIT) and is not loaded from a CDN.
- Account probing is opt-in; credentials are used in memory only.
- The tool intentionally does not implement fingerprint spoofing, proxy
  rotation, account switching, or telemetry tampering.
