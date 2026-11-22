# Security policy

catool creates and handles CA private keys, so reports about its security are welcome.

## Supported versions

Only the latest version of `catool.sh` on the `main` branch is supported. Fixes are
released as a new version of the script; older versions are not patched.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub's private reporting instead: open the **Security** tab of this repository
and choose **Report a vulnerability**. The report is visible only to the maintainer.

Helpful details:

- the version shown in the script banner,
- the operating system, Bash and OpenSSL versions,
- whether a file CA or a YubiKey is used,
- the steps to reproduce the problem and what you expected instead.

Do not include real private keys, passphrases, PINs or management keys in a report.

## What to expect

This is a personal project maintained in spare time. Reports are handled on a
best-effort basis, with no guaranteed response time.

## Scope

In scope: flaws in `catool.sh` itself, for example a secret exposed on the command
line, in a file with loose permissions or in the output, or a certificate issued
with weaker settings than the ones selected.

Out of scope: vulnerabilities in OpenSSL, OpenSC, `yubico-piv-tool`, the YubiKey
firmware or the operating system. Report those to their own maintainers.
