# Contributing to wp-ajax-audit

Thanks for your interest in contributing! `wp-ajax-audit` is a small, zero-dependency Python tool that audits WordPress plugins and themes for AJAX/REST handlers missing capability and nonce checks. Contributions of any size are welcome — bug reports, documentation fixes, new checks, and test cases.

## Ways to contribute

- **Report a bug:** open an issue with a short description, the command you ran, and the output you expected vs. what you got.
- **Suggest an improvement:** open an issue first so the idea can be discussed before you write code.
- **Submit a fix or feature:** fork the repo, make your change on a branch, and open a pull request.

## Getting started

1. Fork this repository and clone your fork:

   ```bash
   git clone https://github.com/<your-username>/wp-ajax-audit.git
   cd wp-ajax-audit
   ```

2. You need Python 3.9 or later. There are no third-party dependencies.
3. Try the tool against the included sample before changing anything:

   ```bash
   python wp_ajax_audit.py samples/vulnerable-plugin
   ```

## Branch naming

Use a short, descriptive branch name with a prefix:

- `feature/<short-description>` — new functionality
- `fix/<short-description>` — bug fixes
- `docs/<short-description>` — documentation-only changes

Example: `feature/check-rest-nonce`.

## Commit style

- Write commits in the imperative mood, e.g. `Add nonce check for REST routes`.
- Keep each commit focused on one change.
- If a commit addresses an issue, mention it in the commit message, e.g. `Fixes #12`.

## Pull request process

1. Make sure the tool still runs cleanly on the sample plugin:

   ```bash
   python wp_ajax_audit.py samples/vulnerable-plugin
   ```

2. Keep pull requests small and focused — one change per PR where possible.
3. In the PR description, say what changed, why, and how you tested it.
4. Update the README if your change affects usage or output.

## Reporting security findings

This tool is for **authorized testing only**. Never run it against sites you do not own or do not have explicit permission to test, and do not use findings to exploit live sites. If you find a vulnerability in a real plugin or theme, report it responsibly to the vendor (or via a coordinated disclosure platform) — do not open a public issue with exploit details.

## Questions

If you are unsure about anything, open an issue and ask — that is what issues are for. Thanks for helping make WordPress auditing better!
