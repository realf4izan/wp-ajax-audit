# wp-ajax-audit

Find WordPress AJAX and REST handlers missing authorization — the bug class
behind most real WordPress plugin findings.

A `wp_ajax_nopriv_*` handler with no capability or nonce check lets any
visitor call it. A REST route with no `permission_callback` (or with
`__return_true`) is public by default. This tool scans a plugin directory
and lists every handler with a verdict, so the risky ones stand out before
you read a single line of business logic by hand.

## Install

No dependencies. Python 3.8+ only.

```bash
git clone https://github.com/realf4izan/wp-ajax-audit.git
cd wp-ajax-audit
python3 wp_ajax_audit.py /path/to/plugin
```

## Usage

```bash
# Human-readable table (default)
python3 wp_ajax_audit.py /path/to/plugin

# Machine-readable JSON
python3 wp_ajax_audit.py /path/to/plugin --json

# Single file
python3 wp_ajax_audit.py /path/to/plugin/includes/ajax.php
```

Exit code is `1` if any `VULNERABLE` handler is found, `0` otherwise — so
it works in a script or a pre-commit check.

## What it checks

| Handler | What counts as protected |
|---|---|
| `wp_ajax_nopriv_*` | Callback body contains `current_user_can(`, `check_ajax_referer(`, `wp_verify_nonce(`, `check_admin_referer(` or `is_user_logged_in(` |
| `wp_ajax_*` (logged-in) | Same checks — missing checks are flagged `REVIEW`, because the handler is still reachable by low-privilege users |
| `register_rest_route()` | A `permission_callback` that is not `__return_true` and contains a recognizable auth check |

Callbacks given as plain function names, `array( $this, 'method' )`,
`[ $this, 'method' ]`, and closures are all handled. Closures on AJAX
handlers are reported as `REVIEW` (body not inspected).

## Example output

Against the included sample plugin (`samples/vulnerable-plugin/`), which
has one vulnerable nopriv handler, one safe handler, one open REST route
and one protected REST route:

```
$ python3 wp_ajax_audit.py samples/vulnerable-plugin/
Handler                        Type         File:Line                 Verdict     Reason
-----------------------------  -----------  ------------------------  ----------  --------------------------------------------------------
wp_ajax_nopriv_vp_delete_data  ajax-nopriv  vulnerable-plugin.php:11  VULNERABLE  nopriv handler with no capability/nonce check
wp_ajax_vp_save_settings       ajax         vulnerable-plugin.php:19  OK          auth check present: current_user_can, check_ajax_referer
vp/v1 /public-info (GET)       rest         vulnerable-plugin.php:32  VULNERABLE  no permission_callback — route is public
vp/v1 /admin-stats (GET)       rest         vulnerable-plugin.php:44  OK          permission_callback checks: current_user_can

4 handler(s) scanned: 2 VULNERABLE, 0 REVIEW, 2 OK
```

Exit code: `1` (vulnerable handlers found).

## Verdicts

- **VULNERABLE** — no authorization check found. Verify in the lab and
  report if the handler reaches sensitive data or actions.
- **OK** — a recognizable auth check is present in the callback (or in the
  REST `permission_callback`).
- **REVIEW** — the tool could not decide: callback not found, anonymous
  closure, or a logged-in-only handler with no capability check. Read the
  code by hand.

## Limitations

Static analysis only — it reads code, it does not run it.

- A check that exists but is bypassable (wrong capability, nonce checked
  after the action, logic error) is reported `OK`. Always verify a finding
  by hand in a local lab before reporting it.
- Callbacks built dynamically (variable function names, `call_user_func`
  with variables) are reported `REVIEW`.
- Heredoc strings and very unusual formatting can confuse the parser.
- False positives are possible. A `VULNERABLE` verdict is a lead, not a
  confirmed vulnerability.

## License

MIT. See [LICENSE](LICENSE).
