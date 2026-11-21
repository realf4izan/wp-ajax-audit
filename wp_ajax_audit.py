#!/usr/bin/env python3
"""
wp-ajax-audit — find WordPress AJAX and REST handlers missing authorization.

Missing-authorization AJAX/REST handlers are the most common bug class in
real WordPress plugin findings: a handler registered for unauthenticated
users (wp_ajax_nopriv_*) or a REST route with no permission_callback lets
any visitor call privileged code.

Usage:
    python3 wp_ajax_audit.py /path/to/plugin
    python3 wp_ajax_audit.py /path/to/plugin --json

Exit code 1 if any VULNERABLE handler is found, 0 otherwise.
Standard library only. No dependencies.
"""

import argparse
import json
import re
import sys
from pathlib import Path

AUTH_CHECKS = (
    "current_user_can(",
    "check_ajax_referer(",
    "wp_verify_nonce(",
    "check_admin_referer(",
    "is_user_logged_in(",
)

# ---------------------------------------------------------------------------
# PHP source handling (comment stripping that preserves line numbers)
# ---------------------------------------------------------------------------

def strip_comments(code):
    """Replace PHP comments with spaces, keeping newlines so line numbers
    stay exact. Strings are respected, so // inside a URL is not stripped."""
    out = list(code)
    i = 0
    n = len(code)
    while i < n:
        c = code[i]
        if c == "'" or c == '"':
            quote = c
            i += 1
            while i < n:
                if code[i] == "\\":
                    i += 2
                    continue
                if code[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if c == "/" and i + 1 < n and code[i + 1] == "/":
            while i < n and code[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and i + 1 < n and code[i + 1] == "*":
            out[i] = " "
            out[i + 1] = " "
            i += 2
            while i < n and not (code[i] == "*" and i + 1 < n and code[i + 1] == "/"):
                if code[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
                out[i + 1] = " "
                i += 2
            continue
        if c == "#":
            while i < n and code[i] != "\n":
                out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def line_of(code, pos):
    return code.count("\n", 0, pos) + 1


# ---------------------------------------------------------------------------
# Small expression parsers (callback values, arrays)
# ---------------------------------------------------------------------------

def read_string(text, pos):
    """Read a quoted string starting at pos. Returns (value, end_pos)."""
    quote = text[pos]
    i = pos + 1
    chars = []
    while i < len(text):
        if text[i] == "\\" and i + 1 < len(text):
            chars.append(text[i + 1])
            i += 2
            continue
        if text[i] == quote:
            return "".join(chars), i + 1
        chars.append(text[i])
        i += 1
    return "".join(chars), i


def skip_ws(text, pos):
    while pos < len(text) and text[pos] in " \t\r\n":
        pos += 1
    return pos


def match_bracket(text, pos):
    """pos points at '(', '[' or '{'. Returns the index just past the
    matching closer, or -1 if unbalanced."""
    opener = text[pos]
    closer = {"(": ")", "[": "]", "{": "}"}[opener]
    depth = 0
    i = pos
    while i < len(text):
        c = text[i]
        if c in "'\"":
            _, i = read_string(text, i)
            continue
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def split_top_level(text):
    """Split text on top-level commas (nesting and strings respected)."""
    parts = []
    depth = 0
    start = 0
    i = 0
    while i < len(text):
        c = text[i]
        if c in "'\"":
            _, i = read_string(text, i)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    parts.append(text[start:])
    return parts


def parse_callback(text, pos):
    """Parse a callback expression at pos. Returns
    (kind, name, end_pos) where kind is 'function', 'method', 'closure'
    or 'unknown'."""
    pos = skip_ws(text, pos)
    if pos >= len(text):
        return "unknown", None, pos
    c = text[pos]
    if c in "'\"":
        name, end = read_string(text, pos)
        return "function", name, end
    if text.startswith("function", pos):
        return "closure", None, pos
    if text.startswith("array", pos) and skip_ws(text, pos + 5) < len(text) \
            and text[skip_ws(text, pos + 5)] == "(":
        open_pos = skip_ws(text, pos + 5)
        end = match_bracket(text, open_pos)
        if end == -1:
            return "unknown", None, pos
        inner = text[open_pos + 1:end - 1]
        parts = split_top_level(inner)
        if len(parts) >= 2:
            p = skip_ws(parts[1], 0)
            if p < len(parts[1]) and parts[1][p] in "'\"":
                name, _ = read_string(parts[1], p)
                return "method", name, end
        return "unknown", None, end
    if c == "[":
        end = match_bracket(text, pos)
        if end == -1:
            return "unknown", None, pos
        inner = text[pos + 1:end - 1]
        parts = split_top_level(inner)
        if len(parts) >= 2:
            p = skip_ws(parts[1], 0)
            if p < len(parts[1]) and parts[1][p] in "'\"":
                name, _ = read_string(parts[1], p)
                return "method", name, end
        return "unknown", None, end
    m = re.match(r"[A-Za-z_][A-Za-z0-9_\\]*", text[pos:])
    if m:
        return "function", m.group(0), pos + m.end()
    return "unknown", None, pos


# ---------------------------------------------------------------------------
# Function-body index
# ---------------------------------------------------------------------------

def index_functions(code):
    """Map function/method name -> list of bodies (brace-matched)."""
    bodies = {}
    for m in re.finditer(r"\bfunction\s+([A-Za-z0-9_]+)\s*\(", code):
        name = m.group(1)
        brace = code.find("{", m.end())
        semi = code.find(";", m.end())
        if brace == -1 or (semi != -1 and semi < brace):
            continue  # abstract / interface method, no body
        end = match_bracket(code, brace)
        if end == -1:
            continue
        bodies.setdefault(name, []).append(code[brace:end])
    return bodies


def auth_checks_found(body):
    """Return the list of auth-check calls present in a function body."""
    if not body:
        return []
    return [check[:-1] for check in AUTH_CHECKS if check in body]


# ---------------------------------------------------------------------------
# Handler discovery
# ---------------------------------------------------------------------------

AJAX_RE = re.compile(
    r"""add_action\s*\(\s*(['"])wp_ajax_(nopriv_)?([A-Za-z0-9_\-]+)\1\s*,""",
    re.VERBOSE,
)

REST_RE = re.compile(
    r"""register_rest_route\s*\(\s*(['"])([^'"]+)\1\s*,\s*(['"])([^'"]+)\3\s*,""",
    re.VERBOSE,
)

KEY_RE = re.compile(r"""['"](callback|permission_callback)['"]\s*=>""")
METHODS_RE = re.compile(r"""['"]methods['"]\s*=>\s*['"]([^'"]+)['"]""")


def find_ajax_handlers(code, rel_path):
    handlers = []
    for m in AJAX_RE.finditer(code):
        nopriv = bool(m.group(2))
        action = m.group(3)
        kind, name, _ = parse_callback(code, m.end())
        handlers.append({
            "handler": "wp_ajax_{}{}".format("nopriv_" if nopriv else "", action),
            "type": "ajax-nopriv" if nopriv else "ajax",
            "file": rel_path,
            "line": line_of(code, m.start()),
            "callback_kind": kind,
            "callback": name,
        })
    return handlers


def find_rest_handlers(code, rel_path):
    handlers = []
    for m in REST_RE.finditer(code):
        namespace, route = m.group(2), m.group(4)
        pos = skip_ws(code, m.end())
        if pos >= len(code):
            continue
        args_text = None
        if code.startswith("array", pos) and code[skip_ws(code, pos + 5)] == "(":
            open_pos = skip_ws(code, pos + 5)
            end = match_bracket(code, open_pos)
            if end != -1:
                args_text = code[open_pos + 1:end - 1]
        elif code[pos] == "[":
            end = match_bracket(code, pos)
            if end != -1:
                args_text = code[pos + 1:end - 1]
        if args_text is None:
            continue
        # Pair each callback with the permission_callback that follows it
        # (before the next callback) — handles multi-endpoint arrays too.
        keys = [(km.group(1), km.end()) for km in KEY_RE.finditer(args_text)]
        callbacks = []
        for idx, (key, val_pos) in enumerate(keys):
            kind, name, _ = parse_callback(args_text, val_pos)
            callbacks.append((key, kind, name, val_pos))
        methods = None
        for i, (key, kind, name, val_pos) in enumerate(callbacks):
            if key != "callback":
                continue
            perm = None
            for j in range(i + 1, len(callbacks)):
                if callbacks[j][0] == "callback":
                    break
                if callbacks[j][0] == "permission_callback":
                    perm = callbacks[j]
                    break
            before = args_text[:val_pos]
            mm = list(METHODS_RE.finditer(before))
            methods = mm[-1].group(1) if mm else "ANY"
            handlers.append({
                "handler": "{} {} ({})".format(namespace, route, methods),
                "type": "rest",
                "file": rel_path,
                "line": line_of(code, m.start()),
                "callback_kind": kind,
                "callback": name,
                "perm_kind": perm[1] if perm else None,
                "perm_callback": perm[2] if perm else None,
                "perm_pos": perm[3] if perm else None,
                "args_text": args_text,
            })
    return handlers


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------

def verdict_ajax(handler, functions):
    kind, name = handler["callback_kind"], handler["callback"]
    if kind == "closure":
        return "REVIEW", "anonymous callback — body not inspected, verify by hand"
    if kind == "unknown" or not name:
        return "REVIEW", "callback could not be parsed — verify by hand"
    bodies = functions.get(name, [])
    if not bodies:
        return "REVIEW", "callback '{}' definition not found — verify by hand".format(name)
    checks = auth_checks_found(bodies[0])
    if checks:
        return "OK", "auth check present: {}".format(", ".join(checks))
    if handler["type"] == "ajax-nopriv":
        return "VULNERABLE", "nopriv handler with no capability/nonce check"
    return "REVIEW", "logged-in only, but no capability/nonce check — check which roles can reach it"


def verdict_rest(handler, functions):
    perm_kind = handler.get("perm_kind")
    perm_name = handler.get("perm_callback")
    if perm_kind is None:
        return "VULNERABLE", "no permission_callback — route is public"
    if perm_kind == "function" and perm_name == "__return_true":
        return "VULNERABLE", "permission_callback is __return_true — route is public"
    if perm_kind == "closure":
        # Inspect the closure body text inside the route args.
        segment = handler["args_text"][handler["perm_pos"]:]
        checks = auth_checks_found(segment)
        if checks:
            return "OK", "permission_callback closure checks: {}".format(", ".join(checks))
        return "REVIEW", "permission_callback closure with no recognizable auth check — verify by hand"
    if perm_kind == "unknown" or not perm_name:
        return "REVIEW", "permission_callback could not be parsed — verify by hand"
    bodies = functions.get(perm_name, [])
    if not bodies:
        return "REVIEW", "permission_callback '{}' definition not found — verify by hand".format(perm_name)
    checks = auth_checks_found(bodies[0])
    if checks:
        return "OK", "permission_callback checks: {}".format(", ".join(checks))
    return "REVIEW", "permission_callback '{}' has no recognizable auth check — verify by hand".format(perm_name)


# ---------------------------------------------------------------------------
# Scanning + output
# ---------------------------------------------------------------------------

def scan(target):
    target = Path(target)
    if target.is_file():
        files = [target]
        base = target.parent
    else:
        files = sorted(target.rglob("*.php"))
        base = target
    functions = {}
    handlers = []
    for path in files:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        code = strip_comments(raw)
        try:
            rel = str(path.relative_to(base))
        except ValueError:
            rel = str(path)
        for name, bodies in index_functions(code).items():
            functions.setdefault(name, []).extend(bodies)
        handlers.extend(find_ajax_handlers(code, rel))
        handlers.extend(find_rest_handlers(code, rel))
    results = []
    for h in handlers:
        if h["type"] == "rest":
            verdict, reason = verdict_rest(h, functions)
        else:
            verdict, reason = verdict_ajax(h, functions)
        results.append({
            "handler": h["handler"],
            "type": h["type"],
            "file": h["file"],
            "line": h["line"],
            "verdict": verdict,
            "reason": reason,
        })
    return results


def print_table(results):
    if not results:
        print("No AJAX/REST handlers found.")
        return
    headers = ("Handler", "Type", "File:Line", "Verdict", "Reason")
    rows = [
        (r["handler"], r["type"], "{}:{}".format(r["file"], r["line"]),
         r["verdict"], r["reason"])
        for r in results
    ]
    widths = [max(len(h), max(len(row[i]) for row in rows)) for i, h in enumerate(headers)]
    widths[-1] = max(widths[-1], len(headers[-1]))
    fmt = "  ".join("{{:<{}}}".format(w) for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for row in rows:
        print(fmt.format(*row))
    vuln = sum(1 for r in results if r["verdict"] == "VULNERABLE")
    review = sum(1 for r in results if r["verdict"] == "REVIEW")
    print()
    print("{} handler(s) scanned: {} VULNERABLE, {} REVIEW, {} OK".format(
        len(results), vuln, review, len(results) - vuln - review))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Find WordPress AJAX and REST handlers missing authorization.")
    parser.add_argument("path", nargs="?", default=".",
                        help="plugin directory or single .php file to scan")
    parser.add_argument("--json", action="store_true",
                        help="output results as JSON")
    args = parser.parse_args(argv)
    results = scan(args.path)
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_table(results)
    return 1 if any(r["verdict"] == "VULNERABLE" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
