# Answer key (keep this OUT of the GitHub repo)

7 real vulnerabilities + 2 false positives (+ 1 duplicate row in the report, to exercise de-duplication).

| # | Finding | Where | Why it is real / what a good fix does |
|---|---|---|---|
| 1 | SQL Injection (second-order) | app/reports.py:18 | Usernames are inserted safely at register time, then concatenated into an f-string query by the admin audit summary. Register as `x' OR '1'='1`. Fix: parameterize the query. |
| 2 | Server-Side Request Forgery | app/webhooks.py:17 | `startswith("https://hooks.vaultdesk.example")` is bypassed by `https://hooks.vaultdesk.example.evil.net/` or `https://hooks.vaultdesk.example@169.254.169.254/`. Fix: parse the URL, compare exact hostname + https, block private IPs. |
| 3 | Path Traversal (decode after check) | app/files.py:22 | `..` is rejected, then the name is URL-decoded again. `%252e%252e%252fsecret` passes the check and becomes `../secret`. Fix: decode first, then realpath + base-dir check. |
| 4 | Insecure Deserialization | app/prefs.py:37 | `pickle.loads` on request data. The HMAC key falls back to a hard-coded default, so the signature can be forged. Fix: JSON instead of pickle (and no default key). |
| 5 | Unsigned JWT accepted | app/auth.py:51 | `alg: none` is accepted when the token claims `iss: legacy-sso`, which the attacker controls. Fix: pin HS256, always verify. |
| 6 | Broken object authorization + mass assignment | app/tickets.py:28 | Any user can PATCH any ticket, and `owner_id` is editable. Fix: ownership check (or admin) and remove `owner_id` from editable fields. |
| 7 | Open Redirect (parser differential) | app/auth.py:119 | `_is_local` passes `/\evil.com` and `///evil.com`, which browsers treat as external. Fix: reject backslashes and leading `//`, or allow-list paths. |
| FP | SQL Injection (Suspect) | app/reports.py:28 | Table name comes from a fixed dict after an allow-list check. Not exploitable. |
| FP | Cross-Site Scripting (Suspect) | app/files.py:14 | JSON response (`jsonify`), not HTML. Not exploitable. |

Existing tests (7, pytest) pass on the vulnerable code and should still pass after the fixes.
