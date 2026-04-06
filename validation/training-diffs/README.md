# Training diffs (malicious PR simulation)

These files are **unified diffs** against the clean baseline [`validation/target-app/server.js`](../target-app/server.js). Each patch introduces **exactly one** vulnerability for training or pipeline testing. They are **not** applied in the repository by default.

Apply from the **repository root** (review before applying):

```bash
git apply --check validation/training-diffs/<name>.diff   # dry run
git apply validation/training-diffs/<name>.diff           # apply to working tree
```

Revert with `git checkout -- validation/target-app/server.js` if you do not commit.

| Diff file | What it changes | OWASP Top 10 (2021) | Notes |
|-----------|-----------------|---------------------|--------|
| [`sqli-unsanitized-query.diff`](sqli-unsanitized-query.diff) | `GET /users/:id` builds SQL with string concatenation from `req.params.id` | **A03:2021 – Injection** | Classic SQL injection (CWE-89). Baseline uses parameterized queries. |
| [`xss-unescaped-output.diff`](xss-unescaped-output.diff) | Adds `GET /users/:id/profile` returning HTML with `${u.name}` / `${u.email}` unescaped | **A03:2021 – Injection** | Reflected/stored XSS (CWE-79) when user-controlled data reaches the template. |
| [`path-traversal-filename.diff`](path-traversal-filename.diff) | Adds `GET /files/:name` reading `path.join(__dirname, 'uploads', req.params.name)` | **A01:2021 – Broken Access Control** | Path traversal (CWE-22) via `../` segments in `:name`. |
| [`command-injection-exec.diff`](command-injection-exec.diff) | Adds `POST /users/:id/export` using `child_process.exec` with the DB `name` field in the shell string | **A03:2021 – Injection** | OS command injection (CWE-78). |
| [`broken-auth-no-session.diff`](broken-auth-no-session.diff) | Adds `DELETE /admin/users/:id` with no authentication or authorization | **A01:2021 – Broken Access Control** | Missing enforcement of intent (admin-only delete); related to **A07:2021 – Identification and Authentication Failures** when auth should exist but does not. |

**Disclaimer:** These patterns are for **education and controlled testing** only. Do not deploy them to production systems.
