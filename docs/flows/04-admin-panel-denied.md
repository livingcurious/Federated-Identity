# Flow 4 — SP Admin Panel, Denied (Marie, no `admin` role)

Precondition: Marie has completed Flow 2 (login) at SP-A. Valid `fabric_sp_sp_a`
cookie, `SPSessionRow.roles == ["user"]` — no `admin`.

## Step-by-step

1. **Rendering (no) link.** On `home.html` / `profile.html`, `is_admin = _is_admin(user)`
   evaluates `False` for Marie (`"admin" not in ["user"]`). The
   `{% if is_admin %}...{% endif %}` block is skipped entirely — the `<a href="/admin">`
   tag is **not present anywhere in the HTML** Marie's browser receives. There's nothing
   to click. This is the same template used for Grace in Flow 3; the only difference is
   the boolean fed into it.

2. **Marie navigates to `http://sp-a:9401/admin` directly anyway** (typed URL, bookmark,
   whatever — the point of this flow is that hiding the link is not what stops her).
   `GET /admin` (`sp/api/routes.py::admin_panel`):
   - Session loads fine (`load_valid` succeeds — she *is* logged in, just not an admin).
   - `_is_admin(user)` → `False`.
   - `audit.record(Event.SP_ADMIN_ACCESS_DENIED, Severity.WARNING, subject="user-marie",
     outcome="denied", detail={"path": "/admin", "roles": ["user"]})`.
   - Renders `forbidden.html` with `status_code=403`, message *"This page is restricted
     to the admin role."* — no session list, no form, nothing admin-related is ever
     constructed or sent.

3. **Marie tries the action endpoint directly too:
   `POST http://sp-a:9401/admin/revoke-all`** (skipping the UI form entirely — again,
   simulating "what if she just knows the URL"). `admin_revoke_all`:
   - Identical role check, run completely independently of step 2 (no shared state, no
     "already checked this session" shortcut).
   - `audit.record(Event.SP_ADMIN_ACCESS_DENIED, Severity.WARNING, subject="user-marie",
     outcome="denied", detail={"path": "/admin/revoke-all", "roles": ["user"]})`.
   - `403 Forbidden`, same `forbidden.html`, message *"This action is restricted to the
     admin role."* — `SPSessionService.revoke_all()` is never called; no session anywhere
     is touched.

## Why this is the actual security boundary, not the hidden link

If step 1's template check were the *only* control, Marie finding the URL by any other
means (guessing, a search-engine cache, a leaked screenshot, browser history, a
misconfigured link elsewhere) would have full admin capability, including the destructive
"revoke every session at this SP" action. Because steps 2 and 3 independently re-derive
`is_admin` from her actual session's `roles` on the server, on every single request,
knowing or guessing the URL confers nothing — the response is identical (`403`,
audited as `denied`) no matter how she got there.

## Verified live (2026-08-29, against the real container deployment)

```
MARIE login final:              200
MARIE GET  /admin              -> 403
MARIE POST /admin/revoke-all   -> 403
```
Audit trail read directly from `sp_a.db` inside the container:
```
('sp.admin.access_denied', 'warning', 'user-marie', '{"path": "/admin", "roles": ["user"]}')
('sp.admin.access_denied', 'warning', 'user-marie', '{"path": "/admin/revoke-all", "roles": ["user"]}')
```
Both direct hits — GET and POST — were blocked and logged identically, whether or not
the link was ever rendered for her.
