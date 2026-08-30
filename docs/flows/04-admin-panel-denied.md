# Flow 4 — SP Admin Panel, Denied (Marie, no `admin` role)

Precondition: Marie has completed Flow 2 (login) at SP-A. Valid `fabric_sp_sp_a`
cookie, `SPSessionRow.roles == ["finance"]` — looked up from SP-A's own `SPUserRoleRow`
table (`seed.py::_SEED_LOCAL_ROLES["sp-a"]["user-marie"]`), not from any IdP claim. She
has a real role (`finance` — see the Finance panel), just not `admin`, which is the
point: role gating is per-role, not "has any role vs. has none."

## Step-by-step

1. **Rendering (no) link.** On `home.html` / `profile.html`, `is_admin = _is_admin(user)`
   evaluates `False` for Marie (`"admin" not in ["finance"]`) — she *does* get the
   Finance link rendered (`is_finance` is `True`), just not the Admin one. The
   `{% if is_admin %}...{% endif %}` block around the Admin link is skipped entirely —
   the `<a href="/admin">` tag is **not present anywhere in the HTML** Marie's browser
   receives. There's nothing to click. This is the same template used for Grace in
   Flow 3; the only difference is which booleans are fed into it.

2. **Marie navigates to `http://sp-a:9401/admin` directly anyway** (typed URL, bookmark,
   whatever — the point of this flow is that hiding the link is not what stops her).
   `GET /admin` (`sp/api/routes.py::admin_panel`):
   - Session loads fine (`load_valid` succeeds — she *is* logged in, just not an admin).
     `_require_role(..., role="admin", action_path="/admin")` checks `"admin" not in
     ["finance"]` → denied.
   - `audit.record(Event.SP_ACCESS_DENIED, Severity.WARNING, subject="user-marie",
     outcome="denied", detail={"path": "/admin", "required_role": "admin",
     "roles": ["finance"]})`. (`SP_ACCESS_DENIED` — renamed from the old
     `SP_ADMIN_ACCESS_DENIED` once this check moved into the shared `_require_role`
     helper used by Admin, Finance, *and* HR alike.)
   - Renders `forbidden.html` with `status_code=403`, message *"This page is restricted
     to the admin role."* — no session list, no form, nothing admin-related is ever
     constructed or sent.

3. **Marie tries the action endpoint directly too:
   `POST http://sp-a:9401/admin/revoke-all`** (skipping the UI form entirely — again,
   simulating "what if she just knows the URL"). `admin_revoke_all`:
   - Identical role check via the same `_require_role` helper, run completely
     independently of step 2 (no shared state, no "already checked this session"
     shortcut).
   - `audit.record(Event.SP_ACCESS_DENIED, Severity.WARNING, subject="user-marie",
     outcome="denied", detail={"path": "/admin/revoke-all", "required_role": "admin",
     "roles": ["finance"]})`.
   - `403 Forbidden`, same `forbidden.html`, message *"This page is restricted to the
     admin role."* (the helper's message is generated from the role name, not
     hand-written per route — see `_require_role`) — `SPSessionService.revoke_all()` is
     never called; no session anywhere is touched.

## Why this is the actual security boundary, not the hidden link

If step 1's template check were the *only* control, Marie finding the URL by any other
means (guessing, a search-engine cache, a leaked screenshot, browser history, a
misconfigured link elsewhere) would have full admin capability, including the destructive
"revoke every session at this SP" action. Because steps 2 and 3 independently re-run
`_require_role` against her actual session's `roles` on the server, on every single
request, knowing or guessing the URL confers nothing — the response is identical (`403`,
audited as `denied`) no matter how she got there.

## Verified live (2026-08-29, re-verified against the container deployment)

```
MARIE login final:              200
MARIE GET  /admin              -> 403
MARIE POST /admin/revoke-all   -> 403
```
Audit trail read directly from `sp_a.db` inside the container:
```
('sp.access.denied', 'warning', 'user-marie', '{"path": "/admin", "required_role": "admin", "roles": ["finance"]}')
('sp.access.denied', 'warning', 'user-marie', '{"path": "/admin/revoke-all", "required_role": "admin", "roles": ["finance"]}')
```
Both direct hits — GET and POST — were blocked and logged identically, whether or not
the link was ever rendered for her.
