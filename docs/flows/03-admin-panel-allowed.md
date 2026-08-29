# Flow 3 — SP Admin Panel, Allowed (Grace, has the `admin` role)

Precondition: Grace has already completed Flow 2 (login) at SP-A. She has a valid
`fabric_sp_sp_a` cookie and her `SPSessionRow.roles == ["user", "admin"]` (copied
verbatim from the `id_token`'s `roles` claim at login time — see Flow 2 step 4).

## Step-by-step

1. **Rendering the link (`sp/api/routes.py::profile`, `home`).** Both the home page and
   the profile page compute `is_admin = _is_admin(user)` where
   `_is_admin(user) = user is not None and "admin" in user.roles`, and pass it into the
   Jinja2 template context. `profile.html` / `home.html` contain
   `{% if is_admin %}<p>→ <a href="/admin">Admin panel</a></p>{% endif %}` — for Grace
   this evaluates true, so the link renders. **This check is purely cosmetic** — it
   decides what HTML gets sent, nothing more. It is not the security boundary; step 2 is.

2. **Browser → SP-A: `GET /admin`** (`sp/api/routes.py::admin_panel`).
   - Loads the session the same way `/profile` does
     (`SPSessionService.load_valid(cookie)`); if there's no valid session, `302` to
     `/login` (not relevant here — Grace has one).
   - Computes `_is_admin(user)` **again, independently of the template check in step
     1** — this second, server-side evaluation is the actual enforcement point. It's
     true for Grace.
   - `SPSessionService.list_active()` → `SPSessionRepository.all_active()` — a plain
     `SELECT * FROM sp_sessions WHERE revoked = 0`, no filtering by who's asking beyond
     the role gate already passed.
   - Renders `admin.html`: `200`, listing every currently-active local session at SP-A
     (email, roles, `sid`, `idp_sid`, `created_at`) and a form
     `<form method="post" action="/admin/revoke-all">`.

3. **Browser → SP-A: `POST /admin/revoke-all`** (`sp/api/routes.py::admin_revoke_all`).
   - Same session load + same independent `_is_admin()` check, re-run from scratch on
     this request (it does not trust anything decided by the `GET /admin` request a
     moment ago — every request re-proves the role).
   - `SPSessionService.revoke_all()` → `SPSessionRepository.revoke_all_active()`: loads
     every non-revoked `SPSessionRow`, sets `revoked=True` on each (including, notably,
     **Grace's own** row — "revoke all" means all, no special-casing the caller), commits.
   - Audits `sp.admin.sessions_revoked` at **`ALERT`** severity (this is a
     high-signal/destructive action — appears in the "loud stderr banner" alert path,
     not just the routine log), `subject=user-grace`, `detail={"count": <n>}`.
   - Response: `303 See Other` → `/admin`.

4. **Browser → SP-A: `GET /admin` again.** Grace's own session was just revoked in step
   3, so `load_valid()` now returns `None` → `302` to `/login`. (An expected, correct
   side effect of "revoke *all*", not a bug — confirmed by design, not assumed.)

## Verified live (2026-08-29, against the real container deployment)

```
GRACE login final: 200
GRACE GET  /admin              -> 200   (sessions listed: 31 — accumulated from repeated test logins)
GRACE POST /admin/revoke-all   -> 200
```
Audit trail read directly from `sp_a.db` inside the container:
```
('sp.admin.sessions_revoked', 'alert', 'user-grace', '{"count": 31}')
```
All 31 active sessions at SP-A (Grace's own included) were revoked in one call, exactly
as designed.
