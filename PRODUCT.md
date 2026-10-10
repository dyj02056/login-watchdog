# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Next.js (static export, TypeScript) served by the existing Flask app (`python app.py`); deployed on Vercel. Backend, auth, CSRF and RBAC stay in Flask. (Stack confirmed by the user.)

## Users

- Security operators watching the dashboard on a large monitor in a control-room setting, scanning for what needs action in seconds.
- Admins with three roles (security_viewer / security_admin / super_admin) who unlock IPs and accounts, resolve events and manage members.
- Members of the demo site (signup, login, board, profile, recovery flows) who are the monitored population.

## Product Purpose

Login Watchdog detects brute-force and other L7 abuse, locks IPs/accounts, alerts Slack, and lets admins review and act. Success: an operator sees the current threat picture and acts on it without hunting.

## Positioning

Real detection + response behind the screen (lockouts, SIEM correlation, SOAR, AI early warning), not mock data. Where no data exists (L3/L4 network-layer attacks) the UI says so instead of inventing numbers.

## Visual commitments (user-volunteered)

- Reference: the user's two screenshots of a Korean network-security monitoring wall ("분석기술팀 상세 위협현황", "Attack 상세 모니터링"): dark navy control-room board, HUD-style titled frame, cyan/green accents, dense charts (area lines, bars, heatmap, sankey, pie) and tables.
- Must not read as AI-generated.

## Open decisions (inferred, not user-confirmed)

- No interview round was run; the brief was explicit and the user asked to proceed. Product facts above are inferred from the repo README and the user's request.
