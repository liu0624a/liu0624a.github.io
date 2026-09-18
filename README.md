# VehicleWatch — Abandoned Vehicle Reporting

VehicleWatch is a self-contained MVP for a county abandoned-vehicle program. It uses the Node.js built-in HTTP server and SQLite (`node:sqlite`), so it has no package installation step.

## Run locally

```powershell
$env:APP_SECRET = "use-a-long-random-secret-in-production"
node server.js
```

Open `http://localhost:3000`.

The first start creates `data/vehiclewatch.sqlite` and private image storage under `uploads/`. It also inserts clearly marked demo data and a local administrator:

- Email: `admin@vehiclewatch.local`
- Password: `ChangeMe!2026`

Change or remove this account before deployment. In production, set a strong `APP_SECRET`, set `DEMO_MODE=false`, serve behind HTTPS, and use a managed filesystem/object store and SMTP/identity provider as appropriate.

## What is implemented

- Public, account-free report flow with client-side image resizing, server-side byte/signature/dimension validation, private photo storage, status lookup, geolocation/manual address, duplicate-risk detection, honeypot, timing check, and server-side source rate limiting.
- Staff password authentication with database-backed, expiring HTTP-only sessions; role checks are performed on every staff API request. The seed account is an Administrator.
- SQLite records for reports, vehicle cases, notes, review history, and append-only audit events.
- Staff dashboard, reports search/filter, report review, possible-match review, case creation/linking, notes, status changes, active-map coordinate plot, case resolution, statistics, and settings guidance.
- Public status responses deliberately omit uploaded images, precise coordinates, staff notes, risk flags, duplicate analysis, and audit history.

## Production integration boundaries

The app deliberately needs no third-party credentials for a local demo. `MAP_TILE_URL` is reserved for an authorized mapping provider; the built-in interactive coordinate plot and OpenStreetMap directions links work without it. The `analyzePossibleDuplicates` function is the explicit integration point for future image-similarity/AI scoring; its results are advisory only.
