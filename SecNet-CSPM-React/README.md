# SecNet CSPM React Console

React + TypeScript SOC/CSPM console for the existing SecNet backend.

## Preserved backend
This frontend is designed to keep the current:
- FastAPI
- PostgreSQL
- CSPM worker
- CSPM scanner
- AWS integration
- real scan/finding data

## API used
- `GET /api/v1/scans`
- `GET /api/v1/scans/{id}/detail`
- `POST /api/v1/scans`

Set the API URL in `.env`:

```env
VITE_API_BASE_URL=http://localhost:8000/api/v1
```

## Run

```powershell
npm install
copy .env.example .env
npm run dev
```

Open:

`http://localhost:5173`

## Important
The current backend does not expose remediation execution endpoints in the known API contract. Therefore the Remediation page is intentionally a workflow/review surface and does not pretend to mutate AWS. No AWS workload is changed by this frontend.
