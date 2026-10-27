# API Reference

SentinelAI exposes a RESTful API powered by FastAPI.
To view the interactive Swagger documentation, navigate to `/api/docs` when the backend is running.

## Key Endpoints

### Authentication
- `POST /api/auth/register` - Create a new user
- `POST /api/auth/login` - Authenticate and receive a JWT
- `GET /api/auth/me` - Retrieve current user profile

### Analysis
- `POST /api/analysis/upload` (multipart/form-data) - Upload a file for analysis
- `POST /api/analysis/url` (json) - Submit a URL for analysis
- `POST /api/analysis/text` (json) - Submit text for analysis
- `GET /api/analysis` - List recent analyses
- `GET /api/analysis/{id}` - Poll for analysis status and retrieve full results

### Reports
- `GET /api/reports` - List completed reports
- `GET /api/reports/{id}/pdf` - Download report as PDF
- `GET /api/reports/{id}/json` - Export report as JSON

### Admin
- `GET /api/admin/stats` - Retrieve global system metrics
- `GET /api/admin/users` - List system users
- `GET /api/admin/audit` - List system audit logs
