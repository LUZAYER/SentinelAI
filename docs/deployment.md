# Deployment Guide

SentinelAI supports multiple deployment models, from local development to production-grade container orchestration.

## Docker Compose (Recommended)
The easiest way to deploy SentinelAI is using the provided `docker-compose.yml`.

```bash
# Start all services
docker-compose up -d --build

# View logs
docker-compose logs -f
```

This starts:
1. `db`: PostgreSQL 15 Database
2. `redis`: Redis 7 Message Broker
3. `backend`: FastAPI API Server (port 8000)
4. `worker`: Celery Background Worker
5. `frontend`: Next.js 15 UI (port 3000)

## Production Considerations
- **Secrets**: Replace all placeholder secrets in `docker-compose.yml` or `.env` with strong, randomly generated keys.
- **HTTPS**: Use a reverse proxy like Nginx or Traefik to terminate SSL/TLS.
- **LLM Engine**: If deploying locally without a cloud API key, ensure Ollama is running on the host machine and accessible via `host.docker.internal:11434`.

## Manual / Bare Metal Deployment
1. Set up a PostgreSQL server and create a database named `sentinelai`.
2. Set up a Redis server.
3. Install backend dependencies via `pip install -r requirements.txt`.
4. Run migrations: `alembic upgrade head`.
5. Run the FastAPI server: `uvicorn backend.app.main:app --host 0.0.0.0 --port 8000`.
6. Run the Celery worker: `celery -A backend.app.workers.celery_app worker --loglevel=info`.
7. Install frontend dependencies: `npm install`.
8. Build frontend: `npm run build`.
9. Start frontend: `npm start`.
