# Universal Parser V2 - Deployment Guide

**Version**: 0.1.0 (PoC)
**Last Updated**: October 14, 2025

## Overview

This guide covers deploying Universal Parser V2 in various environments:

1. **Development Deployment** - Local testing and development
2. **Docker Deployment** - Containerized microservice
3. **DefectDojo Integration** - Integrating with existing DefectDojo
4. **Production Deployment** - Production-ready setup

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Development Deployment](#development-deployment)
- [Docker Deployment](#docker-deployment)
- [DefectDojo Integration](#defectdojo-integration)
- [Production Deployment](#production-deployment)
- [Configuration](#configuration)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

**Microservice**:
- Python 3.12 or higher
- 512 MB RAM minimum (2 GB recommended)
- 100 MB disk space

**DefectDojo**:
- DefectDojo 2.x with `upV2-Poc` branch
- PostgreSQL 12+ (DefectDojo requirement)
- Redis (DefectDojo requirement)

### Required Software

```bash
# Check Python version
python3 --version  # Should be 3.12+

# Check pip
pip3 --version

# Check Docker (for Docker deployment)
docker --version
docker compose version
```

---

## Development Deployment

Development deployment is for local testing and parser development.

### Step 1: Clone Repository

```bash
cd /your/development/directory
git clone https://github.com/DefectDojo/django-DefectDojo.git
cd django-DefectDojo
git checkout upV2-Poc
```

### Step 2: Setup Microservice

```bash
# Navigate to microservice directory
cd universal-parser-v2

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -m pytest tests/ -v
```

Expected output: **47 tests passing ✅**

### Step 3: Start Microservice

```bash
# Start FastAPI with hot-reload
uvicorn app.main:app --reload --port 8000

# Or run directly
python app/main.py
```

The microservice will be available at:
- **Web UI**: http://localhost:8000
- **Swagger API**: http://localhost:8000/api/docs
- **ReDoc**: http://localhost:8000/api/redoc
- **Health Check**: http://localhost:8000/health

### Step 4: Setup DefectDojo (Development Mode)

In a **separate terminal**:

```bash
cd django-DefectDojo

# Set development environment
docker/setEnv.sh dev

# Build and start DefectDojo
docker compose build
docker compose up
```

Wait for initialization (approximately 3 minutes). Then get admin credentials:

```bash
docker compose logs initializer | grep "Admin password:"
```

DefectDojo will be available at:
- **Web UI**: http://localhost:8080
- **API**: http://localhost:8080/api/v2/

### Step 5: Get API Token

1. Open http://localhost:8080
2. Log in with admin credentials
3. Click your profile (top-right)
4. Click "API Key"
5. Copy the token

### Step 6: Test End-to-End

```bash
# Create a test in DefectDojo first, then:
cd universal-parser-v2

curl -X POST http://localhost:8000/api/import \
  -F "scan_file=@tests/fixtures/acunetix_sample.json" \
  -F "yaml_file=@configs/acunetix360_json.yaml" \
  -F "defectdojo_url=http://localhost:8080" \
  -F "defectdojo_api_token=YOUR_TOKEN" \
  -F "test_id=1"
```

### Development Workflow

```bash
# Terminal 1: Microservice with hot-reload
cd universal-parser-v2
source venv/bin/activate
uvicorn app.main:app --reload --port 8000

# Terminal 2: DefectDojo
cd django-DefectDojo
docker compose up

# Terminal 3: Run tests
cd universal-parser-v2
python -m pytest tests/ -v
```

---

## Docker Deployment

Deploy the microservice as a Docker container.

### Step 1: Create Dockerfile

Create `universal-parser-v2/Dockerfile`:

```dockerfile
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY configs/ ./configs/

# Create non-root user
RUN useradd -m -u 1000 upv2 && \
    chown -R upv2:upv2 /app
USER upv2

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Run application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Step 2: Build Docker Image

```bash
cd universal-parser-v2
docker build -t universal-parser-v2:latest .
```

### Step 3: Run Container

```bash
docker run -d \
  --name universal-parser-v2 \
  -p 8000:8000 \
  --restart unless-stopped \
  universal-parser-v2:latest
```

### Step 4: Verify Container

```bash
# Check container status
docker ps | grep universal-parser-v2

# Check logs
docker logs universal-parser-v2

# Test health endpoint
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "universal-parser-v2",
  "version": "0.1.0"
}
```

### Step 5: Docker Compose Setup

Create `universal-parser-v2/docker-compose.yml`:

```yaml
version: '3.8'

services:
  universal-parser-v2:
    build: .
    container_name: universal-parser-v2
    ports:
      - "8000:8000"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s
    environment:
      - LOG_LEVEL=info
    volumes:
      # Mount configs for easy updates
      - ./configs:/app/configs:ro
    networks:
      - defectdojo

networks:
  defectdojo:
    external: true
```

Run with Docker Compose:

```bash
docker compose up -d
docker compose logs -f
```

---

## DefectDojo Integration

Integrate the microservice with an existing DefectDojo instance.

### Option 1: Same Host as DefectDojo

If running on the same host as DefectDojo:

```bash
# Add microservice to DefectDojo's docker-compose
cd django-DefectDojo

# Edit docker-compose.override.yml
cat >> docker-compose.override.yml << 'EOF'
version: '3.8'

services:
  universal-parser-v2:
    build: ./universal-parser-v2
    container_name: universal-parser-v2
    ports:
      - "8000:8000"
    restart: unless-stopped
    networks:
      - defectdojo

networks:
  defectdojo:
    name: defectdojo_default
EOF

# Start all services
docker compose up -d
```

### Option 2: Separate Host

If running on a different host:

**Microservice Host**:
```bash
# Start microservice
docker run -d \
  --name universal-parser-v2 \
  -p 8000:8000 \
  universal-parser-v2:latest
```

**Configuration**:
- Ensure firewall allows traffic on port 8000
- Use DefectDojo's public URL when calling API
- Configure HTTPS if needed (see Production Deployment)

### Option 3: Kubernetes

Create `universal-parser-v2/k8s/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: universal-parser-v2
  labels:
    app: universal-parser-v2
spec:
  replicas: 2
  selector:
    matchLabels:
      app: universal-parser-v2
  template:
    metadata:
      labels:
        app: universal-parser-v2
    spec:
      containers:
      - name: universal-parser-v2
        image: universal-parser-v2:latest
        ports:
        - containerPort: 8000
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 3
          periodSeconds: 10
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
---
apiVersion: v1
kind: Service
metadata:
  name: universal-parser-v2
spec:
  selector:
    app: universal-parser-v2
  ports:
  - protocol: TCP
    port: 8000
    targetPort: 8000
  type: LoadBalancer
```

Deploy:

```bash
kubectl apply -f k8s/deployment.yaml
kubectl get pods -l app=universal-parser-v2
kubectl get svc universal-parser-v2
```

---

## Production Deployment

Production deployment requires additional security and reliability considerations.

### Security Checklist

- [ ] Enable HTTPS/TLS
- [ ] Implement rate limiting
- [ ] Add API authentication
- [ ] Configure CORS properly
- [ ] Use secrets management
- [ ] Enable audit logging
- [ ] Restrict network access
- [ ] Update dependencies regularly

### Step 1: HTTPS/TLS Setup

**Option A: Nginx Reverse Proxy**

Create `nginx.conf`:

```nginx
server {
    listen 443 ssl http2;
    server_name parser.example.com;

    ssl_certificate /etc/ssl/certs/parser.crt;
    ssl_certificate_key /etc/ssl/private/parser.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://universal-parser-v2:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;

        # File upload size limit
        client_max_body_size 100M;
    }
}
```

**Option B: Traefik**

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  universal-parser-v2:
    build: .
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.parser.rule=Host(`parser.example.com`)"
      - "traefik.http.routers.parser.entrypoints=websecure"
      - "traefik.http.routers.parser.tls.certresolver=letsencrypt"
    networks:
      - traefik

  traefik:
    image: traefik:v2.10
    command:
      - "--providers.docker=true"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.email=admin@example.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
      - "--certificatesresolvers.letsencrypt.acme.tlschallenge=true"
    ports:
      - "443:443"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "./letsencrypt:/letsencrypt"
    networks:
      - traefik

networks:
  traefik:
    external: true
```

### Step 2: Rate Limiting

Add to `app/main.py`:

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/api/import")
@limiter.limit("10/minute")
async def import_scan(...):
    # ... existing code
```

Install dependency:
```bash
pip install slowapi
```

### Step 3: Environment Variables

Create `.env.production`:

```bash
# Microservice Configuration
LOG_LEVEL=warning
WORKERS=4
MAX_UPLOAD_SIZE=104857600  # 100 MB

# DefectDojo Configuration (defaults)
DEFECTDOJO_URL=https://defectdojo.example.com
DEFECTDOJO_TIMEOUT=300
DEFECTDOJO_VERIFY_SSL=true

# Security
CORS_ORIGINS=https://defectdojo.example.com,https://ci.example.com
```

Load in `app/main.py`:

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    log_level: str = "info"
    cors_origins: str = "*"
    defectdojo_url: str = ""
    defectdojo_timeout: int = 300

    class Config:
        env_file = ".env"

settings = Settings()
```

### Step 4: Logging

Configure structured logging in `app/main.py`:

```python
import logging
import json

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
        }
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_data)

handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logging.root.addHandler(handler)
logging.root.setLevel(logging.WARNING)
```

### Step 5: Health Checks and Monitoring

Enhanced health check:

```python
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "universal-parser-v2",
        "version": "0.1.0",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": {
            "api": "ok",
            "memory": get_memory_usage(),
            "uptime": get_uptime()
        }
    }

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    return {
        "requests_total": metrics_counter.get(),
        "requests_failed": error_counter.get(),
        "imports_total": import_counter.get(),
        "findings_processed": findings_counter.get()
    }
```

### Step 6: Production Docker Compose

`docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  universal-parser-v2:
    build:
      context: .
      dockerfile: Dockerfile
    image: universal-parser-v2:${VERSION:-latest}
    container_name: universal-parser-v2
    restart: always
    ports:
      - "127.0.0.1:8000:8000"
    environment:
      - LOG_LEVEL=warning
      - WORKERS=4
    env_file:
      - .env.production
    volumes:
      - ./configs:/app/configs:ro
      - ./logs:/app/logs
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    networks:
      - internal
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M

networks:
  internal:
    driver: bridge
```

Deploy:

```bash
VERSION=1.0.0 docker compose -f docker-compose.prod.yml up -d
```

---

## Configuration

### Microservice Configuration

**Environment Variables**:

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | Logging level (debug, info, warning, error) |
| `WORKERS` | `1` | Number of worker processes |
| `MAX_UPLOAD_SIZE` | `104857600` | Max upload size in bytes (100 MB) |
| `CORS_ORIGINS` | `*` | Allowed CORS origins (comma-separated) |
| `DEFECTDOJO_URL` | - | Default DefectDojo URL |
| `DEFECTDOJO_TIMEOUT` | `300` | API timeout in seconds |
| `DEFECTDOJO_VERIFY_SSL` | `true` | Verify SSL certificates |

### DefectDojo Configuration

DefectDojo requires the `upV2-Poc` branch to be deployed.

**Verify Integration**:

```bash
# Check that the endpoint exists
curl http://localhost:8080/api/v2/universal-parser-v2/

# Should return available methods
```

**Configuration Files**:
- View: `dojo/api_v2/views.py:2638`
- Serializers: `dojo/api_v2/serializers.py:3154`
- Reimporter: `dojo/tools/universal_parser_v2/reimporter.py`
- URL Config: `dojo/urls.py:164`

---

## Monitoring

### Application Metrics

Monitor these key metrics:

- **Request Rate**: Requests per minute
- **Error Rate**: Failed requests percentage
- **Response Time**: Average/P95/P99 latency
- **Import Success Rate**: Successful imports percentage
- **Findings Processed**: Total findings imported

### Docker Monitoring

```bash
# Container stats
docker stats universal-parser-v2

# Logs
docker logs -f universal-parser-v2

# Health check
docker inspect --format='{{json .State.Health}}' universal-parser-v2
```

### Prometheus + Grafana

Install Prometheus exporters:

```bash
pip install prometheus-fastapi-instrumentator
```

Add to `app/main.py`:

```python
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI(...)
Instrumentator().instrument(app).expose(app)
```

Metrics available at: `http://localhost:8000/metrics`

### Log Aggregation

Configure centralized logging:

```yaml
# docker-compose with logging
services:
  universal-parser-v2:
    logging:
      driver: syslog
      options:
        syslog-address: "tcp://logstash:5000"
        tag: "universal-parser-v2"
```

---

## Troubleshooting

### Common Issues

**Issue 1: Container won't start**

```bash
# Check logs
docker logs universal-parser-v2

# Check port conflicts
netstat -tuln | grep 8000

# Verify image built correctly
docker images | grep universal-parser-v2
```

**Issue 2: Can't connect to DefectDojo**

```bash
# Test network connectivity
docker exec universal-parser-v2 curl http://defectdojo:8080/api/v2/

# Check DefectDojo is running
docker ps | grep defectdojo

# Verify API token
curl -H "Authorization: Token YOUR_TOKEN" http://localhost:8080/api/v2/users/
```

**Issue 3: Import fails with 403 Forbidden**

- Verify API token is correct
- Check user has `Import_Scan_Result` permission
- Verify test exists and user has access

**Issue 4: Slow imports**

```bash
# Increase workers
docker run -e WORKERS=4 ...

# Increase timeout
docker run -e DEFECTDOJO_TIMEOUT=600 ...

# Check resource limits
docker stats universal-parser-v2
```

**Issue 5: YAML validation fails**

```bash
# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Test with validate endpoint
curl -X POST http://localhost:8000/api/validate-yaml \
  -F "yaml_file=@config.yaml"
```

### Debug Mode

Enable debug logging:

```bash
docker run -e LOG_LEVEL=debug universal-parser-v2:latest
```

### Getting Support

1. Check logs: `docker logs universal-parser-v2`
2. Test health endpoint: `curl http://localhost:8000/health`
3. Verify DefectDojo integration
4. Review `docs/ARCHITECTURE.md` for system design
5. Check GitHub Issues

---

## Backup and Recovery

### Configuration Backup

```bash
# Backup YAML configurations
tar -czf configs-backup-$(date +%Y%m%d).tar.gz configs/

# Backup environment
cp .env.production .env.production.backup
```

### DefectDojo Backup

Follow DefectDojo's standard backup procedures for the database.

### Disaster Recovery

1. Redeploy microservice container
2. Restore configuration files
3. Verify health endpoint
4. Test with validation endpoint
5. Resume normal operations

---

## Upgrading

### Microservice Upgrade

```bash
# Pull latest code
git pull origin upV2-Poc

# Rebuild image
docker build -t universal-parser-v2:latest .

# Stop old container
docker stop universal-parser-v2

# Start new container
docker run -d \
  --name universal-parser-v2 \
  -p 8000:8000 \
  universal-parser-v2:latest

# Verify
curl http://localhost:8000/health
```

### DefectDojo Upgrade

Follow DefectDojo's upgrade procedures. Ensure the `upV2-Poc` branch is merged or rebased.

---

## Security Considerations

### Network Security

- Use HTTPS/TLS in production
- Restrict access to port 8000
- Use firewall rules
- Consider VPN for sensitive environments

### API Security

- Rotate API tokens regularly
- Use short-lived tokens when possible
- Implement rate limiting
- Log all API calls
- Monitor for suspicious activity

### Container Security

```bash
# Scan image for vulnerabilities
docker scan universal-parser-v2:latest

# Use non-root user (already in Dockerfile)
# Keep base image updated
docker pull python:3.12-slim
docker build --no-cache -t universal-parser-v2:latest .
```

---

## Performance Tuning

### Resource Allocation

```yaml
# docker-compose with resource limits
services:
  universal-parser-v2:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 1G
```

### Worker Processes

```bash
# Multiple workers for concurrent requests
docker run -e WORKERS=4 universal-parser-v2:latest
```

### Caching

Consider caching YAML configurations:

```python
from functools import lru_cache

@lru_cache(maxsize=100)
def load_yaml_config(yaml_content_hash):
    # Cache parsed YAML configs
    pass
```

---

## Support

- **Issues**: GitHub Issues (DefectDojo repository)
- **Documentation**: See `docs/` directory
- **Community**: DefectDojo Slack/Discord

---

**Status**: PoC (Proof of Concept) - Day 7 Complete ✅
**Branch**: `upV2-Poc`
**Author**: T. Walker - DefectDojo
**Created**: October 2025
