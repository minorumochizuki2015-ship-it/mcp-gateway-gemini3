FROM python:3.12-slim AS base

WORKDIR /app

# System deps for lxml
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libxml2-dev libxslt1-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY docs/ docs/

ENV PYTHONUNBUFFERED=1
ENV MCP_GATEWAY_DEMO_MODE=false

EXPOSE 8080

# Cloud Run sets PORT env var; default 8080
CMD ["python", "-m", "uvicorn", "src.mcp_gateway.gateway:app", \
     "--host", "0.0.0.0", "--port", "8080"]
