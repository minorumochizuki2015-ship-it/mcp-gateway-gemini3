FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=on

RUN useradd -ms /bin/bash appuser
WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY docs ./docs
COPY scripts ./scripts
COPY observability ./observability

EXPOSE 4100
USER appuser
CMD ["python", "-m", "mcp_gateway.gateway"]
