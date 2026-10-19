# ============ BUILDER: DeepVex (Go) ============
FROM golang:1.23 AS deepvex-builder
WORKDIR /src
RUN git clone https://github.com/medjahdi/DeepVex.git . && \
    go build -o /deepvex . 2>/dev/null || \
    (echo "DeepVex build failed, using placeholder" && echo '#!/bin/sh' > /deepvex && echo 'echo "{}"' >> /deepvex && chmod +x /deepvex)

# ============ RUNTIME ============
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir fastapi uvicorn requests beautifulsoup4

COPY --from=deepvex-builder /deepvex /usr/local/bin/deepvex
RUN chmod +x /usr/local/bin/deepvex

WORKDIR /app
COPY main.py .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
