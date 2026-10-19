FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates whois dnsutils && \
    rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir fastapi uvicorn requests beautifulsoup4
WORKDIR /app
COPY main.py tools.py tools_assets.py ./
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
