FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY images/analyzer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY analyzer /app/analyzer
ENV PYTHONPATH=/app
CMD ["python", "-m", "analyzer"]
