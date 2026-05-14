FROM python:3.11-slim

WORKDIR /careotter

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        net-tools \
        vim \
            && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create directory for the SQLite database with correct permissions
RUN mkdir -p /app/data && chmod 777 /app/data

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY ./ /careotter

ENV VULNERABLE=1
# DEVICE_IP intentionally not set here — the device IP is learned at runtime
# via POST /admin/device/register (BLE provisioning) or POST /initialize_iot
# (fallback). Defaults to "" in config.py until then.
ENV IGP_PORT=9999
ENV HTTP_PORT=8081
ENV PORT=5002
ENV DB_PATH=/app/data/careotter.db

EXPOSE 5002

CMD ["python3", "app.py"]
