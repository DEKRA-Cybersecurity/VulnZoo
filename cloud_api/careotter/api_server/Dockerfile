FROM python:3.11-slim

WORKDIR /careotter

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        net-tools \
        vim \
    && rm -rf /var/lib/apt/lists/*

# Crear directorio para la base de datos SQLite con permisos correctos
RUN mkdir -p /app/data && chmod 777 /app/data

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY ./ /careotter

ENV VULNERABLE=1
ENV DEVICE_IP=192.168.2.1
ENV IGP_PORT=9999
ENV HTTP_PORT=8081
ENV PORT=5002
ENV DB_PATH=/app/data/careotter.db

EXPOSE 5002

CMD ["python3", "app.py"]
