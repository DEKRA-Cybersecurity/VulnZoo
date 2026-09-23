FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends sqlite3 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# SQLite database directory (persisted via the compose volume).
RUN mkdir -p /app/data && chmod 777 /app/data

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV DB_PATH=/app/data/bulbbee.db
EXPOSE 5004

CMD ["gunicorn", \
     "--bind", "0.0.0.0:5004", \
     "--workers", "1", \
     "--threads", "4", \
     "--timeout", "60", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "wsgi:app"]
