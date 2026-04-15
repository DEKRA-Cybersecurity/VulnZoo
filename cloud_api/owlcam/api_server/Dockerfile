FROM python:3.11-slim

WORKDIR /vulnzoo

# Instala solo lo necesario, incluyendo cron
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libffi-dev \
        libssl-dev \
        python3-dev \
        cron \
        libgl1 \
        libglib2.0-0 \
        libsm6 \
        libxrender1 \
        libxext6 \
        libxcb1 \
        vim \
        net-tools \
    && rm -rf /var/lib/apt/lists/*

# Instala dependencias de Python
COPY requirements.txt .
RUN pip install --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r requirements.txt

# Copia el código de la aplicación
COPY ./ /vulnzoo

# Configura el cron
COPY tools/admin_cron /etc/cron.d/admin_cron
RUN chmod 0644 /etc/cron.d/admin_cron && \
    crontab /etc/cron.d/admin_cron

ENV VULNERABLE=1
ENV TOKENTIMETOLIVE=60
ENV C2_SERVER_URL=http://c2-server:4999

# Solo expone el puerto de la API Flask
# Los puertos C2 (8443/8444) se han eliminado - ahora están en contenedor separado
EXPOSE 5000

# Inicia cron y la app
CMD service cron start && python3 app.py
