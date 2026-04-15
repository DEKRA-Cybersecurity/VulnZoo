FROM python:3.11-slim

WORKDIR /c2server

# Instalar solo dependencias necesarias (sin OpenCV)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libffi-dev \
        libssl-dev \
        python3-dev \
        vim \
        net-tools \
    && rm -rf /var/lib/apt/lists/*

# Instalar dependencias de Python
COPY requirements.txt .
RUN pip install --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código del servidor C2
COPY ./ /c2server

ENV C2_PORT=4999
ENV MONGO_URI=mongodb://mongo:27017/
ENV PANEL_PASSWORD=letstechin

EXPOSE 4999

CMD python3 c2_server.py
