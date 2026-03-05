FROM python:3.11-slim

# Instala ffmpeg y Flask
RUN apt-get update && \
	apt-get install -y --no-install-recommends ffmpeg vim net-tools && \
	pip install flask && \
	rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copia el script y el video de ejemplo (debes añadirlos en la carpeta camera_sim)
COPY camera_stream.py .
COPY dancing_cat.mp4 .

EXPOSE 9090

CMD ["python", "camera_stream.py"]
