from flask import Flask, Response
import subprocess
import threading
import time

app = Flask(__name__)

# Frame compartido entre el hilo de ffmpeg y los clientes HTTP
latest_frame = None
frame_lock = threading.Lock()


def ffmpeg_reader():
    """Hilo en background: ejecuta ffmpeg UNA vez y extrae frames JPEG continuamente."""
    global latest_frame
    cmd = [
        "ffmpeg",
        "-re",
        "-stream_loop", "-1",  # Repite el video infinitamente
        "-i", "dancing_cat.mp4",
        "-f", "mjpeg",
        "-q:v", "5",
        "pipe:1"
    ]
    while True:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        buf = b''
        try:
            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    break
                buf += chunk
                # Buscar frames JPEG completos (SOI: 0xFFD8, EOI: 0xFFD9)
                while True:
                    soi = buf.find(b'\xff\xd8')
                    if soi == -1:
                        buf = b''
                        break
                    eoi = buf.find(b'\xff\xd9', soi + 2)
                    if eoi == -1:
                        # Frame incompleto, esperar más datos
                        buf = buf[soi:]
                        break
                    # Frame JPEG completo encontrado
                    frame = buf[soi:eoi + 2]
                    buf = buf[eoi + 2:]
                    with frame_lock:
                        latest_frame = frame
        except Exception:
            pass
        finally:
            process.terminate()
            process.wait()
        # Si ffmpeg muere, reiniciar tras breve pausa
        time.sleep(1)


def mjpeg_stream():
    """Generador que sirve el frame más reciente como MJPEG multipart."""
    while True:
        with frame_lock:
            frame = latest_frame
        if frame is not None:
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
        time.sleep(1.0 / 30)  # ~30 fps


@app.route('/video')
def video():
    return Response(mjpeg_stream(), mimetype='multipart/x-mixed-replace; boundary=frame')


if __name__ == "__main__":
    # Iniciar lector ffmpeg en hilo de fondo
    reader_thread = threading.Thread(target=ffmpeg_reader, daemon=True)
    reader_thread.start()
    # Esperar a que haya al menos un frame disponible
    time.sleep(2)
    app.run(host="0.0.0.0", port=9090)
