from flask import Flask, Response
import time

app = Flask(__name__)

# Static camera image published for this device (same file the virtual-cameras
# producer pushes into the v4l2loopback / RTSP feed).
#
# Served straight from the file on purpose: v4l2rtspserver ships the MJPEG as
# JPEG-over-RTP (RFC 2435), which strips the JPEG Huffman tables and lets the
# receiver reconstruct with the standard ones, corrupting this image. Reading
# the RTSP therefore yields a scrambled frame no client can recover, so the
# bridge serves the intact file the cloud API expects at :9090/video.
IMAGE_PATH = "/root/img_cam0.jpeg"
HTTP_PORT = 9090
FPS = 25


def mjpeg_stream():
    """Serve the camera image as an HTTP MJPEG multipart stream."""
    frame = open(IMAGE_PATH, "rb").read()
    while True:
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
        time.sleep(1.0 / FPS)


@app.route('/video')
def video():
    return Response(mjpeg_stream(), mimetype='multipart/x-mixed-replace; boundary=frame')


if __name__ == "__main__":
    # threaded: the API opens the health-check stream and the snapshot capture
    # concurrently, so a single-threaded server would block the second client.
    app.run(host="0.0.0.0", port=HTTP_PORT, threaded=True)
