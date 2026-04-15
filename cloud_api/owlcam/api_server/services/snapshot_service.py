from flask import Response, request
from cloud_api.owlcam.api_server.repositories.snapshot_repository import SnapshotRepository
import cv2
import numpy as np

class SnapshotService:
    def __init__(self, snapshot_repository, mongo_client, cameras_urls):
        self.repo = snapshot_repository
        self.cameras_urls = cameras_urls

    def get_snapshot(self, token, camera_url):
        user = self.repo.validate_token_and_get_user(token)
        if not user:
            raise Exception("Invalid token or user not found")

        if not camera_url:
            raise Exception("Camera not found")

        cap = cv2.VideoCapture(camera_url)
        if not cap.isOpened():
            raise Exception("Could not open video stream")
        
        ret, frame = cap.read()
        cap.release()

        if not ret:
            raise Exception("Failed to capture frame")
        ret, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 90])
        if not ret:
            raise Exception("Failed to encode frame")
        return Response(buffer.tobytes(), mimetype='image/jpeg')


    