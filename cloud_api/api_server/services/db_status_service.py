class DbStatusService:
    def __init__(self, mongo_client):
        self.mongo_client = mongo_client

    def get_database_status(self):
        try:
            self.mongo_client.vulnzoo_sec.command("ping")
            return "connected"
        except Exception as e:
            return "disconnected"