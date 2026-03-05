class SnapshotRepository:
    def __init__(self, mongo_client):
        self.mongo_client = mongo_client

    def validate_token_and_get_user(self, token):
        token_data = self.mongo_client.vulnzoo_sec.tokens.find_one({"token": token})
        if not token_data:
            return None
        user_id = token_data.get("user_id")
        user_data = self.mongo_client.vulnzoo_sec.users.find_one({"_id": user_id})
        return user_data