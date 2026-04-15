from pymongo import MongoClient
import os

vuln = int(os.getenv('VULN', 0))

class UserRepository:
    def __init__(self, mongo_client):
        self.users = mongo_client.vulnzoo_sec.users

    def find_by_username(self, username):
        return self.users.find_one({"username": username})
    
    def insert_user(self, user_data):
        return self.users.insert_one(user_data)