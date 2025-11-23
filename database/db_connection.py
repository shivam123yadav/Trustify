from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()


client = MongoClient(os.getenv("MONGO_URI", ""))

db = client["trustify"]

users_collection = db["users"]        
records_collection = db["records"]    
