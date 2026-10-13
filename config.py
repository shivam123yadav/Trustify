import os
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGODB_URI") or os.getenv("MONGO_URI", "mongodb://localhost:27017/trustify")
SECRET_KEY = os.getenv("FLASK_SECRET_KEY") or os.getenv("SECRET_KEY", "dev_secret_key")
