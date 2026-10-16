from pymongo import MongoClient
from pymongo.errors import PyMongoError
from urllib.parse import urlparse
import os
import re
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("trustify.database")

def _clean_uri(val: str | None) -> str:
    """Strip whitespace, accidental quotes, and redundant slashes from URI string."""
    if not val or not isinstance(val, str):
        return ""
    val = val.strip()
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        val = val[1:-1].strip()
    # Normalize accidental redundant slashes after protocol scheme (e.g. mongodb+srv://// -> mongodb+srv://)
    val = re.sub(r"^(mongodb(?:\+srv)?://)/+", r"\1", val, flags=re.IGNORECASE)
    return val

def _mask_uri(raw_uri: str) -> str:
    """Mask credentials (both username and password) in MongoDB URI for safe logging."""
    if not raw_uri or not isinstance(raw_uri, str):
        return "<sanitized-uri>"
    try:
        # Safe regex masking ensures credentials (username and password) are never leaked even if URI is malformed
        masked = re.sub(r":///*[^@/]+@", r"://****:****@", raw_uri)
        if masked != raw_uri:
            return masked
        parsed = urlparse(raw_uri)
        if parsed.password or parsed.username:
            masked_netloc = f"****:****@{parsed.hostname}"
            if parsed.port:
                masked_netloc += f":{parsed.port}"
            return parsed._replace(netloc=masked_netloc).geturl()
        return raw_uri
    except Exception:
        return "<sanitized-uri>"

raw_mongodb = _clean_uri(os.getenv("MONGODB_URI"))
raw_mongo = _clean_uri(os.getenv("MONGO_URI"))

# Intelligent selection:
# If either variable points to a remote cluster (Atlas or remote host), prioritize it over localhost.
if raw_mongodb and "localhost" not in raw_mongodb and "127.0.0.1" not in raw_mongodb:
    mongo_uri = raw_mongodb
elif raw_mongo and "localhost" not in raw_mongo and "127.0.0.1" not in raw_mongo:
    mongo_uri = raw_mongo
else:
    mongo_uri = raw_mongodb or raw_mongo or "mongodb://localhost:27017/"

# Configure connection parameters
client_kwargs = {
    "serverSelectionTimeoutMS": 5000,
    "connectTimeoutMS": 5000,
}

# Attach certifi CA bundle for Atlas TLS handshakes if TLS/SRV is used
is_tls = "mongodb+srv://" in mongo_uri or "ssl=true" in mongo_uri.lower() or "tls=true" in mongo_uri.lower()
if is_tls:
    try:
        import certifi
        client_kwargs["tlsCAFile"] = certifi.where()
    except Exception:
        pass

# Initialize MongoClient
client = MongoClient(mongo_uri, **client_kwargs)

# Select the trustify database
db = client["trustify"]

users_collection = db["users"]
records_collection = db["records"]
rate_limits_collection = db["rate_limits"]

# Diagnostic ping on startup to verify connectivity and assist debugging
try:
    print(f"[Database] Connecting to: {_mask_uri(mongo_uri)}")
    client.admin.command("ping")
    print("[Database] [OK] MongoDB connection established successfully.")
except PyMongoError as exc:
    print(f"[Database] [!] Could not connect to MongoDB on startup: {_mask_uri(str(exc))}")
except Exception as exc:
    print(f"[Database] [!] Unexpected error checking MongoDB on startup: {_mask_uri(str(exc))}")
