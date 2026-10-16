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

def _redact_key_values(text: str) -> str:
    """Redact password, pwd, secret, user, and username key-value pairs.
    Handles unquoted, single-quoted, and double-quoted keys and values (including JSON).
    Preserves surrounding quotes and separators while masking values with '****'.
    Fails closed to '<sanitized-uri>' if an ambiguous or unclosed quote follows a credential key.
    """
    if not text or not isinstance(text, str):
        return text

    # Pattern for quoted values: handles both quoted keys ("key": "val") and unquoted keys (key: "val" or key="val")
    # Group 1: key + separator + whitespace, Group 2: quote char on key if present, Group 3: quote char on value
    quoted_pattern = r'((?:(["\'])(?:password|pwd|secret|user|username)\2|\b(?:password|pwd|secret|user|username)\b)\s*[:=]\s*)(["\'])(?:\\.|(?!\3)[^\\\r\n])*\3'
    text = re.sub(quoted_pattern, r'\1\3****\3', text, flags=re.IGNORECASE)

    # Check for ambiguous or unterminated quote following a key
    ambiguous_quote = r'(?:(["\'])(?:password|pwd|secret|user|username)\1|\b(?:password|pwd|secret|user|username)\b)\s*[:=]\s*(["\'])(?!\*{4}\2)'
    if re.search(ambiguous_quote, text, flags=re.IGNORECASE):
        return "<sanitized-uri>"

    # Pattern for unquoted values
    unquoted_pattern = r'((?:(["\'])(?:password|pwd|secret|user|username)\2|\b(?:password|pwd|secret|user|username)\b)\s*[:=]\s*)([^\s&,;\'"()\]\}]+)'
    text = re.sub(unquoted_pattern, r'\1****', text, flags=re.IGNORECASE)

    return text

def _mask_uri(val: str | None) -> str:
    """Mask credentials (both username and password) in MongoDB URI or connection text for safe logging.
    Fails closed: if credentials or ambiguous connection details cannot be safely sanitized,
    returns '<sanitized-uri>'.
    """
    if not val or not isinstance(val, str):
        return "<sanitized-uri>"
    
    val = val.strip()
    if not val:
        return "<sanitized-uri>"

    try:
        # Broken/missing scheme with leading slashes (e.g. ://host or error: ://host) is malformed -> fail closed
        if re.search(r"(?:^|[\s'\":/(\[])://", val):
            return "<sanitized-uri>"

        # Check if the string contains a mongodb scheme anywhere (start of string or inside exception text)
        uri_pattern = r"(mongodb(?:\+srv)?:///*)([^/?#\s'\"\)\]]*)"
        if re.search(uri_pattern, val, flags=re.IGNORECASE):
            def sanitize_matched_uri(match):
                prefix = match.group(1)
                authority = match.group(2)

                if "@" in authority:
                    if authority.count("@") > 1:
                        # Ambiguous credentials in authority -> trigger fail-closed sentinel
                        return "<sanitized-uri-sentinel>"
                    # Replace credentials before '@' with '****:****@'
                    masked_auth = re.sub(r"^[^@]+@", "****:****@", authority)
                    clean_pref = re.sub(r":///*", "://", prefix)
                    return f"{clean_pref}{masked_auth}"
                else:
                    clean_pref = re.sub(r":///*", "://", prefix)
                    return f"{clean_pref}{authority}"

            res = re.sub(uri_pattern, sanitize_matched_uri, val, flags=re.IGNORECASE)
            if "<sanitized-uri-sentinel>" in res:
                return "<sanitized-uri>"
            
            # Redact any password/pwd/secret/user/username key-value pairs (e.g. query parameters)
            return _redact_key_values(res)

        # Handle schemeless connection text (e.g. "No servers found for user:pass@cluster")
        if "@" in val:
            if val.count("@") > 1:
                return "<sanitized-uri>"
            
            # Match [boundary][credentials]@[host[:port]]
            # Boundary includes start of string, whitespace, quotes, colons, slashes, parens
            masked, count = re.subn(
                r"(^|[\s'\":/(\[])[^@/\s'\":/(\[]*(?::[^@/\s'\"]*)?@([^\s/'\"\)\]]+)",
                r"\1****:****@\2",
                val
            )
            if count > 0:
                return _redact_key_values(masked)
            
            # If '@' was present but could not be safely sanitized, fail closed
            return "<sanitized-uri>"

        # Check for lingering password/secret/user key-value patterns
        return _redact_key_values(val)

    except Exception:
        return "<sanitized-uri>"

def _mask_error(exc: Exception | str | None) -> str:
    """Safely sanitize exception messages for diagnostic logging.
    Preserves error class name and safe details, but fails closed to a generic message
    if the error could contain unsanitized credentials or raw connection details.
    """
    if exc is None:
        return "Unknown error"
    
    exc_type = type(exc).__name__ if isinstance(exc, Exception) else "Error"
    try:
        msg = str(exc).strip()
    except Exception:
        return f"{exc_type}: <unprintable exception>"
    
    if not msg:
        return f"{exc_type}: <no details>"
    
    if "@" in msg or "://" in msg or "mongodb://" in msg.lower() or "mongodb+srv://" in msg.lower():
        masked = _mask_uri(msg)
        if masked == "<sanitized-uri>":
            return f"{exc_type}: Connection failed (details sanitized for security)"
        return f"{exc_type}: {masked}"
    
    key_pattern = r'(?:(["\'])(?:password|pwd|secret|user|username)\1|\b(?:password|pwd|secret|user|username)\b)\s*[:=]'
    if re.search(key_pattern, msg, flags=re.IGNORECASE):
        masked = _redact_key_values(msg)
        if masked == "<sanitized-uri>":
            return f"{exc_type}: Connection failed (details sanitized for security)"
        return f"{exc_type}: {masked}"
        
    return f"{exc_type}: {msg}"

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
    print(f"[Database] [!] Could not connect to MongoDB on startup: {_mask_error(exc)}")
except Exception as exc:
    print(f"[Database] [!] Unexpected error checking MongoDB on startup: {_mask_error(exc)}")
