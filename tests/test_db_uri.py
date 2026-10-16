"""
Regression Test Suite for MongoDB URI Sanitization and Credential Masking.
Ensures zero leaks of credentials, fail-closed behavior for malformed or ambiguous URIs,
redundant-slash handling, and safe diagnostic error masking.

SAFEGUARDS:
- Uses ONLY synthetic dummy credentials.
- Test output NEVER prints synthetic dummy credentials.
- Does NOT connect to MongoDB Atlas, local database, or call Gemini.
"""

import os
import sys
import unittest

# Ensure safe offline environment for imports
os.environ["MONGODB_URI"] = "mongodb://127.0.0.1:27017/trustify"
os.environ["MONGO_URI"] = "mongodb://127.0.0.1:27017/trustify"

# Add repository root to path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from database.db_connection import _clean_uri, _mask_uri, _mask_error, _redact_key_values

DUMMY_USER = "dummy_user_audit"
DUMMY_PASS = "dummy_pass_secret456"
DUMMY_SECRET = "dummy_token_key789"

class TestMongoURISanitization(unittest.TestCase):

    def assert_no_credential_leak(self, result: str, label: str = ""):
        """Verify that neither username, password, secret, nor dummy fragments leak into output."""
        self.assertNotIn(DUMMY_USER, result, f"Leaked dummy username in {label}")
        self.assertNotIn(DUMMY_PASS, result, f"Leaked dummy password in {label}")
        self.assertNotIn(DUMMY_SECRET, result, f"Leaked dummy secret in {label}")
        self.assertNotIn("secret456", result, f"Leaked partial password in {label}")
        self.assertNotIn("user_audit", result, f"Leaked partial username in {label}")
        self.assertNotIn("key789", result, f"Leaked partial secret in {label}")

    # 1. Standard encoded credentials
    def test_standard_encoded_credentials(self):
        uri = f"mongodb+srv://{DUMMY_USER}%40company.com:{DUMMY_PASS}%23%25@cluster0.abc.mongodb.net/trustify?retryWrites=true"
        masked = _mask_uri(uri)
        self.assertEqual(masked, "mongodb+srv://****:****@cluster0.abc.mongodb.net/trustify?retryWrites=true")
        self.assert_no_credential_leak(masked, "standard encoded credentials")

    def test_standard_simple_credentials(self):
        uri = f"mongodb://{DUMMY_USER}:{DUMMY_PASS}@localhost:27017/trustify"
        masked = _mask_uri(uri)
        self.assertEqual(masked, "mongodb://****:****@localhost:27017/trustify")
        self.assert_no_credential_leak(masked, "standard simple credentials")

    # 2. Multiple unencoded @ characters (fail closed)
    def test_multiple_unencoded_at_characters(self):
        uri = f"mongodb+srv://{DUMMY_USER}@{DUMMY_USER}.com:{DUMMY_PASS}@cluster0.abc.mongodb.net/trustify"
        masked = _mask_uri(uri)
        self.assertEqual(masked, "<sanitized-uri>")
        self.assert_no_credential_leak(masked, "multiple unencoded @")

    # 3. Email-like usernames (unencoded @ fails closed)
    def test_email_like_username_fails_closed(self):
        uri = f"mongodb+srv://test.user@company.com:{DUMMY_PASS}@cluster0.abc.mongodb.net/trustify"
        masked = _mask_uri(uri)
        self.assertEqual(masked, "<sanitized-uri>")
        self.assert_no_credential_leak(masked, "email-like username")

    # 4. Password fragments containing @ (unencoded fails closed)
    def test_password_fragment_with_at_fails_closed(self):
        uri = f"mongodb+srv://{DUMMY_USER}:secret@pass@word@{DUMMY_PASS}@cluster0.abc.mongodb.net/trustify"
        masked = _mask_uri(uri)
        self.assertEqual(masked, "<sanitized-uri>")
        self.assert_no_credential_leak(masked, "password with @")

    # 5. Schemeless credential-like exception text
    def test_schemeless_credential_exception_text(self):
        exc_msg = f"ServerSelectionTimeoutError: No servers found for {DUMMY_USER}:{DUMMY_PASS}@cluster0.abc.mongodb.net:27017"
        masked = _mask_uri(exc_msg)
        self.assertEqual(masked, "ServerSelectionTimeoutError: No servers found for ****:****@cluster0.abc.mongodb.net:27017")
        self.assert_no_credential_leak(masked, "schemeless credential exception text")

    def test_schemeless_ambiguous_exception_fails_closed(self):
        exc_msg = f"OperationFailure: Failed auth for user@domain:{DUMMY_PASS}@cluster0.mongodb.net"
        masked = _mask_uri(exc_msg)
        self.assertEqual(masked, "<sanitized-uri>")
        self.assert_no_credential_leak(masked, "schemeless ambiguous exception text")

    # 5b. _mask_error helper tests
    def test_mask_error_safe_redaction(self):
        err = Exception(f"Could not connect to mongodb+srv://{DUMMY_USER}:{DUMMY_PASS}@cluster0.abc.mongodb.net/trustify: timed out")
        res = _mask_error(err)
        self.assertIn("Exception:", res)
        self.assertIn("****:****@", res)
        self.assert_no_credential_leak(res, "_mask_error with URI")

    def test_mask_error_ambiguous_fails_closed(self):
        err = Exception(f"Auth failed for user@domain:{DUMMY_PASS}@cluster0.abc.mongodb.net")
        res = _mask_error(err)
        self.assertEqual(res, "Exception: Connection failed (details sanitized for security)")
        self.assert_no_credential_leak(res, "_mask_error ambiguous")

    def test_mask_error_clean_exception(self):
        err = Exception("timed out after 5000ms")
        res = _mask_error(err)
        self.assertEqual(res, "Exception: timed out after 5000ms")

    # 6. Malformed URIs and parsing errors
    def test_malformed_uris(self):
        malformed = [
            ("not_a_uri", "not_a_uri"),
            ("mongodb://", "mongodb://"),
            ("mongodb+srv://", "mongodb+srv://"),
            ("://broken_scheme@host", "<sanitized-uri>"),
            ("mongodb://localhost:27017/db?param=hello@world", "mongodb://localhost:27017/db?param=hello@world"),
            (f"mongodb://localhost:27017/db?user={DUMMY_USER}&pwd={DUMMY_PASS}", "mongodb://localhost:27017/db?user=****&pwd=****"),
        ]
        for raw, expected in malformed:
            m = _mask_uri(raw)
            self.assertEqual(m, expected, f"Failed for input: {raw}")
            self.assert_no_credential_leak(m, f"malformed input: {raw}")

    # 7. Valid URIs with database paths and query parameters
    def test_valid_uris_preserved(self):
        v1 = "mongodb://localhost:27017/trustify?authSource=admin"
        self.assertEqual(_mask_uri(v1), v1)

        v2 = "mongodb+srv://cluster0.abc.mongodb.net/trustify?retryWrites=true&w=majority"
        self.assertEqual(_mask_uri(v2), v2)

        v3 = f"mongodb+srv:////admin_user:{DUMMY_PASS}@cluster0.abc.mongodb.net/trustify?retryWrites=true"
        m3 = _mask_uri(v3)
        self.assertEqual(m3, "mongodb+srv://****:****@cluster0.abc.mongodb.net/trustify?retryWrites=true")
        self.assert_no_credential_leak(m3, "redundant slashes with query parameters")

    # 8. Empty and non-string inputs
    def test_empty_and_non_string_inputs(self):
        for invalid in [None, "", "   ", 12345, [], {}, object()]:
            self.assertEqual(_mask_uri(invalid), "<sanitized-uri>")
            self.assertEqual(_clean_uri(invalid), "")

    # 9. _clean_uri redundant slash normalization
    def test_clean_uri_redundant_slashes(self):
        cases = [
            ("mongodb+srv:////cluster0.abc.mongodb.net", "mongodb+srv://cluster0.abc.mongodb.net"),
            ("mongodb+srv:///cluster0.abc.mongodb.net", "mongodb+srv://cluster0.abc.mongodb.net"),
            ("mongodb://///localhost:27017", "mongodb://localhost:27017"),
            ('"mongodb+srv:////cluster0.abc.mongodb.net"', "mongodb+srv://cluster0.abc.mongodb.net"),
            ("'mongodb+srv:////cluster0.abc.mongodb.net'", "mongodb+srv://cluster0.abc.mongodb.net"),
            (f"mongodb+srv://{DUMMY_USER}@domain.com:{DUMMY_PASS}@cluster0.abc.mongodb.net", f"mongodb+srv://{DUMMY_USER}@domain.com:{DUMMY_PASS}@cluster0.abc.mongodb.net"),
        ]
        for raw, expected in cases:
            self.assertEqual(_clean_uri(raw), expected)

    # 10. Key-value redaction: Quoted double and single quote values
    def test_quoted_double_quotes_redaction(self):
        cases = [
            (f'password="{DUMMY_PASS}"', 'password="****"'),
            (f'pwd="{DUMMY_PASS}"', 'pwd="****"'),
            (f'secret="{DUMMY_SECRET}"', 'secret="****"'),
            (f'user="{DUMMY_USER}"', 'user="****"'),
            (f'username="{DUMMY_USER}"', 'username="****"'),
            (f'password = "{DUMMY_PASS}"', 'password = "****"'),
            (f'secret : "{DUMMY_SECRET}"', 'secret : "****"'),
        ]
        for raw, expected in cases:
            m = _mask_uri(raw)
            self.assertEqual(m, expected, f"Failed for double-quoted: {raw}")
            self.assert_no_credential_leak(m, "double-quoted key-value")

    def test_quoted_single_quotes_redaction(self):
        cases = [
            (f"password='{DUMMY_PASS}'", "password='****'"),
            (f"pwd='{DUMMY_PASS}'", "pwd='****'"),
            (f"secret='{DUMMY_SECRET}'", "secret='****'"),
            (f"user='{DUMMY_USER}'", "user='****'"),
            (f"username='{DUMMY_USER}'", "username='****'"),
            (f"password = '{DUMMY_PASS}'", "password = '****'"),
            (f"secret : '{DUMMY_SECRET}'", "secret : '****'"),
        ]
        for raw, expected in cases:
            m = _mask_uri(raw)
            self.assertEqual(m, expected, f"Failed for single-quoted: {raw}")
            self.assert_no_credential_leak(m, "single-quoted key-value")

    # 11. Quoted secrets in MongoDB query strings
    def test_quoted_secrets_in_mongodb_query_strings(self):
        uris = [
            (f'mongodb://localhost:27017/?user="{DUMMY_USER}"&password="{DUMMY_PASS}"',
             'mongodb://localhost:27017/?user="****"&password="****"'),
            (f"mongodb://localhost:27017/?user='{DUMMY_USER}'&password='{DUMMY_PASS}'",
             "mongodb://localhost:27017/?user='****'&password='****'"),
            (f'mongodb+srv://cluster0.abc.mongodb.net/trustify?authSource=admin&secret="{DUMMY_SECRET}"&pwd="{DUMMY_PASS}"',
             'mongodb+srv://cluster0.abc.mongodb.net/trustify?authSource=admin&secret="****"&pwd="****"'),
        ]
        for raw, expected in uris:
            m = _mask_uri(raw)
            self.assertEqual(m, expected)
            self.assert_no_credential_leak(m, "query string with quotes")

    # 12. Quoted and unquoted key-value pairs in exception messages
    def test_exception_messages_quoted_and_unquoted(self):
        exceptions = [
            (Exception(f'Authentication failed: user="{DUMMY_USER}", password="{DUMMY_PASS}"'),
             'Exception: Authentication failed: user="****", password="****"'),
            (Exception(f"Connection rejected for username='{DUMMY_USER}', secret='{DUMMY_SECRET}'"),
             "Exception: Connection rejected for username='****', secret='****'"),
            (Exception(f"Handshake error with pwd={DUMMY_PASS} and user={DUMMY_USER}"),
             "Exception: Handshake error with pwd=**** and user=****"),
            (Exception(f"Failed auth for user={DUMMY_USER} with password={DUMMY_PASS}"),
             "Exception: Failed auth for user=**** with password=****"),
        ]
        for err, expected in exceptions:
            m = _mask_error(err)
            self.assertEqual(m, expected)
            self.assert_no_credential_leak(m, "exception with quoted/unquoted key-values")

    # 13. Multiple secrets in one message with punctuation, whitespace, and separators
    def test_multiple_secrets_punctuation_and_whitespace(self):
        cases = [
            (f"options: &password={DUMMY_PASS}&user={DUMMY_USER}",
             "options: &password=****&user=****"),
            (f"options: &password='{DUMMY_PASS}'&user='{DUMMY_USER}'",
             "options: &password='****'&user='****'"),
            (f"config: {{password: '{DUMMY_PASS}', user: '{DUMMY_USER}'}}",
             "config: {password: '****', user: '****'}"),
            (f"config: {{password: \"{DUMMY_PASS}\", secret: \"{DUMMY_SECRET}\"}}",
             'config: {password: "****", secret: "****"}'),
            (f"user={DUMMY_USER}; password={DUMMY_PASS}; secret={DUMMY_SECRET};",
             "user=****; password=****; secret=****;"),
            (f"param1=1, password = \"{DUMMY_PASS}\" , param2=2",
             'param1=1, password = "****" , param2=2'),
        ]
        for raw, expected in cases:
            m = _mask_uri(raw)
            self.assertEqual(m, expected)
            self.assert_no_credential_leak(m, "multiple secrets with separators")

    # 14. Ambiguous and unterminated quote fail-closed behavior
    def test_ambiguous_unterminated_quote_fails_closed(self):
        ambiguous_cases = [
            f'password="{DUMMY_PASS}',
            f"user='{DUMMY_USER}",
            f'mongodb://localhost:27017/?password="{DUMMY_PASS}',
        ]
        for raw in ambiguous_cases:
            m = _mask_uri(raw)
            self.assertEqual(m, "<sanitized-uri>")
            self.assert_no_credential_leak(m, "unterminated quote in _mask_uri")

            err_m = _mask_error(Exception(raw))
            self.assertEqual(err_m, "Exception: Connection failed (details sanitized for security)")
            self.assert_no_credential_leak(err_m, "unterminated quote in _mask_error")

    # 15. Exceptions whose __str__() raises an error
    def test_unprintable_exception_handled_safely(self):
        class SyntheticUnprintableException(Exception):
            def __init__(self, sensitive_val):
                self.sensitive_val = sensitive_val
            def __str__(self):
                raise RuntimeError(f"Internal crash with sensitive payload: {self.sensitive_val}")

        broken_exc = SyntheticUnprintableException(DUMMY_SECRET)
        res = _mask_error(broken_exc)
        self.assertEqual(res, "SyntheticUnprintableException: <unprintable exception>")
        self.assert_no_credential_leak(res, "unprintable exception")

    # 16. Bare malformed ://host fragment in error text fails closed
    def test_bare_malformed_scheme_fragment_fails_closed(self):
        cases = [
            Exception("://broken_host:27017"),
            Exception(f"Failed connecting to ://broken_host:27017 with secret={DUMMY_SECRET}"),
            Exception(f"Invalid URI format: ://cluster0.abc.mongodb.net"),
        ]
        for err in cases:
            res = _mask_error(err)
            self.assertEqual(res, "Exception: Connection failed (details sanitized for security)")
            self.assert_no_credential_leak(res, "bare malformed ://host fragment")

    # 17. JSON-style quoted keys redaction
    def test_json_quoted_keys_redaction(self):
        cases = [
            (f'{{"password": "{DUMMY_PASS}", "username": "{DUMMY_USER}"}}',
             '{"password": "****", "username": "****"}'),
            (f"{{'secret': '{DUMMY_SECRET}', 'user': '{DUMMY_USER}'}}",
             "{'secret': '****', 'user': '****'}"),
            (f'OperationFailure: {{"ok": 0.0, "errmsg": "auth failed", "password": "{DUMMY_PASS}"}}',
             'OperationFailure: {"ok": 0.0, "errmsg": "auth failed", "password": "****"}'),
        ]
        for raw, expected in cases:
            m = _mask_uri(raw)
            self.assertEqual(m, expected)
            self.assert_no_credential_leak(m, "json quoted keys in _mask_uri")

            err_m = _mask_error(Exception(raw))
            self.assertEqual(err_m, f"Exception: {expected}")
            self.assert_no_credential_leak(err_m, "json quoted keys in _mask_error")

        # Unterminated JSON quote fails closed
        unclosed = f'{{"password": "{DUMMY_PASS}'
        self.assertEqual(_mask_uri(unclosed), "<sanitized-uri>")
        self.assertEqual(_mask_error(Exception(unclosed)), "Exception: Connection failed (details sanitized for security)")
        self.assert_no_credential_leak(_mask_uri(unclosed), "unterminated json in _mask_uri")
        self.assert_no_credential_leak(_mask_error(Exception(unclosed)), "unterminated json in _mask_error")

if __name__ == "__main__":
    unittest.main()
