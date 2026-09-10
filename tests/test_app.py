import io
import os
import tempfile
import unittest

import auth
from app import app

class TestBatchUpload(unittest.TestCase):
    def setUp(self):
        app.config["SECRET_KEY"] = "test-secret"
        app.config["WEB_ADMIN_TOKEN"] = "test-admin-token"
        self.client = app.test_client()

        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["csrf_token"] = "test-csrf-token"

    def test_batch_upload_rejects_more_than_max_files(self):
        files = [
            (
                io.BytesIO(b"From: test@example.com\r\n\r\nTest"),
                f"test_{i}.eml"
            )
            for i in range(51)
        ]

        response = self.client.post(
            "/batch/analyze",
            data={
                "files": files,
                "csrf_token": "test-csrf-token",
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(
            b"Too many files",
            response.data
        )

    def test_empty_permissions_remain_empty(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_db = auth.DATABASE_PATH
            auth.DATABASE_PATH = os.path.join(temp_dir, "test.db")

            try:
                result = auth.create_api_key(
                    user_id="test-user",
                    name="No Permissions",
                    permissions=[]
                )

                user = auth.validate_api_key(result["api_key"])

                self.assertIsNotNone(user)
                self.assertEqual(user["permissions"], [])
            finally:
                auth.DATABASE_PATH = original_db

if __name__ == "__main__":
    unittest.main()