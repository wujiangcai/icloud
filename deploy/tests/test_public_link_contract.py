import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


class PublicLinkContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app_source = (REPO_ROOT / "icloud-code-api/platform_app.py").read_text(encoding="utf-8")
        cls.operator_source = (REPO_ROOT / "icloud-code-api/operator.js").read_text(encoding="utf-8")
        cls.viewer_source = (REPO_ROOT / "icloud-code-api/platform_viewer.html").read_text(encoding="utf-8")
        cls.readme = (REPO_ROOT / "icloud-code-api/PLATFORM_README.md").read_text(encoding="utf-8")

    def test_public_api_and_compatibility_routes_are_declared(self):
        self.assertIn('@app.get("/api/v1/public/mail/{access_token}/latest")', self.app_source)
        self.assertIn('@app.get("/public/mail/{access_token}/latest")', self.app_source)
        self.assertIn('format: str = Query("", max_length=16)', self.app_source)
        self.assertIn('"application/json" in accepted', self.app_source)
        self.assertIn('sec-fetch-dest', self.app_source)
        self.assertIn('return True', self.app_source)
        self.assertIn('"canonical_api_url"', self.app_source)

    def test_operator_output_exposes_api_url(self):
        self.assertIn('统一查看 / API 链接', self.operator_source)
        self.assertIn('data.canonical_api_url', self.operator_source)

    def test_viewer_keeps_prefix_aware_api_fetch(self):
        self.assertIn("const basePath", self.viewer_source)
        self.assertIn("basePath + '/api/v1/public/mail/'", self.viewer_source)

    def test_docs_distinguish_viewer_and_api_links(self):
        self.assertIn("GET /public/mail/<PUBLIC_TOKEN>/latest", self.readme)
        self.assertIn("GET /public/mail/<PUBLIC_TOKEN>?format=json", self.readme)
        self.assertIn("PLATFORM_CODE_MAX_AGE_SECONDS", self.readme)


if __name__ == "__main__":
    unittest.main()
