import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
BRIDGE_PATH = ROOT / "python" / "hme_bridge.py"
spec = importlib.util.spec_from_file_location("platform_hme_bridge", BRIDGE_PATH)
bridge = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bridge)


class PlatformHmeBridgeTests(unittest.TestCase):
    def test_full_curl_uses_the_hme_request_shard_and_cookie(self):
        fixture = r"""
curl --url 'https://www.icloud.com/icloudplus/' -b 'X-APPLE-WEBAUTH-USER=first' -H 'accept: text/html' ;
curl --url 'https://p188-maildomainws.icloud.com/v2/hme/list?clientBuildNumber=2628Build27&clientMasteringNumber=2628Build27&clientId=11111111-1111-1111-1111-111111111111&dsid=123456789' -b 'X-APPLE-WEBAUTH-USER=latest' ;
"""

        cookie, region, host = bridge.parse_cookie_context(fixture, "auto")

        self.assertEqual(cookie, "X-APPLE-WEBAUTH-USER=latest")
        self.assertEqual(region, "global")
        self.assertEqual(host, "p188-maildomainws.icloud.com")
        self.assertEqual(
            bridge._extract_request_params(fixture, host)["clientBuildNumber"],
            "2628Build27",
        )

    def test_default_shard_can_recover_from_user_partition(self):
        self.assertEqual(
            bridge._candidate_maildomain_hosts(
                "global", "p68-maildomainws.icloud.com", "188"
            ),
            ["p188-maildomainws.icloud.com", "p68-maildomainws.icloud.com"],
        )

    def test_raw_cookie_does_not_invent_a_maildomain_host(self):
        cookie, region, host = bridge.parse_cookie_context(
            "X-APPLE-WEBAUTH-USER=redacted; X-APPLE-WEBAUTH-TOKEN=redacted",
            "auto",
        )
        self.assertIn("X-APPLE-WEBAUTH-USER", cookie)
        self.assertEqual(region, "auto")
        self.assertEqual(host, "")


if __name__ == "__main__":
    unittest.main()
