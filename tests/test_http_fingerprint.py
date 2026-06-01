from modules.http_fingerprint import fingerprint_http


def test_http_fingerprint_uses_headers_only():
    class Engine:
        def http_request(self, url, method="GET"):
            return {"status": 200, "headers": {"Server": "nginx", "Content-Type": "text/html"}}

    assert fingerprint_http("https://example.com", Engine())["server"] == "nginx"

