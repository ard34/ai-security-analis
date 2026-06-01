from modules.live_headers import fetch_security_headers


def test_live_headers_uses_head():
    calls = []

    class Engine:
        def http_request(self, url, method="GET"):
            calls.append(method)
            return {"url": url, "status": 200, "headers": {"Server": "x"}}

    assert fetch_security_headers("https://example.com", Engine())["status"] == 200
    assert calls == ["HEAD"]

