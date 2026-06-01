from modules.robots_sitemap import fetch_robots_and_sitemap


def test_robots_sitemap_fetches_only_two_paths():
    urls = []

    class Engine:
        def http_request(self, url, method="GET"):
            urls.append(url)
            return {"status": 200, "body": "ok"}

    result = fetch_robots_and_sitemap("https://example.com", Engine())
    assert sorted(result) == ["/robots.txt", "/sitemap.xml"]
    assert len(urls) == 2

