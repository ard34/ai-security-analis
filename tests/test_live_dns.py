from modules.live_dns import resolve_a_aaaa


def test_live_dns_uses_engine():
    class Engine:
        def dns_a_aaaa(self, host):
            return {"A": ["93.184.216.34"], "AAAA": ["::1"], "MX": ["ignored"]}

    assert resolve_a_aaaa("example.com", Engine()) == {"A": ["93.184.216.34"], "AAAA": ["::1"]}

