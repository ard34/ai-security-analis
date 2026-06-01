from modules.dns_parser import parse_a_aaaa


def test_dns_parser_keeps_only_valid_a_aaaa():
    assert parse_a_aaaa({"A": ["1.1.1.1", "bad"], "AAAA": ["::1"]}) == {"A": ["1.1.1.1"], "AAAA": ["::1"]}

