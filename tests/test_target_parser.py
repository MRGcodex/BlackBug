"""Target parser tests."""
import pytest
from modules.target_parser import parse_target


def test_ip():
    r = parse_target("192.168.1.1")
    assert r["type"] == "ip"
    assert r["host"] == "192.168.1.1"


def test_cidr():
    r = parse_target("192.168.1.0/24")
    assert r["type"] == "cidr"


def test_domain():
    r = parse_target("example.com")
    assert r["type"] == "domain"
    assert r["url"] == "https://example.com"


def test_url():
    r = parse_target("https://target.com:8443/path")
    assert r["type"] == "url"
    assert r["port"] == 8443


def test_invalid():
    with pytest.raises(ValueError):
        parse_target("")
    with pytest.raises(ValueError):
        parse_target("not_a_valid_target_@#$")
