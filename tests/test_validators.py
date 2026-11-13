# tests/test_validators.py
# Automatic checks for recon/validators.py.
# Run all tests with:  py -m pytest

from recon.validators import is_public_ip, is_valid_domain


# ---------- is_valid_domain ----------

def test_normal_domain_is_valid():
    assert is_valid_domain("example.com") is True


def test_subdomain_is_valid():
    assert is_valid_domain("www.example.co.uk") is True


def test_empty_text_is_not_valid():
    assert is_valid_domain("") is False


def test_single_word_is_not_valid():
    assert is_valid_domain("localhost") is False


def test_url_with_path_is_not_valid():
    assert is_valid_domain("127.0.0.1:5000/scan/9999") is False


def test_ip_address_is_not_a_domain():
    assert is_valid_domain("192.168.1.1") is False


def test_spaces_and_symbols_are_not_valid():
    assert is_valid_domain("exa mple.com") is False
    assert is_valid_domain("example.com; rm -rf") is False


def test_label_cannot_start_with_a_hyphen():
    assert is_valid_domain("-example.com") is False


# ---------- is_public_ip (our SSRF protection) ----------

def test_public_ip_is_allowed():
    assert is_public_ip("8.8.8.8") is True


def test_localhost_is_blocked():
    assert is_public_ip("127.0.0.1") is False


def test_private_network_is_blocked():
    assert is_public_ip("192.168.1.10") is False
    assert is_public_ip("10.0.0.5") is False


def test_cloud_metadata_address_is_blocked():
    assert is_public_ip("169.254.169.254") is False


def test_ipv6_localhost_is_blocked():
    assert is_public_ip("::1") is False


def test_text_that_is_not_an_ip_is_blocked():
    assert is_public_ip("hello") is False