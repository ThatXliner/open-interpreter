"""Offline trust checks. These tests never import the interpreter or call an LLM."""

import ssl

import certifi
from packaging.version import Version


def test_certifi_includes_emudhra_remediation():
    assert Version(certifi.__version__) >= Version("2026.10.19")


def test_default_requests_bundle_excludes_compromised_root_chains():
    import requests

    context = ssl.create_default_context(cafile=requests.certs.where())
    common_names = {
        value
        for certificate in context.get_ca_certs()
        for component in certificate["subject"]
        for key, value in component
        if key == "commonName"
    }
    assert "AAA Certificate Services" not in common_names
    assert "emSign ECC Root CA - G3" not in common_names
