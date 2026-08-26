from __future__ import annotations

from scripts.installed_model_onboarding_acceptance import _loopback_url


def test_installed_acceptance_allows_the_product_loopback_host() -> None:
    assert (
        _loopback_url("http://127.77.77.77:8080", "gateway_url")
        == "http://127.77.77.77:8080"
    )
