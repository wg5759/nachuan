"""Fixed production paths owned by the Installation Epoch Root.

These helpers deliberately do not consult environment variables.  The
installer and packaged gateway must resolve the same Windows Known Folder
authority even when their inherited environments differ.
"""

from __future__ import annotations

from pathlib import Path

from gateway.installation_root import default_installation_root_path


_GATEWAY_LEDGER_NAME = "gateway-paid-media-requests.db"
_CHANNEL_MEDIA_LEDGER_NAME = "channel-media-requests.db"
_PAID_MEDIA_ASSET_STORE_NAME = "paid-media-assets"


def default_gateway_ledger_path() -> Path:
    """Return the gateway ledger inside the ACL-restricted ``StateRoot``."""

    root_path = default_installation_root_path()
    return root_path.parent / _GATEWAY_LEDGER_NAME


def default_paid_media_asset_store_path() -> Path:
    """Return the private asset directory inside the protected ``StateRoot``."""

    root_path = default_installation_root_path()
    return root_path.parent / _PAID_MEDIA_ASSET_STORE_NAME


def default_channel_media_ledger_path() -> Path:
    """Return the Root-bound channel inference ledger in ``StateRoot``."""

    root_path = default_installation_root_path()
    return root_path.parent / _CHANNEL_MEDIA_LEDGER_NAME


__all__ = [
    "default_channel_media_ledger_path",
    "default_gateway_ledger_path",
    "default_paid_media_asset_store_path",
]
