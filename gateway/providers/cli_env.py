"""Minimal environment for local AI CLI subprocesses.

The gateway process holds provider keys and channel tokens.  Those credentials
must never be inherited by a model-controlled CLI merely because it was
started as a child process.  Authentication for Codex/Claude Code is expected
to come from their per-user login stores under the profile directories.
"""

from __future__ import annotations

import os
from collections.abc import Mapping


_PASSTHROUGH = {
    # Windows/process bootstrap and executable discovery.
    "SYSTEMROOT",
    "WINDIR",
    "SYSTEMDRIVE",
    "COMSPEC",
    "PATH",
    "PATHEXT",
    # Per-user CLI login/config locations.
    "USERPROFILE",
    "HOME",
    "APPDATA",
    "LOCALAPPDATA",
    "CODEX_HOME",
    "CLAUDE_CONFIG_DIR",
    # Temporary files and text handling.
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS",
}


def sanitized_cli_env(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a case-insensitive allowlist, excluding every application secret.

    Keep this deliberately small.  In particular, API keys, bot tokens,
    gateway credentials and proxy URLs (which may embed credentials) are not
    inherited.  Callers that need another non-secret bootstrap variable must
    add it here deliberately and cover it with a test.
    """

    raw = os.environ if source is None else source
    allowed = {name.upper() for name in _PASSTHROUGH}
    out = {str(k): str(v) for k, v in raw.items() if str(k).upper() in allowed}
    out["NO_COLOR"] = "1"
    return out
