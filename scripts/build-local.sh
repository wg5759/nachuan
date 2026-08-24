#!/usr/bin/env bash
# Experimental macOS/Linux local candidate build. Official releases remain Windows-only.
# Usage: bash scripts/build-local.sh [lean|full]   (default: lean)
set -euo pipefail

if [ "${NACHUAN_EXPERIMENTAL_CROSS_PLATFORM:-0}" != "1" ]; then
  echo "Blocked: official releases are Windows-only until native secret-store adapters are verified."
  echo "For non-production adapter development only, set NACHUAN_EXPERIMENTAL_CROSS_PLATFORM=1."
  exit 2
fi

WANT="${1:-lean}"
case "$WANT" in
  lean|full) ;;
  *) echo "expected argument: lean / full"; exit 1 ;;
esac

EXPECTED_UV='0.11.3'
EXPECTED_PYTHON='3.12.9'
EXPECTED_NODE='24.14.0'
EXPECTED_NPM='11.12.1'
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$ROOT"
test -f "$ROOT/pyproject.toml" && test -f "$ROOT/desktop/package.json" || {
  echo "Refusing to build outside the repository root: $ROOT"
  exit 1
}

# Close ambient code-execution and binary-override inputs before invoking any
# build tool. Dependency lifecycle scripts remain disabled; reviewed project
# scripts are invoked explicitly after the locked install.
unset NODE_OPTIONS NODE_PATH NODE_EXTRA_CA_CERTS NODE_TLS_REJECT_UNAUTHORIZED
unset ELECTRON_RUN_AS_NODE ELECTRON_MIRROR ELECTRON_BUILDER_BINARIES_MIRROR
unset ELECTRON_CUSTOM_DIR ELECTRON_CUSTOM_FILENAME ELECTRON_CUSTOM_VERSION
unset ELECTRON_OVERRIDE_DIST_PATH ESBUILD_BINARY_PATH
unset npm_config_electron_mirror npm_config_electron_custom_dir
unset npm_config_electron_custom_filename npm_config_electron_custom_version
unset npm_config_node_options
unset PYTHONHOME PYTHONPATH PYTHONSTARTUP PYTHONUSERBASE
TRUSTED_COMMAND_SHELL="$(type -P sh || true)"
test -n "$TRUSTED_COMMAND_SHELL" && test -f "$TRUSTED_COMMAND_SHELL" && test -x "$TRUSTED_COMMAND_SHELL" || {
  echo 'A trusted system sh is required for reviewed npm project scripts' >&2
  exit 1
}
export npm_config_script_shell="$TRUSTED_COMMAND_SHELL"

resolve_tool() {
  local name="$1" candidate directory
  candidate="$(type -P "$name" || true)"
  test -n "$candidate" || { echo "Required tool is missing: $name" >&2; return 1; }
  directory="$(cd "$(dirname "$candidate")" && pwd -P)"
  candidate="$directory/$(basename "$candidate")"
  test -f "$candidate" && test -x "$candidate" || {
    echo "Tool is not a regular executable: $candidate" >&2
    return 1
  }
  printf '%s\n' "$candidate"
}

# Resolve once and invoke by absolute path. Do not prepend or otherwise mutate PATH.
UV_BIN="$(resolve_tool uv)"
NODE_BIN="$(resolve_tool node)"
NPM_BIN="$(resolve_tool npm)"
UV_ACTUAL="$("$UV_BIN" --version | awk '{print $2}')"
test "$UV_ACTUAL" = "$EXPECTED_UV" || { echo "uv $EXPECTED_UV is required"; exit 1; }
test "$("$NODE_BIN" --version)" = "v$EXPECTED_NODE" || { echo "Node.js $EXPECTED_NODE is required"; exit 1; }
test "$("$NPM_BIN" --version)" = "$EXPECTED_NPM" || { echo "npm $EXPECTED_NPM is required"; exit 1; }

export UV_PYTHON="$EXPECTED_PYTHON"
export npm_config_registry='https://registry.npmjs.org'
export GH_OWNER="${GH_OWNER:-wg5759}"
export GH_REPO="${GH_REPO:-nachuan}"

echo '==> 1/5 Exact Python environment and tests'
"$UV_BIN" python install "$EXPECTED_PYTHON"
if [ -n "${UV_MIRROR:-}" ]; then
  UV_DEFAULT_INDEX="$UV_MIRROR" UV_INDEX_URL="$UV_MIRROR" \
    "$UV_BIN" sync --locked --extra dev --python "$EXPECTED_PYTHON"
else
  "$UV_BIN" sync --locked --extra dev --python "$EXPECTED_PYTHON"
fi
test "$("$UV_BIN" run python -c 'import platform; print(platform.python_version())')" = "$EXPECTED_PYTHON" || {
  echo 'Unexpected Python version'; exit 1;
}
"$UV_BIN" run pytest -q -p no:cacheprovider

echo '==> 2/5 Build the engine binary'
BUILD_DIR="$ROOT/build"
ENGINE_FILE="$ROOT/dist/engine"
case "$BUILD_DIR" in "$ROOT"/*) ;; *) echo 'Unsafe build cleanup path'; exit 1 ;; esac
rm -rf -- "$BUILD_DIR"
rm -f -- "$ENGINE_FILE" "$ROOT/dist/engine.exe"
"$UV_BIN" run pyinstaller engine.spec --noconfirm --distpath dist --workpath build

echo '==> 3/5 Prepare reviewed local-runtime inputs'
case "$(uname -s)" in
  Darwin|Linux) ;;
  *) echo 'Windows must use scripts/build-local.ps1'; exit 1 ;;
esac
if [ "$WANT" = 'lean' ]; then
  unset LLAMA_SRC MODELS_SRC
  echo '    lean: cloud/BYOK only; local runtime intentionally excluded'
else
  : "${MODELS_SRC:?MODELS_SRC must be a reviewed directory containing GGUF files for full}"
  test -d "$MODELS_SRC" || { echo 'MODELS_SRC is not a directory'; exit 1; }
  find "$MODELS_SRC" -maxdepth 1 -type f -iname '*.gguf' -print -quit | grep -q . || {
    echo 'MODELS_SRC contains no GGUF; refusing a misleading full package'; exit 1;
  }
  : "${LLAMA_URL:?LLAMA_URL must point to a pinned official llama.cpp asset}"
  : "${LLAMA_SHA256:?LLAMA_SHA256 must be the reviewed digest for LLAMA_URL}"
  : "${NACHUAN_FULL_RUNTIME_TRUST_MANIFEST:?trusted full runtime manifest is required}"
  test -f "$NACHUAN_FULL_RUNTIME_TRUST_MANIFEST" || {
    echo 'NACHUAN_FULL_RUNTIME_TRUST_MANIFEST must be a regular file'; exit 1;
  }
  case "$LLAMA_URL" in
    https://github.com/ggml-org/llama.cpp/releases/download/*) ;;
    *) echo 'LLAMA_URL must be official github.com llama.cpp release HTTPS'; exit 1 ;;
  esac
  printf '%s' "$LLAMA_SHA256" | grep -Eq '^[0-9a-fA-F]{64}$' || {
    echo 'LLAMA_SHA256 must be a 64-character hex digest'; exit 1;
  }
  curl --fail --location --proto '=https' --tlsv1.2 -o "$ROOT/dist/_llama.tgz" "$LLAMA_URL"
  printf '%s  %s\n' "$LLAMA_SHA256" "$ROOT/dist/_llama.tgz" | sha256sum --check -
  LLAMA_DIR="$ROOT/dist/_llama_dl"
  case "$LLAMA_DIR" in "$ROOT"/*) ;; *) echo 'Unsafe llama cleanup path'; exit 1 ;; esac
  rm -rf -- "$LLAMA_DIR"
  mkdir -p "$LLAMA_DIR"
  (cd "$LLAMA_DIR" && tar -xzf "$ROOT/dist/_llama.tgz")
  server="$(find "$LLAMA_DIR" -maxdepth 4 -type f \( -name 'llama-server' -o -name 'llama-server.exe' \) -print -quit)"
  test -n "$server" || { echo 'verified llama archive contains no llama-server'; exit 1; }
  export LLAMA_SRC="$(dirname "$server")"
fi

echo '==> 4/5 Install locked desktop dependencies and build'
cd "$ROOT/desktop"
"$NODE_BIN" scripts/prepare-pack.mjs "$WANT"
"$NPM_BIN" ci --ignore-scripts --no-audit --no-fund --registry 'https://registry.npmjs.org'
"$NODE_BIN" scripts/electron-runtime-policy.mjs prepare
"$NODE_BIN" scripts/license-stage.mjs prepare
"$NODE_BIN" scripts/write-engine-digest.mjs
# Experimental local candidates must never inherit a stale release trust root.
unset NACHUAN_UPDATE_TIER
"$NODE_BIN" scripts/write-update-trust.mjs
"$NPM_BIN" run typecheck
"$NPM_BIN" test
"$NPM_BIN" run build

echo "==> 5/5 Package and verify $WANT from an empty release directory"
export DMX_VARIANT="$WANT"
"$NODE_BIN" scripts/release-output.mjs clean
"$NPM_BIN" exec --offline -- electron-builder --publish never
"$NODE_BIN" scripts/release-output.mjs prune "$WANT"
"$NODE_BIN" scripts/_verify_pack.mjs "$WANT"

echo '[OK] Verified experimental local candidate is in desktop/release (not production-approved).'
