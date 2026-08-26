# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules
from PyInstaller.utils.hooks import collect_all
from pathlib import Path
import sys

# PyInstaller executes a spec with its launcher directory at sys.path[0].
# Bind imports used while evaluating this spec to the reviewed repository root.
_project_root = str(Path(SPECPATH).resolve())
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from orchestrator.skill_bundle import verified_skill_bundle_datas
from gateway.runtime_profile import STORE_RUNTIME_PROFILE

datas = [('config', 'config')]
datas += verified_skill_bundle_datas(Path(SPECPATH) / 'skills')
binaries = []
hiddenimports = []
hiddenimports += collect_submodules('gateway')
hiddenimports += collect_submodules('orchestrator')
# gateway.app imports the reviewed online backup module statically.  Keep an
# explicit frozen-build edge as a regression guard without collecting every
# operator-only script into the commercial runtime.
hiddenimports += [
    'cli.isolated_plugin_worker_entrypoint',
    'scripts.sqlite_backup',
    'scripts.run_weixin_ilink_bridge',
]
# lean/full 商业候选当前均为 text-first：只收文字网关、渠道桥接与多模型协作的直接运行库。
# 本地语音/LLMLingua 仍可从源码用显式 extra 评估，但在许可证和二进制闭包完成前不得冻结进发行引擎。
for _pkg in ('uvicorn', 'fastapi', 'pydantic'):
    tmp_ret = collect_all(_pkg)
    datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

# Keep Analysis.excludes a literal so independent release-boundary auditors can
# inspect it without executing the spec.  Refuse the build if the literal ever
# drifts from the versioned store policy loaded above.
_store_frozen_excludes = (
    'gateway.providers.claude_code',
    'gateway.providers.codex',
    'yt_dlp',
)
if _store_frozen_excludes != STORE_RUNTIME_PROFILE.frozen_python_excludes:
    raise RuntimeError('engine.spec store exclusions drifted from the runtime profile')


a = Analysis(
    ['engine_main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # text-first 发行闭包：保留 gateway.audio 的友好 503 接口，但排除其可选实现、
    # 本地压缩实现及所有预编译/模型依赖。相关能力只允许源码环境显式 extra 评估。
    excludes=[
        'torch', 'torchaudio', 'torchvision', 'funasr', 'modelscope', 'kaldiio', 'numpy',
        'torch_complex', 'faster_whisper', 'ctranslate2', 'sentencepiece',
        'onnxruntime', 'tokenizers',
        'gateway.asr_sensevoice', 'gateway.asr_nemotron',
        'orchestrator.compress', 'orchestrator.neural_coordinator',
        'transformers', 'tensorflow', 'matplotlib',
        # Bound above to STORE_RUNTIME_PROFILE.frozen_python_excludes.
        'gateway.providers.claude_code', 'gateway.providers.codex', 'yt_dlp',
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='engine',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    # 发布产物不做 UPX 二次改写：避免构建机 PATH 中未固定版本的 UPX 参与供应链，
    # 也减少压缩壳触发杀软启发式误报。体积优化交给安装器压缩。
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
