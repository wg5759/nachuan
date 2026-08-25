"""pip 打包合同测试（ADR-0013：主分发形态 = pip 包 + nachuan CLI + 本地 Web UI）。

验证 pyproject.toml 从应用项目转为可构建包：console script 指向真实可导入入口、
包闭集覆盖运行所需模块、运行期数据文件（catalog/store profile）随包携带。
"""

from __future__ import annotations

import json
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"


def _pyproject() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


class TestBuildSystem:
    def test_build_backend_declared(self):
        build = _pyproject()["build-system"]
        assert "setuptools" in " ".join(build["requires"])
        assert build["build-backend"] == "setuptools.build_meta"

    def test_uv_no_longer_app_only(self):
        uv = _pyproject().get("tool", {}).get("uv", {})
        assert uv.get("package") is not False, "tool.uv package=false 与 pip 分发矛盾"


    def test_sdist_contains_the_clean_wheel_build_command(self):
        """An sdist must be able to import the command that closes wheel inputs."""

        temp_root = ROOT / ".ptmp"
        temp_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="pip-sdist-", dir=temp_root) as temp:
            output = Path(temp) / "sdist"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "build",
                    "--sdist",
                    "--no-isolation",
                    "--outdir",
                    str(output),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
                check=False,
            )
            assert result.returncode == 0, result.stderr[-4000:]
            archives = list(output.glob("*.tar.gz"))
            assert len(archives) == 1, archives
            with tarfile.open(archives[0], "r:gz") as archive:
                archive_members = archive.getmembers()
                assert all(
                    not Path(member.name).is_absolute()
                    and ".." not in Path(member.name).parts
                    for member in archive_members
                )
                members = {
                    Path(member.name).as_posix().split("/", 1)[-1]
                    for member in archive_members
                    if "/" in member.name
                }
                source_root = Path(temp) / "source"
                archive.extractall(source_root, filter="data")
            assert "packaging_build.py" in members
            extracted = [path for path in source_root.iterdir() if path.is_dir()]
            assert len(extracted) == 1, extracted

            wheel_dir = Path(temp) / "wheel-from-sdist"
            rebuilt = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "build",
                    "--wheel",
                    "--no-isolation",
                    "--outdir",
                    str(wheel_dir),
                    str(extracted[0]),
                ],
                cwd=temp,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
                check=False,
            )
            assert rebuilt.returncode == 0, rebuilt.stderr[-4000:]
            assert len(list(wheel_dir.glob("*.whl"))) == 1


class TestConsoleScripts:
    def test_nachuan_cli_entrypoint(self):
        scripts = _pyproject()["project"]["scripts"]
        assert scripts["nachuan"] == "cli.nachuan:main"

    def test_engine_entrypoint(self):
        scripts = _pyproject()["project"]["scripts"]
        assert scripts["nachuan-engine"] == "cli.engine_entrypoint:main"

    def test_entrypoints_are_importable_and_callable(self):
        from cli.nachuan import main as cli_main
        from gateway.app import main as engine_main

        assert callable(cli_main)
        assert callable(engine_main)


class TestPackageClosure:
    def test_runtime_packages_listed(self):
        packages = set(_pyproject()["tool"]["setuptools"]["packages"])
        required = {
            "gateway",
            "gateway.providers",
            "gateway.web_ui",
            "gateway.web_ui.assets",
            "orchestrator",
            "orchestrator.workflows",
            "bridge",
            "cli",
            "scripts",
            "config",
        }
        assert required <= packages, required - packages

    def test_runtime_data_files_ship(self):
        # catalog 与 store runtime profile 由 PROJECT_ROOT/config 相对路径读取；
        # 打包后 PROJECT_ROOT 是 site-packages，config 必须作为包随轮携带。
        assert (ROOT / "config" / "__init__.py").is_file()
        assert (ROOT / "config" / "models.yaml").is_file()
        assert (ROOT / "config" / "store-runtime-profile.v1.json").is_file()

    def test_package_data_declared(self):
        # setuptools 默认只收 .py；非代码数据文件必须显式声明，否则轮子缺文件。
        data = (
            _pyproject()["tool"]["setuptools"].get("package-data", {}).get("config", [])
        )
        assert "*.yaml" in data and "*.json" in data

    def test_built_wheel_contains_complete_web_ui(self):
        """wheel 本身携带可启动的 Web UI，不能借用仓库外置 out-web。"""

        temp_root = ROOT / ".ptmp"
        temp_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="pip-wheel-", dir=temp_root) as temp:
            wheel_dir = Path(temp) / "wheel"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "build",
                    "--wheel",
                    "--no-isolation",
                    "--outdir",
                    str(wheel_dir),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
                check=False,
            )
            assert result.returncode == 0, result.stderr[-4000:]
            wheels = list(wheel_dir.glob("*.whl"))
            assert len(wheels) == 1, wheels

            with zipfile.ZipFile(wheels[0]) as archive:
                names = set(archive.namelist())
                web_shim = archive.read("gateway/web_ui/api-shim.js").decode("utf-8")

        source_web_files = {
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "gateway" / "web_ui").rglob("*")
            if path.is_file()
        }
        packaged_web_files = {
            name for name in names if name.startswith("gateway/web_ui/")
        }

        assert "gateway/web_ui/index.html" in names
        assert "gateway/web_ui/api-shim.js" in names
        assert "cli/local_web_start.py" in names
        assert "cli/engine_entrypoint.py" in names
        assert "gateway/kimi_acp_product_protocol.py" in names
        assert "gateway/kimi_acp_auth_probe_protocol.py" in names
        assert "gateway/kimi_subscription_login.py" in names
        assert "gateway/kimi_subscription_worker.py" in names
        assert "gateway/providers/kimi_subscription.py" in names
        assert "cli/kimi_login_entrypoint.py" in names
        assert "cli/kimi_auth_probe_entrypoint.py" in names
        assert "cli/kimi_worker_entrypoint.py" in names
        assert "gateway/provider_plugins.py" in names
        assert "orchestrator/plugin_kernel.py" in names
        assert "orchestrator/tool_plugins.py" in names
        assert any(
            name.startswith("gateway/web_ui/assets/") and name.endswith(".js")
            for name in names
        )
        assert "/v1/paid-media/web/read-asset" in web_shim
        assert "resolvePaidMediaAsset" in web_shim
        assert "releasePaidMediaAsset" in web_shim
        assert packaged_web_files == source_web_files, {
            "unexpected": sorted(packaged_web_files - source_web_files),
            "missing": sorted(source_web_files - packaged_web_files),
        }

    def test_installed_wheel_exposes_complete_trusted_skill_bundle(self):
        """A wheel install must retain the exact reviewed project skill set."""

        expected_paths = {
            "skills/trusted-manifest.json",
            "skills/ATTRIBUTION.md",
            "skills/LICENSE.agency-agents",
            "skills/README.md",
            "skills/content-creator/SKILL.md",
            "skills/mcp-builder/SKILL.md",
            "skills/product-manager/SKILL.md",
            "skills/security-appsec-engineer/SKILL.md",
            "skills/video-optimization-specialist/SKILL.md",
            "skills/xiaohongshu-specialist/SKILL.md",
        }
        expected_names = {
            "Content Creator",
            "MCP Builder",
            "Product Manager",
            "Application Security Engineer",
            "Video Optimization Specialist",
            "Xiaohongshu Specialist",
        }

        temp_root = ROOT / ".ptmp"
        temp_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="pip-skills-", dir=temp_root) as temp:
            temp_dir = Path(temp)
            wheel_dir = temp_dir / "wheel"
            build = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "build",
                    "--wheel",
                    "--no-isolation",
                    "--outdir",
                    str(wheel_dir),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
                check=False,
            )
            assert build.returncode == 0, build.stderr[-4000:]
            wheels = list(wheel_dir.glob("*.whl"))
            assert len(wheels) == 1, wheels

            with zipfile.ZipFile(wheels[0]) as archive:
                names = set(archive.namelist())
            packaged_skills = {name for name in names if name.startswith("skills/")}
            assert packaged_skills == expected_paths

            venv_root = temp_dir / "venv"
            create_venv = subprocess.run(
                [sys.executable, "-m", "venv", str(venv_root)],
                cwd=temp_dir,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
                check=False,
            )
            assert create_venv.returncode == 0, create_venv.stderr[-4000:]
            installed_python = venv_root / (
                "Scripts/python.exe" if sys.platform == "win32" else "bin/python"
            )
            install = subprocess.run(
                [
                    str(installed_python),
                    "-m",
                    "pip",
                    "install",
                    "--disable-pip-version-check",
                    "--no-index",
                    "--no-cache-dir",
                    "--no-deps",
                    str(wheels[0]),
                ],
                cwd=temp_dir,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
                check=False,
            )
            assert install.returncode == 0, install.stderr[-4000:]

            probe = subprocess.run(
                [
                    str(installed_python),
                    "-I",
                    "-c",
                    (
                        "import json; "
                        "from orchestrator import skills; "
                        "print(json.dumps({"
                        "'root': str(skills._ROOT), "
                        "'skills': skills.list_skills()}))"
                    ),
                ],
                cwd=temp_dir,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
                check=False,
            )
            assert probe.returncode == 0, probe.stderr
            payload = json.loads(probe.stdout)
            discovered = payload["skills"]

        assert {item["name"] for item in discovered} == expected_names
        installed_skills = Path(payload["root"]).resolve()
        assert installed_skills.is_relative_to(venv_root.resolve())
        assert all(
            Path(item["path"]).resolve().is_relative_to(installed_skills)
            for item in discovered
        )
