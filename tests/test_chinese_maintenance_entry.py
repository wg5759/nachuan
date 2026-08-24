from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAINTENANCE = ROOT / "安装与维护"


def _command(name: str) -> str:
    path = MAINTENANCE / name
    raw = path.read_bytes()
    assert raw.isascii(), f"{name} must remain ASCII-safe for cmd.exe"
    return raw.decode("ascii").replace("/", "\\").lower()


def test_chinese_maintenance_entry_points_to_single_project_sources() -> None:
    assert (MAINTENANCE / "README.md").is_file()
    assert (ROOT / "scripts" / "start_all.ps1").is_file()
    assert (ROOT / "scripts" / "build-local.ps1").is_file()

    status = _command("查看运行状态.cmd")
    stop = _command("停止纳川.cmd")
    resume = _command("恢复并启动纳川.cmd")
    build = _command("构建本地安装包-精简版.cmd")
    desktop_dev = _command("开发模式启动桌面端.cmd")

    assert "scripts\\start_all.ps1" in status and "-action status" in status
    assert "scripts\\start_all.ps1" in stop and "-action stop" in stop
    assert "scripts\\start_all.ps1" in resume and "-action','resume'" in resume
    assert "start-process -windowstyle hidden" in resume
    assert "scripts\\build-local.ps1" in build and " lean" in build
    assert "%~dp0..\\desktop" in desktop_dev and "npm run dev" in desktop_dev
    assert not (ROOT / "启动引擎.bat").exists()
    assert not (ROOT / "启动纳川.bat").exists()


def test_maintenance_commands_do_not_reference_a_second_project_copy() -> None:
    for name in (
        "查看运行状态.cmd",
        "停止纳川.cmd",
        "恢复并启动纳川.cmd",
        "构建本地安装包-精简版.cmd",
        "开发模式启动桌面端.cmd",
    ):
        command = _command(name)
        assert "d:\\" not in command
        assert "大模型聚合器" not in command
