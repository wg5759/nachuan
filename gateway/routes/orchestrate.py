"""协作编排、滚动摘要清理、智能单答路由与战绩记分牌路由（从 gateway/app.py 拆出）。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from gateway.auth import require_api_key
from gateway.privacy import (
    is_incognito_request,
    is_local_model,
    is_offline_only_router,
    should_inject_memory,
)
from gateway.providers.base import ProviderError
from gateway.routes.memory_kb import (
    _destructive_request_body,
    _destructive_user_id,
    _has_approval_id,
    _normalized_mutation_id,
    _snapshot_hash,
)
from gateway.schemas import (
    ChatCompletionRequest,
    DebateWorkflowRequest,
    DecomposeWorkflowRequest,
    PanelWorkflowRequest,
    PipelineWorkflowRequest,
    WorkflowOutputLimitError,
)
from orchestrator.agent import memory_system_note
from orchestrator.durable_event_log import DurableWorkflowEventUnavailable
from orchestrator.plugin_kernel import ServiceNotFound
from orchestrator.workflow_plugins import PIPELINE_WORKFLOW_SERVICE
from orchestrator.workflows.coding_team import run_arch_editor, run_coding_team
from orchestrator.workflows.debate import run_debate
from orchestrator.workflows.decompose import run_decompose
from orchestrator.workflows.panel_judge import run_panel

router = APIRouter(tags=["orchestrate"])


def _app_mod():
    import gateway.app as _mod

    return _mod


def _validated_git_repo(value: Any) -> str:
    """Resolve an exact existing repository root for capability binding."""

    raw = str(value or "").strip()
    if not raw:
        raise HTTPException(status_code=422, detail="需要 repo")
    try:
        repo = Path(raw).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=422, detail="repo 不存在或无法解析") from exc
    if not repo.is_dir() or repo.parent == repo or not (repo / ".git").exists():
        raise HTTPException(status_code=422, detail="repo 必须是现有 Git 仓库根目录")
    return str(repo)


def _summary_clear_spec(conv_id: str) -> dict[str, Any]:
    app_mod = _app_mod()
    store = app_mod.conv_summary._get_store()  # noqa: SLF001 - module owns no public reader
    if store is None:
        raise HTTPException(status_code=503, detail="对话摘要存储不可用")
    summary, covered = store.get(conv_id)
    state_sha256, _ = _snapshot_hash([(summary, covered)])
    return {
        "target": {"kind": "conversation_summary", "conversation_id": conv_id},
        "snapshot": {
            "sha256": state_sha256,
            "covered": covered,
            "exists": bool(summary or covered),
        },
    }


@router.post("/v1/orchestrate/panel")
async def orchestrate_panel(request: Request, api_key: str = Depends(require_api_key)):
    """M4 协作编排 · 议会汇总：多个 panelists 独立作答 → judge 综合。"""
    del api_key
    body = await request.json()
    try:
        spec = PanelWorkflowRequest.model_validate(body)
        result = await run_panel(
            request.app.state.router,
            prompt=spec.prompt,
            panelists=spec.panelists,
            judge=spec.judge,
        )
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="协作议会参数不符合资源限制") from exc
    except WorkflowOutputLimitError as exc:
        raise HTTPException(status_code=502, detail="协作模型输出超过安全上限") from exc
    return JSONResponse(result)


@router.post("/v1/orchestrate/coding")
async def orchestrate_coding(request: Request, _: str = Depends(require_api_key)):
    """M4 协作编排 · 编程团队：规划 → 并行实现(各 agent 一个 worktree) → 评审。"""
    raise HTTPException(
        status_code=503,
        detail="编程 CLI 团队已关闭：需要独立低权限执行 worker 后才能启用",
    )
    app_mod = _app_mod()  # pragma: no cover
    body = await request.json()
    repo = _validated_git_repo(body.get("repo"))
    task = (body.get("task") or "").strip()
    planner = str(body.get("planner") or "")
    reviewer = str(body.get("reviewer") or "")
    implementers = body.get("implementers") or []
    if not task or not planner or not reviewer or not implementers:
        raise HTTPException(
            status_code=422, detail="需要 repo、task、planner、reviewer、implementers"
        )
    if (
        request.app.state.router.resolve(planner) is None
        or request.app.state.router.resolve(reviewer) is None
    ):
        raise HTTPException(status_code=422, detail="planner/reviewer 必须是当前已连接模型")
    approval_id, held = await app_mod._action_capability(  # noqa: SLF001
        body=body,
        router=request.app.state.router,
        task=task,
        workdir=repo,
        user_id=str(
            body.get("user_id") or app_mod.get_settings().agent_user_id or "owner"
        ),
        scope="orchestrate_coding",
        mode="auto",
        require_explicit_capability=True,
        payload_extra={
            "planner": planner,
            "reviewer": reviewer,
            "implementers": implementers,
        },
    )
    if held is not None:
        return held
    try:
        result = await run_coding_team(
            request.app.state.router,
            repo=repo,
            task=task,
            planner=planner,
            implementers=implementers,
            reviewer=reviewer,
        )
    except (ValueError, TypeError) as exc:
        if approval_id:
            request.app.state.approvals.finish_action(approval_id, success=False)
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception:
        if approval_id:
            request.app.state.approvals.finish_action(approval_id, success=False)
        raise
    if approval_id:
        request.app.state.approvals.finish_action(approval_id, success=True)
    return JSONResponse(result)


@router.post("/v1/orchestrate/arch-editor")
async def orchestrate_arch_editor(request: Request, _: str = Depends(require_api_key)):
    """架构师/编辑：强模型规划 → 便宜模型出文件代码（省 token 的编程模式）。"""
    raise HTTPException(
        status_code=503,
        detail="架构编辑执行已关闭：Git/worktree 写入需要独立低权限执行 worker 后才能启用",
    )
    app_mod = _app_mod()  # pragma: no cover
    body = await request.json()
    repo = _validated_git_repo(body.get("repo"))
    task = (body.get("task") or "").strip()
    architect = str(body.get("architect") or "")
    editor = str(body.get("editor") or "")
    if not task or not architect or not editor:
        raise HTTPException(status_code=422, detail="需要 repo、task、architect、editor")
    if (
        request.app.state.router.resolve(architect) is None
        or request.app.state.router.resolve(editor) is None
    ):
        raise HTTPException(status_code=422, detail="architect/editor 必须是当前已连接模型")
    approval_id, held = await app_mod._action_capability(  # noqa: SLF001
        body=body,
        router=request.app.state.router,
        task=task,
        workdir=repo,
        user_id=str(
            body.get("user_id") or app_mod.get_settings().agent_user_id or "owner"
        ),
        scope="orchestrate_arch_editor",
        mode="auto",
        require_explicit_capability=True,
        payload_extra={"architect": architect, "editor": editor},
    )
    if held is not None:
        return held
    try:
        result = await run_arch_editor(
            request.app.state.router,
            repo=repo,
            task=task,
            architect=architect,
            editor=editor,
        )
    except Exception:
        if approval_id:
            request.app.state.approvals.finish_action(approval_id, success=False)
        raise
    if approval_id:
        request.app.state.approvals.finish_action(approval_id, success=True)
    return JSONResponse(result)


@router.post("/v1/conv/{conv_id}/clear-summary")
async def clear_conv_summary(
    conv_id: str, request: Request, _: str = Depends(require_api_key)
):
    """Clear one exact reviewed rolling-summary snapshot after approval."""
    app_mod = _app_mod()
    normalized_conv_id = _normalized_mutation_id(
        conv_id, label="conversation_id", max_length=256
    )
    body = await _destructive_request_body(request)
    user_id = _destructive_user_id(body)
    spec = _summary_clear_spec(normalized_conv_id)
    if not _has_approval_id(body) and not spec["snapshot"]["exists"]:
        return {
            "ok": True,
            "conversation_id": normalized_conv_id,
            "already_empty": True,
        }
    task = f"清空对话滚动摘要：{normalized_conv_id}"
    approval_id, held = await app_mod._action_capability(  # noqa: SLF001
        body=body,
        router=request.app.state.router,
        task=task,
        workdir=str(Path(app_mod.get_settings().usage_db_path).parent.resolve()),
        user_id=user_id,
        scope="conversation_summary_clear",
        mode="full",
        require_explicit_capability=True,
        payload_extra=spec,
    )
    if held is not None:
        return held
    try:
        if _summary_clear_spec(normalized_conv_id) != spec:
            raise HTTPException(status_code=409, detail="对话摘要已变化，请重新审批")
        app_mod.conv_summary.clear(normalized_conv_id)
        if _summary_clear_spec(normalized_conv_id)["snapshot"]["exists"]:
            raise RuntimeError(
                "conversation summary clear did not remove the reviewed target"
            )
    except Exception:
        request.app.state.approvals.finish_action(approval_id, success=False)
        raise
    request.app.state.approvals.finish_action(approval_id, success=True)
    return {"ok": True, "conversation_id": normalized_conv_id}


@router.post("/v1/route")
async def route_mode(request: Request, api_key: str = Depends(require_api_key)):
    """单答模式调度：auto(自动智能·默认) / smart / cascade / economy / best / harness。"""
    app_mod = _app_mod()
    body = await request.json()
    mode = body.get("mode", "smart")
    messages = body.get("messages") or []
    _incognito = is_incognito_request(body)
    _inject_memory = should_inject_memory(body)
    _route_source_model = str(body.get("model") or "").strip() or None
    if not _incognito:
        messages = (
            await app_mod.conv_summary.rolling_compress(
                request.app.state.router,
                str(body.get("conversation_id") or ""),
                messages,
                source_model=_route_source_model,
                incognito=_incognito,
            )
            or messages
        )
    _is_short_followup = app_mod._inject_followup_context(messages)  # noqa: SLF001
    reasoning_effort = str(body.get("reasoning_effort") or "").strip().lower()
    if reasoning_effort in {"low", "medium", "high"}:
        effort_zh = {"low": "低", "medium": "中", "high": "高"}[reasoning_effort]
        messages.insert(
            0,
            {
                "role": "system",
                "content": f"本次推理级别：{effort_zh}。低=快速简答；中=平衡；高=更充分地核查与规划，但最终仍只输出结论和必要过程摘要。",
            },
        )
    if (
        body.get("web_search") is True
        and not _is_short_followup
        and not _incognito
        and not is_offline_only_router(request.app.state.router)
        and not is_local_model(request.app.state.router, _route_source_model)
    ):
        try:
            _web_req = ChatCompletionRequest(
                model=str(_route_source_model or app_mod.get_settings().bridge_model),
                messages=messages,
                web_search=True,
                incognito=_incognito,
            )
            await app_mod.websearch.maybe_augment_request(
                _web_req,
                router=request.app.state.router,
                incognito=_incognito,
            )
            messages = [m.model_dump(exclude_none=True) for m in _web_req.messages]
        except Exception:  # noqa: BLE001
            pass
    if _inject_memory and not _incognito:
        try:
            _um = next(
                (
                    m.get("content")
                    for m in reversed(messages)
                    if m.get("role") == "user" and isinstance(m.get("content"), str)
                ),
                "",
            )
            _note, _ = memory_system_note(
                request.app.state.memory,
                app_mod.get_settings().agent_user_id or "owner",
                _um,
            )
            if _note:
                _li = max(
                    (i for i, m in enumerate(messages) if m.get("role") == "user"),
                    default=-1,
                )
                _mm = {"role": "system", "content": _note}
                if _li >= 0:
                    messages.insert(_li, _mm)
                else:
                    messages.append(_mm)
        except Exception:  # noqa: BLE001
            pass
    fn = app_mod.SINGLE_ANSWER_MODES.get(mode)
    if fn is None:
        raise HTTPException(status_code=422, detail=f"未知模式 {mode}")
    try:
        result = await fn(request.app.state.router, messages)
    except ProviderError as e:
        raise app_mod._public_provider_http_error(e) from e  # noqa: SLF001
    meta = result.get("_route", {})
    u = result.get("usage") or {}
    _pd = u.get("prompt_tokens_details") or {}
    await app_mod._log_usage_best_effort(  # noqa: SLF001
        request.app.state.usage,
        api_key=api_key,
        virtual_model=mode,
        provider=str(meta.get("provider") or "mode-unserved"),
        upstream_model=str(meta.get("upstream_model") or ""),
        tier=str(meta.get("tier") or "mode"),
        prompt_tokens=int(u.get("prompt_tokens", 0) or 0),
        completion_tokens=int(u.get("completion_tokens", 0) or 0),
        total_tokens=int(u.get("total_tokens", 0) or 0),
        cached_tokens=int(
            u.get("cached_tokens", 0) or _pd.get("cached_tokens", 0) or 0
        ),
        cost_usd=float(u.get("cost_usd", 0) or 0),
        stream=0,
        status="ok",
        latency_ms=0,
    )
    return JSONResponse(result)


@router.post("/v1/orchestrate/debate")
async def orchestrate_debate(request: Request, api_key: str = Depends(require_api_key)):
    """辩论：多模型多轮互评 → 裁判综合。"""
    del api_key
    body = await request.json()
    try:
        spec = DebateWorkflowRequest.model_validate(body)
        result = await run_debate(
            request.app.state.router,
            prompt=spec.prompt,
            debaters=spec.debaters,
            judge=spec.judge,
            rounds=spec.rounds,
        )
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="辩论参数不符合资源限制") from exc
    except WorkflowOutputLimitError as exc:
        raise HTTPException(status_code=502, detail="辩论模型输出超过安全上限") from exc
    return JSONResponse(result)


@router.post("/v1/orchestrate/decompose")
async def orchestrate_decompose(
    request: Request, api_key: str = Depends(require_api_key)
):
    """拆解分工：规划→子任务各派最便宜能做的→汇总。"""
    del api_key
    body = await request.json()
    try:
        spec = DecomposeWorkflowRequest.model_validate(body)
        result = await run_decompose(
            request.app.state.router,
            task=spec.task,
            planner=spec.planner,
            aggregator=spec.aggregator,
        )
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="任务拆解参数不符合资源限制") from exc
    except WorkflowOutputLimitError as exc:
        raise HTTPException(status_code=502, detail="任务拆解模型输出超过安全上限") from exc
    return JSONResponse(result)


@router.post("/v1/orchestrate/pipeline")
async def orchestrate_pipeline(
    request: Request, api_key: str = Depends(require_api_key)
):
    """流水线：固定工序，每步指定模型。"""
    del api_key
    body = await request.json()
    try:
        spec = PipelineWorkflowRequest.model_validate(body)
        try:
            lease = request.app.state.router.plugin_kernel.borrow_service(
                PIPELINE_WORKFLOW_SERVICE
            )
        except ServiceNotFound as exc:
            raise HTTPException(
                status_code=503,
                detail="流水线工作流插件当前不可用",
            ) from exc
        try:
            service = lease.value
            result = await service(
                request.app.state.router,
                prompt=spec.prompt,
                steps=[step.model_dump() for step in spec.steps],
            )
        finally:
            lease.release()
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="流水线参数不符合资源限制") from exc
    except WorkflowOutputLimitError as exc:
        raise HTTPException(status_code=502, detail="流水线模型输出超过安全上限") from exc
    except DurableWorkflowEventUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail="流水线持久事件日志当前不可用",
            headers={"X-Nachuan-Retry-Safe": "false"},
        ) from exc
    return JSONResponse(result)


@router.get("/v1/scoreboard")
async def get_scoreboard(_: str = Depends(require_api_key)) -> dict[str, Any]:
    """只读战绩看板（F6）：返回记分牌全表（每行含胜率），供桌面「进化 · 战绩」页。"""
    app_mod = _app_mod()
    return {"rows": app_mod.scoreboard.dump_all()}
