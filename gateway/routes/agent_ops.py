"""Agent 反馈、反思、任务台账、插话与撤销路由（从 gateway/app.py 拆出）。"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from gateway.admission import BackgroundJobLimitExceeded, get_background_job_pool
from gateway.auth import require_api_key, require_bridge_or_api_key
from gateway.providers.base import ProviderError
from gateway.router import Router
from gateway.runtime_profile import RuntimeCapability, current_runtime_profile
from gateway.schemas import ChatCompletionRequest
from orchestrator.agent import (
    ConversationReceiptUnavailable,
    record_feedback,
    record_feedback_once,
)
from orchestrator.ledger import (
    TaskLedger,
    freeze_execution_spec,
    plan_job,
    run_job,
    validate_execution_spec,
)
from orchestrator.memory import reflect
from orchestrator.modes import pick_model
from orchestrator.undo_receipts import UndoReceiptError

router = APIRouter(tags=["agent-ops"])

_JOBS: set[Any] = set()


def _app_mod():
    import gateway.app as _mod

    return _mod


def _make_step_executor(router_obj: Router, *, workdir: str, backend: str, mode: str):
    """每步执行器：action→当前启用工具执行，reason→模型思考。"""
    app_mod = _app_mod()

    async def executor(step: dict) -> str:
        if step.get("kind") == "reason":
            m = app_mod.get_settings().bridge_model
            prompt = (
                f"任务步骤：{step.get('title', '')}\n{step.get('detail', '')}\n"
                "请完成这一步，直接给结论。"
            )
            req = ChatCompletionRequest(
                model=m,
                messages=[{"role": "user", "content": prompt}],  # type: ignore[arg-type]
            )
            res, _s, _r = await app_mod.chat_with_fallback(router_obj, req)
            return (
                (res.get("choices") or [{}])[0]
                .get("message", {})
                .get("content")
                or ""
            ).strip()
        task = f"{step.get('title', '')}。{step.get('detail', '')}".strip("。 ")
        res = await app_mod._run_agent_exec(  # noqa: SLF001
            router_obj, task, backend=backend, mode=mode, workdir=workdir
        )
        return str(res.get("result") or res.get("reply") or res.get("stdout") or "")[
            :4000
        ]

    return executor


def _spawn_job(ledger: TaskLedger, jid: str, executor) -> None:
    pool = get_background_job_pool()
    lease = pool.try_acquire(kind="agent_job", external_ids=(jid,))
    if lease is None:
        raise BackgroundJobLimitExceeded("background agent-job capacity reached")

    async def tracked() -> None:
        try:
            await run_job(ledger, jid, executor)
        finally:
            pool.release(lease)

    try:
        t = asyncio.create_task(tracked())
    except Exception:
        pool.release(lease)
        raise
    _JOBS.add(t)
    t.add_done_callback(_JOBS.discard)


@router.post("/v1/agent/feedback")
async def agent_feedback(
    request: Request, credential: str = Depends(require_bridge_or_api_key)
):
    """反馈（Reflexion）：rating=up/down。👎+note→存教训(下次注入)；👍→上一轮提升为案例。"""
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="请求体必须是 JSON 对象")
    requested_channel = str(body.get("channel") or "").strip().lower()
    if credential.startswith("bridge:") and credential != f"bridge:{requested_channel}":
        raise HTTPException(status_code=403, detail="bridge credential channel mismatch")
    user_id = str(body.get("user_id") or "")
    rating = str(body.get("rating") or "").lower()
    if not user_id or rating not in ("up", "down"):
        raise HTTPException(status_code=422, detail="需要 user_id 与 rating(up/down)")
    idempotency_key = body.get("idempotency_key")
    if requested_channel in {"feishu", "weixin"} and not isinstance(
        idempotency_key, str
    ):
        raise HTTPException(
            status_code=422,
            detail=f"{requested_channel} feedback requires idempotency_key",
        )
    if idempotency_key is not None:
        try:
            return await run_in_threadpool(
                record_feedback_once,
                memory=request.app.state.memory,
                cases=request.app.state.cases,
                conv=request.app.state.conversations,
                user_id=user_id,
                rating=rating,
                idempotency_key=idempotency_key,
                channel=requested_channel or "api",
                chat_id=str(body.get("chat_id") or ""),
                note=body.get("note"),
            )
        except ValueError as exc:
            status = 409 if "semantic conflict" in str(exc) else 422
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        except ConversationReceiptUnavailable as exc:
            raise HTTPException(
                status_code=503,
                detail="durable feedback receipt is unavailable",
            ) from exc
    return record_feedback(
        memory=request.app.state.memory,
        cases=request.app.state.cases,
        conv=request.app.state.conversations,
        user_id=user_id,
        rating=rating,
        channel=requested_channel or "api",
        chat_id=str(body.get("chat_id") or ""),
        note=body.get("note"),
    )


@router.post("/v1/agent/reflect")
async def agent_reflect(request: Request, _: str = Depends(require_api_key)):
    """反思：把某用户的零散记忆归纳为高层洞察(insight)。"""
    app_mod = _app_mod()
    body = await request.json()
    user_id = str(body.get("user_id") or "")
    if not user_id:
        raise HTTPException(status_code=422, detail="需要 user_id")
    router_obj: Router = request.app.state.router
    model = (
        "agnes-flash"
        if router_obj.resolve("agnes-flash")
        else (
            pick_model(router_obj, "cheap") or app_mod.get_settings().bridge_model
        )
    )
    added = await reflect(
        router_obj, request.app.state.memory, user_id=user_id, model=model
    )
    return {"user_id": user_id, "insights_added": added}


@router.post("/v1/agent/exec")
async def agent_exec_endpoint(request: Request, _: str = Depends(require_api_key)):
    """Native host execution is unavailable inside the gateway process."""
    raise HTTPException(
        status_code=503,
        detail="本机 CLI 执行已关闭：需要独立低权限执行 worker 后才能启用",
    )
    app_mod = _app_mod()  # pragma: no cover
    router_obj: Router = request.app.state.router
    body = await request.json()
    task = (body.get("task") or "").strip()
    if not task:
        raise HTTPException(status_code=422, detail="需要 task")
    s = app_mod.get_settings()
    workdir = str(body.get("workdir") or s.agent_exec_workdir or str(app_mod.PROJECT_ROOT))
    uid = str(body.get("user_id") or s.agent_user_id or "owner")
    _mode = app_mod._agent_mode(body)  # noqa: SLF001
    _instr = str(body.get("instruction") or "").strip()
    if not _instr and "【现在的指令】" in task:
        _instr = task.split("【现在的指令】", 1)[1].strip()
    _approval_id, held = await app_mod._action_capability(  # noqa: SLF001
        body=body,
        router=router_obj,
        task=task,
        workdir=workdir,
        user_id=uid,
        scope="agent_exec",
        mode=_mode,
        summary=_instr,
        soft_check=True,
        require_explicit_capability=_mode != "plan",
        payload_extra={
            "backend": body.get("backend"),
            "model": body.get("model"),
        },
    )
    if held is not None:
        return held
    _claimed = bool(_approval_id)
    try:
        result = await app_mod._run_agent_exec(  # noqa: SLF001
            router_obj,
            task,
            backend=str(body.get("backend") or "auto").lower(),
            mode=_mode,
            workdir=workdir,
            model_override=body.get("model"),
        )
    except ProviderError as e:
        if _claimed:
            request.app.state.approvals.finish_action(_approval_id, success=False)
        raise app_mod._public_provider_http_error(e) from e  # noqa: SLF001
    except Exception:
        if _claimed:
            request.app.state.approvals.finish_action(_approval_id, success=False)
        raise
    if _claimed:
        request.app.state.approvals.finish_action(_approval_id, success=True)
    return result


@router.post("/v1/agent/job")
async def create_job_endpoint(request: Request, _: str = Depends(require_api_key)):
    """执行脊柱：把一个目标自动分解成多步、逐步执行、可断点续跑。后台跑，立即返回 job_id+步骤；GET 轮询进度。"""
    raise HTTPException(
        status_code=503,
        detail="本机 CLI 任务执行已关闭：需要独立低权限执行 worker 后才能启用",
    )
    app_mod = _app_mod()  # pragma: no cover
    router_obj: Router = request.app.state.router
    body = await request.json()
    s = app_mod.get_settings()
    approved = app_mod._approved_action_record(body, scope="agent_job")  # noqa: SLF001
    if approved is not None:
        if approved.get("status") == "revise":
            raise HTTPException(
                status_code=409,
                detail="换方案会改变冻结步骤；请带补充要求重新发起并审批一份新计划",
            )
        payload = approved.get("payload") or {}
        try:
            spec = validate_execution_spec(payload.get("execution_spec"))
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=403,
                detail="审批记录缺少可验证的冻结执行规范，请重新发起任务",
            )
        uid = str(approved.get("user_id") or "owner")
        claim_goal = str(spec["goal"])
    else:
        goal = str(body.get("goal") or "").strip()
        if not goal:
            raise HTTPException(status_code=422, detail="需要 goal")
        workdir = str(
            body.get("workdir") or s.agent_exec_workdir or str(app_mod.PROJECT_ROOT)
        )
        mode = app_mod._agent_mode(body)  # noqa: SLF001
        uid = str(body.get("user_id") or "owner")
        steps = body.get("steps") or await plan_job(router_obj, goal)
        if not steps:
            raise HTTPException(status_code=502, detail="任务分解失败，换个说法或自带 steps")
        try:
            spec = freeze_execution_spec(
                goal=goal,
                steps=steps,
                workdir=workdir,
                backend=str(body.get("backend") or "auto"),
                mode=mode,
            )
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        claim_goal = str(spec["goal"])

    goal = str(spec["goal"])
    steps = list(spec["steps"])
    workdir = str(spec["workdir"])
    backend = str(spec["backend"])
    mode = str(spec["mode"])
    frozen_manifest = {
        "steps": steps,
        "backend": backend,
        "execution_spec": spec,
    }
    approval_id, held = await app_mod._action_capability(  # noqa: SLF001
        body=body,
        router=router_obj,
        task=claim_goal,
        workdir=workdir,
        user_id=uid,
        scope="agent_job",
        mode=mode,
        enforce_task_risk=mode != "plan",
        require_explicit_capability=mode != "plan",
        payload_extra=frozen_manifest,
    )
    if held is not None:
        return held
    ledger: TaskLedger = request.app.state.ledger
    jid = ""
    try:
        jid = ledger.create_job(goal, steps, user_id=uid, execution_spec=spec)
        _spawn_job(
            ledger,
            jid,
            _make_step_executor(
                router_obj,
                workdir=workdir,
                backend=backend,
                mode=mode,
            ),
        )
    except Exception:
        if jid:
            ledger.fail_unclaimed_job(jid)
        if approval_id:
            request.app.state.approvals.finish_action(approval_id, success=False)
        raise
    if approval_id:
        request.app.state.approvals.finish_action(approval_id, success=True)
    return {"job_id": jid, **ledger.to_dict(jid)}


@router.get("/v1/agent/job/{job_id}")
async def job_status_endpoint(
    job_id: str, request: Request, _: str = Depends(require_api_key)
):
    """查任务进度（轮询）：含每步 status/output 与 progress。"""
    d = request.app.state.ledger.to_dict(job_id)
    if not d:
        raise HTTPException(status_code=404, detail="无此任务")
    return d


@router.post("/v1/agent/job/{job_id}/resume")
async def job_resume_endpoint(
    job_id: str, request: Request, _: str = Depends(require_api_key)
):
    """断点续跑：把崩溃/失败的步骤复位，从断点接着跑（done 步骤跳过）。"""
    raise HTTPException(
        status_code=503,
        detail="本机 CLI 任务执行已关闭：需要独立低权限执行 worker 后才能启用",
    )
    app_mod = _app_mod()  # pragma: no cover
    ledger: TaskLedger = request.app.state.ledger
    job = ledger.to_dict(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="无此任务")
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    spec = ledger.get_execution_spec(job_id)
    if spec is None:
        raise HTTPException(
            status_code=409,
            detail="任务缺少可验证的冻结执行规范，请新建任务",
        )
    approved = app_mod._approved_action_record(  # noqa: SLF001
        body, scope="agent_job_resume"
    )
    if approved is not None and approved.get("status") == "revise":
        raise HTTPException(
            status_code=409,
            detail="恢复任务不能用换方案修改已冻结执行规范；请新建任务",
        )
    goal = str(spec["goal"])
    workdir = str(spec["workdir"])
    backend = str(spec["backend"])
    mode = str(spec["mode"])
    uid = str(job.get("user_id") or "owner")
    frozen_manifest = {
        "job_id": job_id,
        "backend": backend,
        "execution_spec": spec,
    }
    approval_id, held = await app_mod._action_capability(  # noqa: SLF001
        body=body,
        router=request.app.state.router,
        task=goal,
        workdir=workdir,
        user_id=uid,
        scope="agent_job_resume",
        mode=mode,
        enforce_task_risk=mode != "plan",
        require_explicit_capability=mode != "plan",
        payload_extra=frozen_manifest,
    )
    if held is not None:
        return held
    try:
        _spawn_job(
            ledger,
            job_id,
            _make_step_executor(
                request.app.state.router,
                workdir=workdir,
                backend=backend,
                mode=mode,
            ),
        )
    except Exception:
        if approval_id:
            request.app.state.approvals.finish_action(approval_id, success=False)
        raise
    if approval_id:
        request.app.state.approvals.finish_action(approval_id, success=True)
    return ledger.to_dict(job_id)


@router.post("/v1/agent/inject")
async def agent_inject_endpoint(
    request: Request, api_key: str = Depends(require_api_key)
):
    """运行中插话（steering）：agent 长任务跑着时把用户的话注入循环。"""
    app_mod = _app_mod()
    if not current_runtime_profile().allows(
        RuntimeCapability.CONTROLLED_AGENT_EXECUTION
    ):
        raise HTTPException(
            status_code=503,
            detail="当前运行配置已关闭受控 Agent 执行；需要独立低权限 worker",
        )
    body = await request.json()
    principal = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    ok = app_mod.steer.push(
        str(body.get("conversation_id") or ""),
        str(body.get("message") or ""),
        principal,
    )
    return {"injected": ok}


@router.post("/v1/agent/undo")
async def agent_undo_endpoint(request: Request, _: str = Depends(require_api_key)):
    """Consume a server-issued one-time receipt and restore its exact pre-image."""
    app_mod = _app_mod()
    if not current_runtime_profile().allows(
        RuntimeCapability.CONTROLLED_AGENT_EXECUTION
    ):
        raise HTTPException(
            status_code=503,
            detail="当前运行配置已关闭受控 Agent 执行；需要独立低权限 worker",
        )
    body = await request.json()
    receipt = str(body.get("receipt") or "")
    if not receipt:
        raise HTTPException(
            status_code=410,
            detail="旧版任意路径撤销接口已停用；需要服务端签发的 receipt",
        )
    content = str(body.get("content") or "")
    try:
        result = app_mod.undo_receipts.restore(receipt, content)
    except UndoReceiptError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"ok": True, **result}
