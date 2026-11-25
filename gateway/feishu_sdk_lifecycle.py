"""Own one reviewed Feishu SDK loop without changing durable delivery handlers.

The SDK uses both a module-global loop and asyncio's current loop.  Its synchronous
endpoint HTTP request cannot be interrupted by asyncio; socket timeouts reduce
that exposure, but the parent process/Job deadline remains the hard stop boundary.
No return from this module certifies business drain or process quiescence.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import math
import threading
import time

_OWNER = threading.Lock()
_FAILED_RUNS: list[tuple[asyncio.AbstractEventLoop, object]] = []

class FeishuSdkLifecycleError(RuntimeError):
    pass

class FeishuSdkShutdownError(FeishuSdkLifecycleError):
    pass

class _StopRequested(BaseException):
    """Bypass the SDK's Exception-based reconnect handler after an exit request."""

@dataclass(frozen=True)
class FeishuSdkRunResult:
    stop_requested: bool

class _BoundedRequests:
    def __init__(self, requests_module, stop_event):
        self._requests = requests_module
        self._stop = stop_event

    def post(self, *args, **kwargs):
        if self._stop.is_set():
            raise _StopRequested()
        kwargs['timeout'] = (3.0, 5.0)
        response = self._requests.post(*args, **kwargs)
        if self._stop.is_set():
            response.close()
            raise _StopRequested()
        return response

async def _wait_tasks(tasks, deadline):
    if not tasks:
        return
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise FeishuSdkShutdownError('feishu SDK shutdown deadline exceeded')
    _, pending = await asyncio.wait(tasks, timeout=remaining)
    if pending:
        raise FeishuSdkShutdownError('feishu SDK tasks did not stop')

def _cancel_owned_tasks(loop, deadline):
    while tasks := asyncio.all_tasks(loop):
        for task in tasks:
            task.cancel()
        loop.run_until_complete(_wait_tasks(tasks, deadline))
        # Retrieve task errors without exposing SDK exception messages/secrets.
        for task in tasks:
            if not task.cancelled():
                task.exception()

def run_feishu_sdk(factory, stop_event: threading.Event, *, sdk_module=None,
                   sdk_version=None, shutdown_timeout: float = 5.0) -> FeishuSdkRunResult:
    """Run/close a single client; failure is terminal until this process exits.

    ``stop_event`` means exit, not merely close_claims.  The installed parent must
    finish business drain first.  The factory runs only after both SDK loop roots
    are bound, so constructor-created cache tasks belong to this lifecycle too.
    """
    if (not callable(factory) or not isinstance(stop_event, threading.Event)
            or isinstance(shutdown_timeout, bool)
            or not isinstance(shutdown_timeout, (int, float))
            or not math.isfinite(shutdown_timeout) or not 0 < shutdown_timeout <= 30):
        raise FeishuSdkLifecycleError('invalid feishu SDK lifecycle input')
    if stop_event.is_set():
        return FeishuSdkRunResult(True)
    if sdk_module is None:
        from lark_oapi.ws import client as sdk_module
    if sdk_version is None:
        from importlib.metadata import version
        sdk_version = version('lark-oapi')
    if sdk_version != '1.6.8':
        raise FeishuSdkLifecycleError('unreviewed feishu SDK lifecycle version')
    if not _OWNER.acquire(blocking=False):
        raise FeishuSdkLifecycleError('feishu SDK lifecycle already owned')
    loop = None
    client = None
    poll = None
    try:
        try:
            old_loop = sdk_module.loop
            old_requests = sdk_module.requests
        except AttributeError as exc:
            raise FeishuSdkLifecycleError('SDK loop or requests contract missing') from exc
        if _FAILED_RUNS:
            raise FeishuSdkShutdownError('previous feishu SDK shutdown unresolved')
        if old_loop.is_running():
            raise FeishuSdkLifecycleError('existing feishu SDK loop is running')
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise FeishuSdkLifecycleError('cannot own SDK inside another running loop')
        try:
            previous = asyncio.get_event_loop()
        except RuntimeError:
            previous = None
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        sdk_module.loop = loop
        sdk_module.requests = _BoundedRequests(old_requests, stop_event)
        failure = None
        def check_stop():
            nonlocal poll
            if stop_event.is_set():
                if client is not None:
                    client._auto_reconnect = False
                for task in asyncio.all_tasks(loop):
                    task.cancel()
            else:
                poll = loop.call_later(0.05, check_stop)
        try:
            if not stop_event.is_set():
                client = factory()
                if not callable(getattr(client, '_disconnect', None)):
                    raise FeishuSdkLifecycleError('SDK disconnect contract missing')
                if not stop_event.is_set():
                    poll = loop.call_soon(check_stop)
                    client.start()
        except KeyboardInterrupt:
            stop_event.set()
        except (_StopRequested, asyncio.CancelledError) as exc:
            if not stop_event.is_set():
                failure = exc
        except BaseException as exc:
            failure = exc
        finally:
            if poll is not None:
                poll.cancel()
            if client is not None:
                client._auto_reconnect = False
            deadline = time.monotonic() + shutdown_timeout
            try:
                _cancel_owned_tasks(loop, deadline)
                if client is not None:
                    disconnect = loop.create_task(client._disconnect())
                    loop.run_until_complete(_wait_tasks({disconnect}, deadline))
                    disconnect.result()
                    if getattr(client, '_conn', None) is not None:
                        raise FeishuSdkShutdownError('SDK connection remains open')
                _cancel_owned_tasks(loop, deadline)
                loop.close()
            except BaseException as exc:
                _FAILED_RUNS.append((loop, client))
                raise FeishuSdkShutdownError('feishu SDK shutdown incomplete') from exc
            finally:
                sdk_module.loop = old_loop
                sdk_module.requests = old_requests
                asyncio.set_event_loop(previous)
        if failure is not None:
            raise failure
        return FeishuSdkRunResult(stop_event.is_set())
    finally:
        _OWNER.release()
