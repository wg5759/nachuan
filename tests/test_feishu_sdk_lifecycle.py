"""Owned-loop shutdown regression: no SDK import, credentials or network."""
import asyncio
from types import SimpleNamespace
import threading
import pytest
from gateway import feishu_sdk_lifecycle as lifecycle

@pytest.fixture
def sdk():
    old = asyncio.new_event_loop()
    module = SimpleNamespace(loop=old, requests=SimpleNamespace(post=lambda *a, **k: None))
    yield module
    old.close()
    for loop, client in lifecycle._FAILED_RUNS:
        tasks = asyncio.all_tasks(loop)
        for task in tasks:
            task.cancel()
        if not loop.is_closed():
            if tasks:
                loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
            loop.close()
    lifecycle._FAILED_RUNS.clear()

class Client:
    def __init__(self, sdk, stop, mode='running'):
        self.sdk, self.stop, self.mode = sdk, stop, mode
        self._auto_reconnect = True
        self._conn = None
        self.closed = False
        self.owner_loop = asyncio.get_event_loop()
        self.owner_loop.create_task(self.background())
    async def background(self):
        await asyncio.sleep(3600)
    async def connect(self):
        if self.mode == 'connecting':
            self.sdk.loop.call_soon(self.stop.set)
            await asyncio.sleep(3600)
        self._conn = object()
    def start(self):
        if self.mode == 'raises':
            raise ValueError('synthetic startup failure')
        if self.mode == 'keyboard':
            raise KeyboardInterrupt
        self.sdk.loop.run_until_complete(self.connect())
        self.sdk.loop.call_later(0.01, self.stop.set)
        self.sdk.loop.run_until_complete(self.background())
    async def _disconnect(self):
        if self.mode == 'disconnect-fails':
            raise OSError('synthetic close failure')
        if self.mode == 'disconnect-hangs':
            await asyncio.sleep(3600)
        self._conn = None
        self.closed = True

def run(sdk, stop, mode='running', timeout=0.3):
    made = []
    def factory():
        client = Client(sdk, stop, mode)
        made.append(client)
        return client
    result = lifecycle.run_feishu_sdk(factory, stop, sdk_module=sdk, sdk_version='1.6.8', shutdown_timeout=timeout)
    return result, made

@pytest.mark.parametrize('mode', ['running', 'connecting', 'keyboard'])
def test_stop_closes_owned_loop_and_constructed_tasks(sdk, mode):
    original = sdk.loop
    previous = asyncio.new_event_loop()
    asyncio.set_event_loop(previous)
    try:
        result, made = run(sdk, threading.Event(), mode)
        assert result.stop_requested
        assert made[0].closed and made[0]._conn is None
        assert not made[0]._auto_reconnect
        assert made[0].owner_loop.is_closed()
        assert sdk.loop is original
        assert asyncio.get_event_loop() is previous
    finally:
        asyncio.set_event_loop(None)
        previous.close()

def test_stop_before_start_has_no_client(sdk):
    stop = threading.Event()
    stop.set()
    result, made = run(sdk, stop)
    assert result.stop_requested and made == []

@pytest.mark.parametrize('mode', ['disconnect-fails', 'disconnect-hangs'])
def test_shutdown_failure_is_terminal_not_reconnectable(sdk, mode):
    with pytest.raises(lifecycle.FeishuSdkShutdownError):
        run(sdk, threading.Event(), mode, timeout=0.1)
    with pytest.raises(lifecycle.FeishuSdkShutdownError):
        run(sdk, threading.Event())

def test_normal_start_error_is_preserved_after_cleanup(sdk):
    with pytest.raises(ValueError, match='synthetic startup'):
        run(sdk, threading.Event(), 'raises')
    assert lifecycle._FAILED_RUNS == []

def test_unreviewed_sdk_version_is_rejected_before_factory(sdk):
    with pytest.raises(lifecycle.FeishuSdkLifecycleError):
        lifecycle.run_feishu_sdk(lambda: pytest.fail('factory called'), threading.Event(), sdk_module=sdk, sdk_version='9.0')

def test_concurrent_owner_rejected_without_loop_rebinding(sdk):
    original = sdk.loop
    lifecycle._OWNER.acquire()
    try:
        with pytest.raises(lifecycle.FeishuSdkLifecycleError):
            run(sdk, threading.Event())
        assert sdk.loop is original
    finally:
        lifecycle._OWNER.release()

def test_endpoint_request_is_bounded_and_stop_checked_before_and_after():
    stop = threading.Event()
    calls = []
    response = SimpleNamespace(close=lambda: calls.append('closed'))
    def post(*args, **kwargs):
        calls.append(kwargs['timeout'])
        stop.set()
        return response
    proxy = lifecycle._BoundedRequests(SimpleNamespace(post=post), stop)
    with pytest.raises(lifecycle._StopRequested):
        proxy.post('https://synthetic.invalid', timeout=None)
    assert calls == [(3.0, 5.0), 'closed']
    with pytest.raises(lifecycle._StopRequested):
        proxy.post('https://synthetic.invalid')
    assert len(calls) == 2

def test_missing_sdk_contract_does_not_leak_owner_lock():
    with pytest.raises(lifecycle.FeishuSdkLifecycleError):
        lifecycle.run_feishu_sdk(lambda: None, threading.Event(), sdk_module=SimpleNamespace(), sdk_version='1.6.8')
    assert lifecycle._OWNER.acquire(blocking=False)
    lifecycle._OWNER.release()

def test_factory_failure_cleans_constructor_tasks(sdk):
    owned = []
    def factory():
        loop = asyncio.get_event_loop()
        owned.append(loop)
        loop.create_task(asyncio.sleep(3600))
        raise ValueError('constructor failed')
    with pytest.raises(ValueError, match='constructor failed'):
        lifecycle.run_feishu_sdk(factory, threading.Event(), sdk_module=sdk, sdk_version='1.6.8')
    assert owned[0].is_closed()
    assert not lifecycle._FAILED_RUNS

def test_cross_thread_stop(sdk):
    stop = threading.Event()
    entered = threading.Event()
    made = []
    class CrossThreadClient(Client):
        def start(self):
            self.sdk.loop.run_until_complete(self.connect())
            entered.set()
            self.sdk.loop.run_until_complete(self.background())
    def factory():
        client = CrossThreadClient(sdk, stop)
        made.append(client)
        return client
    def request_stop():
        entered.wait(2)
        stop.set()
    requester = threading.Thread(target=request_stop, daemon=True)
    requester.start()
    result = lifecycle.run_feishu_sdk(factory, stop, sdk_module=sdk, sdk_version='1.6.8')
    requester.join(2)
    assert not requester.is_alive() and result.stop_requested
    assert made[0].closed and made[0].owner_loop.is_closed()

def test_task_created_while_cancelling_is_also_closed(sdk):
    stop = threading.Event()
    made = []
    class SpawningClient(Client):
        async def background(self):
            try:
                await asyncio.sleep(3600)
            finally:
                self.sdk.loop.create_task(asyncio.sleep(3600))
    def factory():
        client = SpawningClient(sdk, stop)
        made.append(client)
        return client
    result = lifecycle.run_feishu_sdk(factory, stop, sdk_module=sdk, sdk_version='1.6.8')
    assert result.stop_requested and made[0].owner_loop.is_closed()

def test_cancellation_resistant_task_is_not_clean(sdk):
    stop = threading.Event()
    release = False
    async def stubborn():
        while not release:
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                continue
    def factory():
        client = Client(sdk, stop)
        client.owner_loop.create_task(stubborn())
        return client
    try:
        with pytest.raises(lifecycle.FeishuSdkShutdownError):
            lifecycle.run_feishu_sdk(factory, stop, sdk_module=sdk, sdk_version='1.6.8', shutdown_timeout=0.1)
        assert lifecycle._FAILED_RUNS
        assert not lifecycle._FAILED_RUNS[0][0].is_closed()
    finally:
        release = True

def test_stop_during_internal_reconnect(sdk):
    stop = threading.Event()
    made = []
    class ReconnectingClient(Client):
        async def reconnect(self):
            self.sdk.loop.call_later(0.01, stop.set)
            await asyncio.sleep(3600)
            pytest.fail('reconnect continued after stop')
        def start(self):
            self.sdk.loop.run_until_complete(self.reconnect())
    def factory():
        client = ReconnectingClient(sdk, stop)
        made.append(client)
        return client
    result = lifecycle.run_feishu_sdk(factory, stop, sdk_module=sdk, sdk_version='1.6.8')
    assert result.stop_requested and made[0].closed
