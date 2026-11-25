"""Actual bridge orchestration with SDK/transport/business side effects stubbed."""
from types import SimpleNamespace
import threading
import pytest
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location('feishu_durable_fixture', Path(__file__).with_name('test_feishu_durable_bridge.py'))
_fixtures = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixtures)
_load_state_runner_without_sdk = _fixtures._load_state_runner_without_sdk
_control_spec = importlib.util.spec_from_file_location('installed_control_fixture', Path(__file__).with_name('test_installed_child_business_runner.py'))
_control_fixtures = importlib.util.module_from_spec(_control_spec)
_control_spec.loader.exec_module(_control_fixtures)

@pytest.fixture
def runner(monkeypatch):
    module = _load_state_runner_without_sdk(monkeypatch)
    monkeypatch.setattr(module, '_mark_disconnected', lambda *args: None)
    monkeypatch.setattr(module, '_connection_generation', lambda: 0)
    return module

def test_connection_stop_does_not_recreate_client(runner, monkeypatch):
    stop = threading.Event()
    calls = []
    monkeypatch.setattr(runner.lark.ws, 'Client', lambda *a, **k: SimpleNamespace())
    def run(factory, event):
        calls.append(factory())
        assert event is stop
        stop.set()
    monkeypatch.setattr(runner, 'run_feishu_sdk', run)
    assert runner._run_feishu_connections('test', 'synthetic', object(), stop) == 0
    assert len(calls) == 1 and runner._CURRENT_WS is None

def test_connection_shutdown_failure_is_not_retried(runner, monkeypatch):
    stop = threading.Event()
    calls = []
    def fail(*args):
        calls.append(1)
        raise runner.FeishuSdkLifecycleError('synthetic')
    monkeypatch.setattr(runner, 'run_feishu_sdk', fail)
    assert runner._run_feishu_connections('test', 'synthetic', object(), stop) == 1
    assert stop.is_set() and calls == [1]

def test_backoff_is_stop_aware(runner, monkeypatch):
    class StopDuringWait:
        stopped = False
        waits = []
        def is_set(self): return self.stopped
        def wait(self, delay):
            self.waits.append(delay)
            self.stopped = True
            return True
    stop = StopDuringWait()
    calls = []
    monkeypatch.setattr(runner, 'run_feishu_sdk', lambda *args: calls.append(1))
    monkeypatch.setattr(runner, '_reconnect_backoff_step', lambda *a, **k: (3, 6))
    assert runner._run_feishu_connections('test', 'synthetic', object(), stop) == 0
    assert calls == [1] and stop.waits == [3]

def test_pre_stopped_main_has_no_channel_effects(runner, monkeypatch):
    stop = threading.Event()
    stop.set()
    monkeypatch.setattr(runner.socket, 'socket', lambda *args: pytest.fail('socket created'))
    assert runner.main(stop_event=stop) == 0

@pytest.mark.parametrize('outcome,workers_clean,health_ok,control_mode', [(0, True, True, None), (1, True, True, None), (0, False, True, None), (0, True, False, None), (0, True, True, 'exit'), (0, True, True, 'failure'), (0, True, True, 'early')])
def test_main_releases_singleton_only_after_full_local_cleanup(runner, monkeypatch, tmp_path, outcome, workers_clean, health_ok, control_mode):
    events = []
    socket = SimpleNamespace(bind=lambda a: None, close=lambda: events.append('socket_closed'))
    monkeypatch.setattr(runner.socket, 'socket', lambda *args: socket)
    monkeypatch.setattr(runner, 'S', SimpleNamespace(feishu_app_id='test', feishu_app_secret='synthetic', usage_db_path=str(tmp_path/'usage.db')))
    builder = SimpleNamespace()
    for name in ('app_id', 'app_secret', 'register_p2_im_message_receive_v1'):
        setattr(builder, name, lambda *args: builder)
    builder.build = lambda: object()
    monkeypatch.setattr(runner.lark, 'Client', SimpleNamespace(builder=lambda: builder))
    monkeypatch.setattr(runner.lark, 'EventDispatcherHandler', SimpleNamespace(builder=lambda *a: builder), raising=False)
    for name in ('_validate_recovery_ledgers_before_channel_start', '_recover_inflight', '_feed_pending_videos'):
        monkeypatch.setattr(runner, name, lambda: None)
    for name in ('_start_inbound_workers', '_start_video_workers'):
        monkeypatch.setattr(runner, name, lambda *a, **k: [])
    class Worker:
        def __init__(self, **kwargs): pass
        def start(self): pass
        def is_alive(self): return False
    real_thread = threading.Thread
    def thread_factory(**kwargs):
        if kwargs.get('name') == 'nachuan-installed-drain-control':
            return real_thread(**kwargs)
        return Worker(**kwargs)
    monkeypatch.setattr(runner.threading, 'Thread', thread_factory)
    control,fence,operation,endpoint=_control_fixtures.setup()
    def connections(*args):
        if control_mode:
            event=args[-1]
            assert event is control.exit_event
            from gateway.installed_channel_drain import InstalledDrainCommand
            endpoint.incoming.put(InstalledDrainCommand(operation=operation, action='close_claims'))
            assert endpoint.outgoing.get(timeout=2).phase == 'drained'
            assert not event.is_set()
            if control_mode == 'exit':
                endpoint.incoming.put(InstalledDrainCommand(operation=operation, action='exit'))
            elif control_mode == 'failure':
                endpoint.incoming.put(OSError('synthetic connection failed'))
            else:
                event.set()
            assert event.wait(2)
        return outcome
    monkeypatch.setattr(runner, '_run_feishu_connections', connections)
    def joined(*args):
        runner._HEALTH_STATE['service_state'] = 'degraded'
        return workers_clean
    monkeypatch.setattr(runner, '_join_bridge_workers', joined)
    def health():
        events.append(runner._HEALTH_STATE['service_state'])
        if not health_ok:
            raise OSError('synthetic health write failed')
    monkeypatch.setattr(runner, '_update_health', health)
    stop = control.exit_event if control_mode else threading.Event()
    expected = 0 if outcome == 0 and workers_clean and health_ok and control_mode not in ('failure', 'early') else 1
    arguments={'control_runtime': control} if control_mode else {'stop_event': stop}
    assert runner.main(**arguments) == expected
    assert stop.is_set() and 'stopping' in events
    assert ('socket_closed' in events) == (expected == 0)
    if expected == 0:
        assert events == ['stopping', 'socket_closed']
        if control_mode:
            assert runner.main() == 1
    if expected:
        monkeypatch.setattr(runner.socket, 'socket', lambda *args: pytest.fail('terminal main reopened'))
        assert runner.main() == 1

def test_startup_failure_enters_cleanup_without_masking_error(runner, monkeypatch, tmp_path):
    stop = threading.Event()
    monkeypatch.setattr(runner.socket, 'socket', lambda *args: SimpleNamespace(bind=lambda *a: None, close=lambda: pytest.fail('failed startup released singleton')))
    monkeypatch.setattr(runner, 'S', SimpleNamespace(feishu_app_id='test', feishu_app_secret='synthetic', usage_db_path=str(tmp_path/'usage.db')))
    def broken(): raise ValueError('synthetic preflight failure')
    monkeypatch.setattr(runner, '_validate_recovery_ledgers_before_channel_start', broken)
    monkeypatch.setattr(runner, '_update_health', broken)
    with pytest.raises(ValueError, match='preflight'):
        runner.main(stop_event=stop)
    assert stop.is_set() and runner._BRIDGE_SHUTDOWN_INCOMPLETE

def test_worker_join_uses_one_deadline(runner, monkeypatch):
    clock = iter([10.0, 10.1, 10.3])
    monkeypatch.setattr(runner.time, 'monotonic', lambda: next(clock))
    joins = []
    worker = SimpleNamespace(is_alive=lambda: True, join=lambda timeout: joins.append(timeout))
    assert not runner._join_bridge_workers([worker, worker], timeout=1.0)
    assert joins == pytest.approx([0.9, 0.7])

def test_control_cannot_bind_over_a_running_source_bridge(runner, monkeypatch):
    control,_,_,_=_control_fixtures.setup()
    runner._BRIDGE_WORKERS.append(SimpleNamespace(is_alive=lambda: True))
    assert runner.main(control_runtime=control) == 1
    assert not runner._BRIDGE_CONTROL_BOUND and control._thread is None

def test_control_rejects_a_separate_untrusted_exit_event(runner):
    control,_,_,_=_control_fixtures.setup()
    assert runner.main(control_runtime=control, stop_event=threading.Event()) == 1
    assert control._thread is None and not runner._BRIDGE_CONTROL_BOUND

def test_entry_lock_covers_startup_before_any_worker_exists(runner, monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    results = []
    errors = []
    def startup(**kwargs):
        assert not entered.is_set(), 'second entry reached business startup'
        entered.set()
        assert release.wait(3)
        return 0
    monkeypatch.setattr(runner, '_run_bridge_main', startup)
    control,_,_,_ = _control_fixtures.setup()
    def source():
        try: results.append(runner.main())
        except BaseException as exc: errors.append(type(exc).__name__)
    worker = threading.Thread(target=source, daemon=True)
    worker.start()
    try:
        assert entered.wait(2)
        assert runner._BRIDGE_WORKERS == []
        assert runner.main(control_runtime=control) == 1
        assert not runner._BRIDGE_CONTROL_BOUND and control._thread is None
    finally:
        release.set()
        worker.join(3)
    assert not worker.is_alive() and results == [0] and errors == []

def test_entry_lock_is_released_when_startup_raises(runner, monkeypatch):
    def failed(**kwargs): raise ValueError('synthetic startup error')
    monkeypatch.setattr(runner, '_run_bridge_main', failed)
    with pytest.raises(ValueError): runner.main()
    monkeypatch.setattr(runner, '_run_bridge_main', lambda **kwargs: 0)
    assert runner.main() == 0
