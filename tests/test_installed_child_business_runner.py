"""Authenticated-control composition tests with local command fixtures only."""
import queue
import threading
import pytest
from gateway.installed_channel_child_drain_runtime import InstalledChannelChildDrainRuntime, InstalledChannelChildDrainRuntimeError
from gateway.installed_channel_drain import InstalledChannelClaimTracker, InstalledChildDrainFence, InstalledChannelDrainContractError, InstalledDrainBinding, InstalledDrainCommand, InstalledDrainOperation
from gateway.installed_channel_supervisor_status import InstalledChannelProcessReceipt
from gateway.windows_installed_drain_pipe import WindowsInstalledDrainPipeTimeout

def setup(role='feishu'):
    binding=InstalledDrainBinding(installation_id='a'*64, installation_epoch=7, config_generation=11, service_boot_id='b'*64)
    process=InstalledChannelProcessReceipt(pid=5103, started_utc_ticks=133000000000000003, command_line_sha256='3'*64)
    fence=InstalledChildDrainFence(binding=binding, role=role, process=process)
    operation=InstalledDrainOperation(binding=binding, stop_id='c'*64, stop_generation=3, deadline_utc_ns=1900000000000000000)
    class Endpoint:
        incoming=queue.Queue()
        outgoing=queue.Queue()
        def receive_command(self):
            try: value=self.incoming.get(timeout=0.02)
            except queue.Empty:
                raise WindowsInstalledDrainPipeTimeout('idle', retry_safe=True)
            if isinstance(value, Exception): raise value
            return value
        def send_receipt(self, receipt): self.outgoing.put(receipt)
    endpoint=Endpoint()
    runtime=InstalledChannelChildDrainRuntime(endpoint=endpoint, fence=fence)
    return runtime, fence, operation, endpoint

@pytest.mark.parametrize('business_status', [0, 7])
def test_same_fence_and_exact_exit_event_keep_close_claims_separate(business_status):
    runtime,fence,operation,endpoint=setup()
    tracker=InstalledChannelClaimTracker('feishu')
    def business(*, stop_event):
        assert stop_event is runtime.exit_event
        assert tracker.commit(('one',), lambda: None)
        endpoint.incoming.put(InstalledDrainCommand(operation=operation, action='close_claims'))
        assert endpoint.outgoing.get(timeout=2).active_claims == 1
        assert not stop_event.is_set()
        assert not tracker.commit(('two',), lambda: pytest.fail('post-drain commit'))
        tracker.finish(('one',))
        endpoint.incoming.put(InstalledDrainCommand(operation=operation, action='exit'))
        assert endpoint.outgoing.get(timeout=2).phase == 'exit_requested'
        assert stop_event.wait(2)
        return business_status
    assert runtime.run_business(business, bind_fence=tracker.bind, join_timeout=1) == business_status
    runtime.raise_if_failed()

@pytest.mark.parametrize('result', [0, 7])
def test_business_early_return_is_not_authenticated_success(result):
    runtime,fence,_,_=setup()
    with pytest.raises(InstalledChannelChildDrainRuntimeError):
        runtime.run_business(lambda **kw: result, bind_fence=lambda f: None, join_timeout=1)
    assert runtime.wait(timeout=1)
    assert fence.try_begin_claim() is None

def test_business_setting_exit_event_cannot_forge_parent_exit():
    runtime,_,_,_=setup()
    def business(*, stop_event):
        stop_event.set()
        return 0
    with pytest.raises(InstalledChannelChildDrainRuntimeError):
        runtime.run_business(business, bind_fence=lambda f: None, join_timeout=1)

def test_business_exception_is_preserved_and_control_stops():
    runtime,_,_,_=setup()
    def business(**kw): raise ValueError('synthetic business failure')
    with pytest.raises(ValueError, match='synthetic business'):
        runtime.run_business(business, bind_fence=lambda f: None, join_timeout=1)
    assert runtime.wait(timeout=1)

def test_transport_failure_locally_fences_pending_and_new_work():
    runtime,fence,_,endpoint=setup()
    pending=fence.try_begin_claim()
    committed=fence.try_begin_claim()
    assert fence.commit_claim(committed)
    def business(*, stop_event):
        endpoint.incoming.put(RuntimeError('synthetic transport failure'))
        assert stop_event.wait(2)
        assert not fence.commit_claim(pending)
        assert fence.try_begin_claim() is None
        assert fence.try_enter_provider(committed) is None
        fence.finish_claim(committed)
        return 0
    with pytest.raises(InstalledChannelChildDrainRuntimeError):
        runtime.run_business(business, bind_fence=lambda f: None, join_timeout=1)

def test_wrong_role_binding_has_zero_business_calls():
    runtime,_,_,_=setup('weixin')
    tracker=InstalledChannelClaimTracker('feishu')
    with pytest.raises(InstalledChannelDrainContractError):
        runtime.run_business(lambda **kw: pytest.fail('business started'), bind_fence=tracker.bind, join_timeout=1)
    assert runtime._thread is None

def test_control_thread_start_failure_has_zero_business_calls(monkeypatch):
    runtime,_,_,_=setup()
    def fail(self): raise RuntimeError('synthetic thread failure')
    monkeypatch.setattr(threading.Thread, 'start', fail)
    with pytest.raises(InstalledChannelChildDrainRuntimeError):
        runtime.run_business(lambda **kw: pytest.fail('business started'), bind_fence=lambda f: None, join_timeout=1)
    assert runtime.wait(timeout=0)

def test_receipt_send_failure_is_not_authenticated_exit():
    runtime,fence,operation,endpoint=setup()
    fence.apply_command(InstalledDrainCommand(operation=operation, action='close_claims'))
    def fail(receipt): raise OSError('synthetic send failure')
    endpoint.send_receipt=fail
    def business(*, stop_event):
        endpoint.incoming.put(InstalledDrainCommand(operation=operation, action='exit'))
        assert stop_event.wait(2)
        return 0
    with pytest.raises(InstalledChannelChildDrainRuntimeError):
        runtime.run_business(business, bind_fence=lambda f: None, join_timeout=1)
    assert not runtime._authenticated_exit

@pytest.mark.parametrize('role', ['engine', 'weixin', 'feishu'])
def test_local_fail_close_preserves_active_work_and_blocks_all_new_permits(role):
    _,fence,operation,_=setup(role)
    begin=fence.try_begin_admission if role == 'engine' else fence.try_begin_claim
    commit=fence.commit_admission if role == 'engine' else fence.commit_claim
    finish=fence.finish_admission if role == 'engine' else fence.finish_claim
    active=begin()
    pending=begin()
    assert commit(active)
    provider=fence.try_enter_provider(active)
    fence.fail_closed()
    fence.fail_closed()
    assert begin() is None and not commit(pending)
    assert fence.try_enter_provider(active) is None
    # Control loss must not manufacture an authenticated operation/snapshot.
    with pytest.raises(InstalledChannelDrainContractError): fence.snapshot(operation=operation)
    with pytest.raises(InstalledChannelDrainContractError): finish(active)
    fence.finish_provider(provider)
    finish(active)

def test_local_stop_does_not_process_a_late_parent_command():
    runtime,fence,operation,endpoint=setup()
    fence.apply_command(InstalledDrainCommand(operation=operation, action='close_claims'))
    entered=threading.Event()
    release=threading.Event()
    def receive():
        entered.set()
        assert release.wait(2)
        return InstalledDrainCommand(operation=operation, action='exit')
    endpoint.receive_command=receive
    runtime.start()
    assert entered.wait(2)
    runtime.request_local_stop()
    release.set()
    assert runtime.wait(timeout=2)
    with pytest.raises(InstalledChannelChildDrainRuntimeError): runtime.raise_if_failed()
    assert endpoint.outgoing.empty()

def test_local_cancel_during_exit_receipt_send_cannot_become_success():
    runtime,fence,operation,endpoint=setup()
    fence.apply_command(InstalledDrainCommand(operation=operation, action='close_claims'))
    sending=threading.Event()
    release=threading.Event()
    def send(receipt):
        sending.set()
        assert release.wait(2)
        endpoint.outgoing.put(receipt)
    endpoint.send_receipt=send
    runtime.start()
    endpoint.incoming.put(InstalledDrainCommand(operation=operation, action='exit'))
    assert sending.wait(2)
    runtime.request_local_stop()
    release.set()
    assert runtime.wait(timeout=2)
    with pytest.raises(InstalledChannelChildDrainRuntimeError): runtime.raise_if_failed()
    assert not runtime._authenticated_exit
