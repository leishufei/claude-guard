"""Exercise WFP transactions and ctypes marshalling without system changes."""

import ctypes as ct
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import wfp_native as wfp


BINARY = r'c:\probe\isolated-probe.exe'
HELPER = r'c:\probe\helper.exe'


class AbiTests(unittest.TestCase):
    """Check SDK offsets independently of ctypes round-trip mocks."""

    def test_sdk_structure_sizes_alignment_and_offsets(self):
        is_64 = ct.sizeof(ct.c_void_p) == 8
        layouts = (
            (wfp.Sublayer, 72 if is_64 else 44, {
                'flags': 32 if is_64 else 24,
                'providerKey': 40 if is_64 else 28,
                'providerData': 48 if is_64 else 32,
                'weight': 64 if is_64 else 40}),
            (wfp.Filter, 200 if is_64 else 152, {
                'weight': 96 if is_64 else 72,
                'numFilterConditions': 112 if is_64 else 80,
                'filterCondition': 120 if is_64 else 84,
                'action': 128 if is_64 else 88,
                'context': 152 if is_64 else 112,
                'reserved': 168 if is_64 else 128,
                'filterId': 176 if is_64 else 136,
                'effectiveWeight': 184 if is_64 else 144}),
            (wfp.Value, 16 if is_64 else 8, {
                'value': 8 if is_64 else 4}),
            (wfp.Condition, 40 if is_64 else 28, {
                'value': 24 if is_64 else 20}),
        )
        for native_type, size, offsets in layouts:
            with self.subTest(native_type=native_type.__name__):
                self.assertEqual(ct.sizeof(native_type), size)
                for field, offset in offsets.items():
                    self.assertEqual(getattr(native_type, field).offset,
                                     offset, field)
        self.assertEqual(dict(wfp.Sublayer._fields_)['flags'], wfp.UINT32)
        self.assertEqual(ct.sizeof(wfp.Context), 16)
        self.assertEqual(ct.alignment(wfp.Context), 8)


class MemoryApi:
    """Model transactional persistent and session-owned dynamic objects."""

    def __init__(self):
        self.filters = {}
        self.handles = {}
        self.snapshots = {}
        self.events = []
        self.next_handle = 0
        self.fail = None

    def _event(self, name, *args):
        self.events.append((name, *args))
        if self.fail == name:
            raise wfp.WfpError(name, 5)

    def open(self, dynamic=False):
        self._event('open', dynamic)
        self.next_handle += 1
        self.handles[self.next_handle] = dynamic
        return self.next_handle

    def close(self, handle):
        self._event('close', handle)
        self.filters = {key: entry for key, entry in self.filters.items()
                        if entry[1] != handle}
        self.handles.pop(handle)

    def app_id(self, program):
        self._event('app_id', program)
        return (program + '\x00').encode('utf-16-le')

    def begin(self, handle):
        self._event('begin', handle)
        self.snapshots[handle] = dict(self.filters)

    def commit(self, handle):
        self._event('commit', handle)
        self.snapshots.pop(handle)

    def abort(self, handle):
        self._event('abort', handle)
        self.filters = self.snapshots.pop(handle)

    def ensure_sublayer(self, handle):
        self._event('ensure_sublayer', handle)

    def verify_sublayer(self, handle):
        self._event('verify_sublayer', handle)

    def add_filter(self, handle, spec, existing_allowed):
        self._event('add_filter', handle, spec)
        if spec.key in self.filters:
            if not existing_allowed or self.filters[spec.key][0] != spec:
                raise wfp.WfpError('collision')
        else:
            owner = handle if self.handles[handle] else None
            self.filters[spec.key] = (spec, owner)

    def verify_filter(self, handle, spec):
        self._event('verify_filter', handle, spec)
        if self.filters[spec.key][0] != spec:
            raise wfp.WfpError('readback mismatch')


class BackendTests(unittest.TestCase):

    def setUp(self):
        self.api = MemoryApi()
        self.backend = wfp.WfpBackend(self.api)

    def test_exact_scope_persistent_baseline_and_dynamic_permit(self):
        keys = self.backend.ensure((BINARY, HELPER), 54321)
        specs = [entry[0] for entry in self.api.filters.values()]
        self.assertEqual(len(keys), 10)
        baseline = [spec for spec in specs if spec.flags == wfp.PERSISTENT]
        permits = [spec for spec in specs if spec.action == wfp.PERMIT]
        self.assertEqual(len(baseline), 8)
        self.assertEqual({spec.layer for spec in baseline},
                         set(wfp.BASELINE_LAYERS))
        for spec in baseline:
            self.assertEqual(spec.action, wfp.BLOCK)
            self.assertEqual(len(spec.conditions), 1)
        for spec in permits:
            self.assertEqual(spec.layer, wfp.CONNECT_V4)
            self.assertEqual(spec.flags, 0)
            self.assertGreater(spec.weight, baseline[0].weight)
            self.assertEqual(spec.conditions[1:], (
                (wfp.PROTOCOL, 1, 6),
                (wfp.REMOTE_ADDRESS, 3, 0x7f000001),
                (wfp.REMOTE_PORT, 2, 54321)))
        commits = [event for event in self.api.events if event[0] == 'commit']
        self.assertEqual(len(commits), 2)
        self.assertLess(self.api.events.index(commits[0]),
                        self.api.events.index(('open', True)))

    def test_revoke_is_idempotent_and_preserves_baseline(self):
        self.backend.revoke_proxy_access()
        keys = self.backend.ensure((BINARY,), 54321)
        self.backend.revoke_proxy_access()
        self.backend.revoke_proxy_access()
        self.assertEqual(set(self.api.filters), set(keys[:-1]))
        self.assertFalse(self.api.handles)

    def test_repeated_ensure_reuses_session_but_reads_policy_again(self):
        keys = self.backend.ensure((BINARY,), 54321)
        dynamic = self.backend._permit_handle
        self.api.events.clear()
        self.assertEqual(self.backend.ensure((BINARY,), 54321), keys)
        self.assertEqual(self.backend._permit_handle, dynamic)
        self.assertNotIn(('open', True), self.api.events)
        self.assertTrue(any(event[0] == 'verify_filter'
                            and event[2].action == wfp.PERMIT
                            for event in self.api.events))

    def test_new_port_revokes_old_lease_before_adding_new(self):
        self.backend.ensure((BINARY,), 54321)
        old_handle = self.backend._permit_handle
        self.backend.ensure((BINARY,), 54322)
        self.assertNotIn(old_handle, self.api.handles)
        self.assertEqual(len(self.api.filters), 5)
        permit = next(spec for spec, _ in self.api.filters.values()
                      if spec.action == wfp.PERMIT)
        self.assertEqual(permit.conditions[-1][-1], 54322)

    def test_baseline_partial_failure_rolls_back_and_never_opens_permit(self):
        add = self.api.add_filter

        def fail_second(handle, spec, existing):
            if len(self.api.filters) == 1:
                raise wfp.WfpError('second filter', 5)
            add(handle, spec, existing)

        self.api.add_filter = fail_second
        with self.assertRaises(wfp.WfpError):
            self.backend.ensure((BINARY,), 54321)
        self.assertFalse(self.api.filters)
        self.assertNotIn(('open', True), self.api.events)
        self.assertTrue(any(event[0] == 'abort' for event in self.api.events))

    def test_permit_partial_failure_keeps_all_committed_baseline(self):
        add = self.api.add_filter

        def fail_second_permit(handle, spec, existing):
            if spec.action == wfp.PERMIT and spec.conditions[0][2] == (
                    HELPER + '\x00').encode('utf-16-le'):
                raise wfp.WfpError('second permit', 5)
            add(handle, spec, existing)

        self.api.add_filter = fail_second_permit
        with self.assertRaises(wfp.WfpError):
            self.backend.ensure((BINARY, HELPER), 54321)
        self.assertEqual(len(self.api.filters), 8)
        self.assertTrue(all(spec.action == wfp.BLOCK
                            for spec, _ in self.api.filters.values()))
        self.assertFalse(self.api.handles)

    def test_transaction_errors_and_timeouts_never_authorize(self):
        for operation in ('begin', 'commit', 'verify_sublayer'):
            with self.subTest(operation=operation):
                api = MemoryApi()
                api.fail = operation
                with self.assertRaises(wfp.WfpError):
                    wfp.WfpBackend(api).ensure((BINARY,), 54321)
                self.assertFalse(api.handles)
        self.api.commit = Mock(side_effect=TimeoutError('RPC timeout'))
        with self.assertRaises(TimeoutError):
            self.backend.ensure((BINARY,), 54321)
        self.assertFalse(self.api.filters)

    def test_dynamic_commit_failure_rolls_back_only_permits(self):
        commit = self.api.commit

        def fail_dynamic(handle):
            if self.api.handles[handle]:
                raise wfp.WfpError('dynamic commit', 5)
            commit(handle)

        self.api.commit = fail_dynamic
        with self.assertRaises(wfp.WfpError):
            self.backend.ensure((BINARY,), 54321)
        self.assertEqual(len(self.api.filters), 4)
        self.assertFalse(self.api.handles)

    def test_rollback_preserves_rules_for_previous_paths(self):
        old_keys = self.backend.ensure((BINARY,), 54321)[:-1]
        self.backend.revoke_proxy_access()
        self.api.fail = 'add_filter'
        with self.assertRaises(wfp.WfpError):
            self.backend.ensure((HELPER,), 54321)
        self.assertEqual(set(self.api.filters), set(old_keys))

    def test_abort_failure_is_reported_and_dynamic_session_still_closed(self):
        commit = self.api.commit

        def fail_dynamic(handle):
            if self.api.handles[handle]:
                self.api.fail = 'abort'
                raise TimeoutError('commit timeout')
            commit(handle)

        self.api.commit = fail_dynamic
        with self.assertRaisesRegex(wfp.WfpError, 'abort'):
            self.backend.ensure((BINARY,), 54321)
        self.assertEqual(len(self.api.filters), 4)
        self.assertFalse(self.api.handles)

    def test_postcommit_readback_failure_revokes_permits(self):
        verify = self.api.verify_filter

        def fail_permit_readback(handle, spec):
            if spec.action == wfp.PERMIT:
                raise wfp.WfpError('readback')
            verify(handle, spec)

        self.api.verify_filter = fail_permit_readback
        with self.assertRaises(wfp.WfpError):
            self.backend.ensure((BINARY,), 54321)
        self.assertEqual(len(self.api.filters), 4)
        self.assertFalse(self.api.handles)

    def test_failed_close_keeps_handle_for_retry(self):
        self.backend.ensure((BINARY,), 54321)
        handle = self.backend._permit_handle
        self.api.fail = 'close'
        with self.assertRaises(wfp.WfpError):
            self.backend.revoke_proxy_access()
        self.assertEqual(self.backend._permit_handle, handle)
        self.api.fail = None
        self.backend.revoke_proxy_access()
        self.assertEqual(len(self.api.filters), 4)

    def test_changed_identity_or_invalid_config_revokes_previous_permit(self):
        self.backend.ensure((BINARY,), 54321)
        with self.assertRaises(wfp.WfpError):
            self.backend.ensure((), 54321)
        self.assertEqual(len(self.api.filters), 4)
        self.assertIsNone(self.backend._permit_handle)


class NativeBindingTests(unittest.TestCase):

    def setUp(self):
        self.api = wfp.NativeApi.__new__(wfp.NativeApi)
        self.api.dll = Mock()
        self.spec = wfp._spec(BINARY, b'app-id\x00', wfp.CONNECT_V4, 54321)
        self.native = None

        def add(handle, pointer, security, filter_id):
            self.native = pointer._obj
            self.native.effectiveWeight = self.native.weight
            return 0

        def get(handle, key, output):
            ct.cast(output, ct.POINTER(ct.POINTER(wfp.Filter)))[0] = (
                ct.pointer(self.native))
            return 0

        self.api.dll.FwpmFilterAdd0.side_effect = add
        self.api.dll.FwpmFilterGetByKey0.side_effect = get

    def test_filter_marshalling_and_readback_use_exact_host_order_values(self):
        self.api.add_filter(1, self.spec, False)
        self.assertEqual(self.native.subLayerKey.text(), wfp.SUBLAYER_KEY)
        self.assertEqual(self.native.filterCondition[2].value.uint32,
                         0x7f000001)
        self.assertEqual(self.native.filterCondition[3].value.uint16, 54321)
        self.api.dll.FwpmFreeMemory0.assert_called_once()

    def test_indexed_bit_is_allowed_but_disabled_or_scope_changes_fail(self):
        self.api.add_filter(1, self.spec, False)
        self.native.flags |= wfp.INDEXED
        self.api.verify_filter(1, self.spec)
        self.native.flags |= 0x20
        with self.assertRaises(wfp.WfpError):
            self.api.verify_filter(1, self.spec)
        self.native.flags = 0
        self.native.filterCondition[3].value.uint16 = 54322
        with self.assertRaises(wfp.WfpError):
            self.api.verify_filter(1, self.spec)

    def test_readback_error_code_and_allocation_cleanup(self):
        self.api.add_filter(1, self.spec, False)
        self.native.weight.type = 0
        with self.assertRaises(wfp.WfpError):
            self.api.verify_filter(1, self.spec)
        self.assertEqual(self.api.dll.FwpmFreeMemory0.call_count, 2)
        self.api.dll.FwpmFilterGetByKey0.side_effect = None
        self.api.dll.FwpmFilterGetByKey0.return_value = 5
        with self.assertRaisesRegex(wfp.WfpError, '0x00000005'):
            self.api.verify_filter(1, self.spec)

    def test_existing_filter_is_verified_never_deleted_or_replaced(self):
        self.api.add_filter(1, self.spec, False)
        self.api.dll.FwpmFilterAdd0.side_effect = None
        self.api.dll.FwpmFilterAdd0.return_value = wfp.ALREADY_EXISTS
        self.api.add_filter(1, self.spec, True)
        with self.assertRaises(wfp.WfpError):
            self.api.add_filter(1, self.spec, False)
        self.assertFalse(self.api.dll.FwpmFilterDeleteByKey0.called)

    def test_stable_keys_separate_layers_ports_and_upgrade_paths(self):
        spec = wfp._spec(BINARY, b'id', wfp.CONNECT_V4)
        self.assertEqual(spec, wfp._spec(BINARY, b'id', wfp.CONNECT_V4))
        others = [wfp._spec(BINARY, b'id', layer).key
                  for layer in wfp.BASELINE_LAYERS]
        others.extend((self.spec.key,
                       wfp._spec(BINARY, b'id', wfp.CONNECT_V4, 54322).key,
                       wfp._spec(HELPER, b'id', wfp.CONNECT_V4).key))
        self.assertEqual(len(set(others)), len(others))

    def test_dynamic_session_flags_and_transaction_wait_are_explicit(self):
        def open_engine(server, authentication, identity, session, output):
            self.assertEqual(authentication, 10)
            self.assertEqual(session._obj.flags, wfp.DYNAMIC)
            self.assertEqual(session._obj.txnWaitTimeoutInMSec, 5000)
            output._obj.value = 123
            return 0

        self.api.dll.FwpmEngineOpen0.side_effect = open_engine
        self.assertEqual(self.api.open(dynamic=True).value, 123)

    def test_sublayer_collision_requires_persistent_exact_readback(self):
        layer = wfp.Sublayer()
        layer.subLayerKey = wfp.GUID.parse(wfp.SUBLAYER_KEY)
        layer.flags = wfp.PERSISTENT
        layer.weight = wfp.SUBLAYER_WEIGHT

        def get(handle, key, output):
            ct.cast(output, ct.POINTER(ct.POINTER(wfp.Sublayer)))[0] = (
                ct.pointer(layer))
            return 0

        self.api.dll.FwpmSubLayerAdd0.return_value = wfp.ALREADY_EXISTS
        self.api.dll.FwpmSubLayerGetByKey0.side_effect = get
        self.api.ensure_sublayer(1)
        layer.flags = 0
        with self.assertRaisesRegex(wfp.WfpError,
                                    'FwpmSubLayerAdd0=already_exists'):
            self.api.ensure_sublayer(1)

    def test_assigned_sublayer_weight_is_reported_without_accepting_it(self):
        layer = wfp.Sublayer()
        layer.subLayerKey = wfp.GUID.parse(wfp.SUBLAYER_KEY)
        layer.flags = wfp.PERSISTENT
        layer.weight = 0x8003

        def get(handle, key, output):
            ct.cast(output, ct.POINTER(ct.POINTER(wfp.Sublayer)))[0] = (
                ct.pointer(layer))
            return 0

        self.api.dll.FwpmSubLayerAdd0.return_value = 0
        self.api.dll.FwpmSubLayerGetByKey0.side_effect = get
        with self.assertRaisesRegex(
                wfp.WfpError, 'weight=32771.*FwpmSubLayerAdd0=created'):
            self.api.ensure_sublayer(1)
        self.api.dll.FwpmFreeMemory0.assert_called_once()

    def test_sublayer_requests_sparse_weight_and_requires_exact_readback(self):
        layer = wfp.Sublayer()

        def add(handle, pointer, security):
            ct.memmove(ct.byref(layer), pointer, ct.sizeof(layer))
            self.assertEqual(layer.weight, 0x1234)
            return 0

        def get(handle, key, output):
            ct.cast(output, ct.POINTER(ct.POINTER(wfp.Sublayer)))[0] = (
                ct.pointer(layer))
            return 0

        self.api.dll.FwpmSubLayerAdd0.side_effect = add
        self.api.dll.FwpmSubLayerGetByKey0.side_effect = get
        self.api.ensure_sublayer(1)
        layer.weight += 1
        with self.assertRaisesRegex(wfp.WfpError, 'weight=4661'):
            self.api.verify_sublayer(1)

    def test_sublayer_sdk_bytes_ignore_padding_but_reject_all_flag_bits(self):
        is_64 = ct.sizeof(ct.c_void_p) == 8
        raw = ct.create_string_buffer(72 if is_64 else 44)
        raw[:16] = bytes(wfp.GUID.parse(wfp.SUBLAYER_KEY))
        flags_offset = 32 if is_64 else 24
        weight_offset = 64 if is_64 else 40
        struct.pack_into('<I', raw, flags_offset, wfp.PERSISTENT)
        struct.pack_into('<H', raw, weight_offset, wfp.SUBLAYER_WEIGHT)
        if is_64:
            raw[36:40] = b'\xa5' * 4
            raw[52:56] = b'\xa5' * 4
        raw[weight_offset + 2:ct.sizeof(raw)] = (
            b'\xa5' * (ct.sizeof(raw) - weight_offset - 2))

        def get(handle, key, output):
            ct.cast(output, ct.POINTER(ct.POINTER(wfp.Sublayer)))[0] = (
                ct.cast(raw, ct.POINTER(wfp.Sublayer)))
            return 0

        self.api.dll.FwpmSubLayerGetByKey0.side_effect = get
        self.api.verify_sublayer(1)
        struct.pack_into('<I', raw, flags_offset, 0x00010001)
        with self.assertRaisesRegex(wfp.WfpError, 'flags=0x00010001'):
            self.api.verify_sublayer(1)
        self.assertEqual(self.api.dll.FwpmFreeMemory0.call_count, 2)

    def test_sublayer_mismatch_diagnostics_and_strict_fields(self):
        layer = wfp.Sublayer()
        layer.subLayerKey = wfp.GUID.parse(wfp.SUBLAYER_KEY)
        layer.flags = wfp.PERSISTENT
        layer.weight = wfp.SUBLAYER_WEIGHT

        def get(handle, key, output):
            ct.cast(output, ct.POINTER(ct.POINTER(wfp.Sublayer)))[0] = (
                ct.pointer(layer))
            return 0

        self.api.dll.FwpmSubLayerGetByKey0.side_effect = get
        provider = wfp.GUID.parse(wfp.CONNECT_V4)
        secret = b'private-provider-payload'
        data = (wfp.UINT8 * len(secret)).from_buffer_copy(secret)
        changes = (
            ('subLayerKey', provider), ('flags', 0), ('weight', 1),
            ('providerKey', ct.pointer(provider)),
            ('providerData', wfp.Blob(len(secret), data)),
        )
        original = bytes(layer)
        for field, value in changes:
            with self.subTest(field=field):
                ct.memmove(ct.byref(layer), original, len(original))
                setattr(layer, field, value)
                with self.assertRaises(wfp.WfpError) as caught:
                    self.api.verify_sublayer(1)
                message = str(caught.exception)
                for label in ('key=', 'flags=', 'weight=', 'providerKey=',
                              'providerData.size=', 'providerData.present='):
                    self.assertIn(label, message)
                self.assertNotIn(secret.decode(), message)
                self.assertNotIn(hex(ct.addressof(data)), message)
        self.assertEqual(self.api.dll.FwpmFreeMemory0.call_count, len(changes))

    def test_filter_sdk_context_padding_and_readback_offsets(self):
        self.api.add_filter(1, self.spec, False)
        is_64 = ct.sizeof(ct.c_void_p) == 8
        raw = ct.create_string_buffer(bytes(self.native), ct.sizeof(wfp.Filter))
        action_end = 148 if is_64 else 108
        context_offset = 152 if is_64 else 112
        raw[action_end:context_offset] = b'\xa5' * 4
        struct.pack_into('<Q', raw, 176 if is_64 else 136, 0x123456789abcdef0)

        def get(handle, key, output):
            ct.cast(output, ct.POINTER(ct.POINTER(wfp.Filter)))[0] = (
                ct.cast(raw, ct.POINTER(wfp.Filter)))
            return 0

        self.api.dll.FwpmFilterGetByKey0.side_effect = get
        self.api.verify_filter(1, self.spec)
        struct.pack_into('<Q', raw, context_offset, 1)
        with self.assertRaisesRegex(wfp.WfpError, 'rawContext.nonzero=True'):
            self.api.verify_filter(1, self.spec)


if __name__ == '__main__':
    unittest.main()
