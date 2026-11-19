"""Native WFP enforcement for explicit executable paths on Windows.

Persistent ALE connect/receive blocks survive this process; permits belong to a
dynamic session and disappear on session close or owner process termination.
Only TCP to the supplied IPv4 loopback port is permitted in our sublayer.
This does not authenticate that listener or prevent it forwarding traffic.
Callers must stop protected processes before policy changes and on failure:
ALE reauthorization is not a measured zero-packet teardown guarantee. Brokers,
VMs, other executable paths, and pre-BFE boot traffic are outside this scope.
Inbound accepts are denied without exceptions, including local Claude bridges.

ABI definitions follow the Windows SDK fwpmtypes.h, fwptypes.h, and fwpmu.h.
No DLL is loaded and no policy is changed merely by importing this module.
"""

import ctypes as ct
from dataclasses import dataclass
import os
import threading
import uuid


UINT8 = ct.c_uint8
UINT16 = ct.c_uint16
UINT32 = ct.c_uint32
UINT64 = ct.c_uint64
HANDLE = ct.c_void_p
PERSISTENT = 1
DYNAMIC = 1
BLOCK = 0x1001
PERMIT = 0x1002
ALREADY_EXISTS = 0x80320009
INDEXED = 0x40
APP_ID = 'd78e1e87-8644-4ea5-9437-d809ecefc971'
REMOTE_ADDRESS = 'b235ae9a-1d64-49b8-a44c-5ff3d9095045'
REMOTE_PORT = 'c35a604d-d22b-4e1a-91b4-68f674ee674b'
PROTOCOL = '3971ef2b-623e-4f9a-8cb1-6e79b806b9a7'
CONNECT_V4 = 'c38d57d1-05a7-4c33-904f-7fbceee60e82'
CONNECT_V6 = '4a72393b-319f-44bc-84c3-ba54dcb3b6b4'
RECV_ACCEPT_V4 = 'e1cd9fe7-f4b5-4273-96c0-592e487b8650'
RECV_ACCEPT_V6 = 'a3b42c97-9f04-4672-b87e-cee9c483257f'
BASELINE_LAYERS = (CONNECT_V4, CONNECT_V6, RECV_ACCEPT_V4, RECV_ACCEPT_V6)
NAMESPACE = uuid.UUID('c7279948-5ef2-49e1-b99a-e675509926eb')
SUBLAYER_KEY = str(uuid.uuid5(NAMESPACE, 'proxy-isolation-v1'))
# BFE assigns the nearest available weight on collision (SDK provider sample).
# Avoid the common 0x8000 request; fail closed if this value also collides.
SUBLAYER_WEIGHT = 0x1234


class WfpError(RuntimeError):
    """An API operation or policy verification failed."""

    def __init__(self, operation, code=None):
        self.code = code
        suffix = '' if code is None else f' (0x{code:08x})'
        super().__init__(operation + suffix)


class GUID(ct.Structure):
    _fields_ = [('data1', UINT32), ('data2', UINT16), ('data3', UINT16),
                ('data4', UINT8 * 8)]

    @classmethod
    def parse(cls, value):
        return cls.from_buffer_copy(uuid.UUID(value).bytes_le)

    def text(self):
        return str(uuid.UUID(bytes_le=bytes(self)))


class DisplayData(ct.Structure):
    _fields_ = [('name', ct.c_wchar_p), ('description', ct.c_wchar_p)]


class Blob(ct.Structure):
    _fields_ = [('size', UINT32), ('data', ct.POINTER(UINT8))]


class ValueUnion(ct.Union):
    _fields_ = [('uint8', UINT8), ('uint16', UINT16), ('uint32', UINT32),
                ('uint64', ct.POINTER(UINT64)),
                ('byteBlob', ct.POINTER(Blob)), ('pointer', ct.c_void_p)]


class Value(ct.Structure):
    _anonymous_ = ('value',)
    _fields_ = [('type', UINT32), ('value', ValueUnion)]


class Condition(ct.Structure):
    _fields_ = [('fieldKey', GUID), ('matchType', UINT32), ('value', Value)]


class Action(ct.Structure):
    _fields_ = [('type', UINT32), ('filterType', GUID)]


class Context(ct.Union):
    # UINT64 gives this SDK union 8-byte alignment, including on Win32.
    _fields_ = [('rawContext', UINT64), ('providerContextKey', GUID)]


class Filter(ct.Structure):
    _fields_ = [('filterKey', GUID), ('displayData', DisplayData),
                ('flags', UINT32), ('providerKey', ct.POINTER(GUID)),
                ('providerData', Blob), ('layerKey', GUID),
                ('subLayerKey', GUID), ('weight', Value),
                ('numFilterConditions', UINT32),
                ('filterCondition', ct.POINTER(Condition)), ('action', Action),
                ('context', Context), ('reserved', ct.POINTER(GUID)),
                ('filterId', UINT64), ('effectiveWeight', Value)]


class Sublayer(ct.Structure):
    # fwpmtypes.h defines flags as UINT32; only weight is UINT16.
    _fields_ = [('subLayerKey', GUID), ('displayData', DisplayData),
                ('flags', UINT32), ('providerKey', ct.POINTER(GUID)),
                ('providerData', Blob), ('weight', UINT16)]


class Session(ct.Structure):
    _fields_ = [('sessionKey', GUID), ('displayData', DisplayData),
                ('flags', UINT32), ('txnWaitTimeoutInMSec', UINT32),
                ('processId', UINT32), ('sid', ct.c_void_p),
                ('username', ct.c_wchar_p), ('kernelMode', ct.c_int32)]


@dataclass(frozen=True)
class FilterSpec:
    """Canonical policy used both for installation and exact readback."""

    key: str
    layer: str
    flags: int
    action: int
    weight: int
    conditions: tuple


def _spec(program, app_id, layer, port=None):
    role = 'deny' if port is None else f'proxy-{port}'
    conditions = ((APP_ID, 12, app_id),)
    if port is not None:
        conditions += ((PROTOCOL, 1, 6),
                       (REMOTE_ADDRESS, 3, 0x7f000001),
                       (REMOTE_PORT, 2, port))
    return FilterSpec(str(uuid.uuid5(NAMESPACE, f'{program}|{layer}|{role}')),
                      layer, PERSISTENT if port is None else 0,
                      BLOCK if port is None else PERMIT,
                      1 if port is None else 2, conditions)


def _check(code, operation):
    if code:
        raise WfpError(operation, code)


class NativeApi:
    """Typed bindings to fwpuclnt; all allocations are freed by their owner."""

    def __init__(self):
        if os.name != 'nt':
            raise WfpError('WFP requires Windows')
        self.dll = ct.WinDLL('fwpuclnt.dll', winmode=0x800)
        signatures = {
            'FwpmEngineOpen0': [ct.c_wchar_p, UINT32, ct.c_void_p,
                                ct.POINTER(Session), ct.POINTER(HANDLE)],
            'FwpmEngineClose0': [HANDLE],
            'FwpmTransactionBegin0': [HANDLE, UINT32],
            'FwpmTransactionCommit0': [HANDLE],
            'FwpmTransactionAbort0': [HANDLE],
            'FwpmSubLayerAdd0': [HANDLE, ct.POINTER(Sublayer), ct.c_void_p],
            'FwpmSubLayerGetByKey0': [HANDLE, ct.POINTER(GUID),
                                     ct.POINTER(ct.POINTER(Sublayer))],
            'FwpmFilterAdd0': [HANDLE, ct.POINTER(Filter), ct.c_void_p,
                               ct.POINTER(UINT64)],
            'FwpmFilterGetByKey0': [HANDLE, ct.POINTER(GUID),
                                   ct.POINTER(ct.POINTER(Filter))],
            'FwpmGetAppIdFromFileName0': [ct.c_wchar_p,
                                         ct.POINTER(ct.POINTER(Blob))],
            'FwpmFreeMemory0': [ct.POINTER(ct.c_void_p)],
        }
        for name, arguments in signatures.items():
            function = getattr(self.dll, name)
            function.argtypes = arguments
            function.restype = None if name == 'FwpmFreeMemory0' else UINT32

    def _free(self, pointer):
        self.dll.FwpmFreeMemory0(ct.cast(ct.byref(pointer),
                                       ct.POINTER(ct.c_void_p)))

    def open(self, dynamic=False):
        session = Session()
        session.displayData.name = 'ClaudeGuard proxy isolation'
        session.flags = DYNAMIC if dynamic else 0
        session.txnWaitTimeoutInMSec = 5000
        handle = HANDLE()
        _check(self.dll.FwpmEngineOpen0(None, 10, None, ct.byref(session),
                                       ct.byref(handle)), 'FwpmEngineOpen0')
        return handle

    def close(self, handle):
        _check(self.dll.FwpmEngineClose0(handle), 'FwpmEngineClose0')

    def begin(self, handle):
        _check(self.dll.FwpmTransactionBegin0(handle, 0),
               'FwpmTransactionBegin0')

    def commit(self, handle):
        _check(self.dll.FwpmTransactionCommit0(handle),
               'FwpmTransactionCommit0')

    def abort(self, handle):
        _check(self.dll.FwpmTransactionAbort0(handle), 'FwpmTransactionAbort0')

    def app_id(self, program):
        if not os.path.isfile(program):
            raise WfpError('Executable does not exist: ' + program)
        pointer = ct.POINTER(Blob)()
        _check(self.dll.FwpmGetAppIdFromFileName0(program, ct.byref(pointer)),
               'FwpmGetAppIdFromFileName0')
        try:
            return ct.string_at(pointer.contents.data, pointer.contents.size)
        finally:
            self._free(pointer)

    def ensure_sublayer(self, handle):
        layer = Sublayer()
        layer.subLayerKey = GUID.parse(SUBLAYER_KEY)
        layer.displayData.name = 'ClaudeGuard proxy isolation v1'
        layer.flags = PERSISTENT
        layer.weight = SUBLAYER_WEIGHT
        code = self.dll.FwpmSubLayerAdd0(handle, ct.byref(layer), None)
        if code != ALREADY_EXISTS:
            _check(code, 'FwpmSubLayerAdd0')
        try:
            self.verify_sublayer(handle)
        except WfpError as error:
            status = 'already_exists' if code == ALREADY_EXISTS else 'created'
            raise WfpError(f'{error}; FwpmSubLayerAdd0={status}') from error

    def verify_sublayer(self, handle):
        pointer = ct.POINTER(Sublayer)()
        key = GUID.parse(SUBLAYER_KEY)
        _check(self.dll.FwpmSubLayerGetByKey0(handle, ct.byref(key),
                                            ct.byref(pointer)),
               'FwpmSubLayerGetByKey0')
        try:
            layer = pointer.contents
            if (layer.subLayerKey.text() != SUBLAYER_KEY
                    or layer.flags != PERSISTENT
                    or layer.weight != SUBLAYER_WEIGHT or layer.providerKey
                    or layer.providerData.size):
                provider = (layer.providerKey.contents.text()
                            if layer.providerKey else None)
                raise WfpError(
                    'Sublayer readback mismatch: '
                    f'key={layer.subLayerKey.text()} '
                    f'flags=0x{layer.flags:08x} weight={layer.weight} '
                    f'providerKey={provider} '
                    f'providerData.size={layer.providerData.size} '
                    f'providerData.present={bool(layer.providerData.data)}; '
                    f'expected key={SUBLAYER_KEY} '
                    f'flags=0x{PERSISTENT:08x} weight={SUBLAYER_WEIGHT} '
                    'providerKey=None providerData.size=0')
        finally:
            self._free(pointer)

    def add_filter(self, handle, spec, existing_allowed):
        native = Filter()
        native.filterKey = GUID.parse(spec.key)
        native.displayData.name = 'ClaudeGuard ' + spec.key
        native.flags = spec.flags
        native.layerKey = GUID.parse(spec.layer)
        native.subLayerKey = GUID.parse(SUBLAYER_KEY)
        weight = UINT64(spec.weight)
        native.weight.type = 4
        native.weight.uint64 = ct.pointer(weight)
        native.action.type = spec.action
        conditions = (Condition * len(spec.conditions))()
        references = []
        for condition, (key, data_type, value) in zip(conditions,
                                                     spec.conditions):
            condition.fieldKey = GUID.parse(key)
            condition.value.type = data_type
            if data_type == 12:
                data = (UINT8 * len(value)).from_buffer_copy(value)
                blob = Blob(len(value), data)
                references.extend((data, blob))
                condition.value.byteBlob = ct.pointer(blob)
            else:
                setattr(condition.value, {1: 'uint8', 2: 'uint16',
                                          3: 'uint32'}[data_type], value)
        native.numFilterConditions = len(conditions)
        native.filterCondition = conditions
        code = self.dll.FwpmFilterAdd0(handle, ct.byref(native), None, None)
        if code != ALREADY_EXISTS or not existing_allowed:
            _check(code, 'FwpmFilterAdd0')
        self.verify_filter(handle, spec)

    def verify_filter(self, handle, spec):
        pointer = ct.POINTER(Filter)()
        key = GUID.parse(spec.key)
        _check(self.dll.FwpmFilterGetByKey0(handle, ct.byref(key),
                                          ct.byref(pointer)),
               'FwpmFilterGetByKey0')
        try:
            native = pointer.contents
            conditions = []
            for index in range(native.numFilterConditions):
                item = native.filterCondition[index]
                value = item.value
                if item.matchType != 0:
                    raise WfpError('Unexpected filter match type')
                if value.type == 12 and value.byteBlob:
                    blob = value.byteBlob.contents
                    data = ct.string_at(blob.data, blob.size)
                elif value.type in (1, 2, 3):
                    data = getattr(value, {1: 'uint8', 2: 'uint16',
                                           3: 'uint32'}[value.type])
                else:
                    raise WfpError('Unexpected filter condition type')
                conditions.append((item.fieldKey.text(), value.type, data))
            if native.weight.type != 4 or not native.weight.uint64:
                raise WfpError('Unexpected filter weight type')
            # INDEXED is an SDK-defined lookup optimization, not policy scope.
            actual = FilterSpec(native.filterKey.text(), native.layerKey.text(),
                                native.flags & ~INDEXED, native.action.type,
                                native.weight.uint64.contents.value,
                                tuple(sorted(conditions)))
            expected = FilterSpec(spec.key, spec.layer, spec.flags, spec.action,
                                  spec.weight, tuple(sorted(spec.conditions)))
            if (actual != expected or native.subLayerKey.text() != SUBLAYER_KEY
                    or native.providerKey or native.providerData.size
                    or native.context.rawContext
                    or native.effectiveWeight.type != 4
                    or not native.effectiveWeight.uint64
                    or native.effectiveWeight.uint64.contents.value
                    != spec.weight):
                changed = [name for name in FilterSpec.__dataclass_fields__
                           if getattr(actual, name) != getattr(expected, name)]
                raise WfpError(
                    f'Filter readback mismatch: expected key={spec.key} '
                    f'actual key={native.filterKey.text()} '
                    f'layer={native.layerKey.text()} '
                    f'sublayer={native.subLayerKey.text()} '
                    f'flags=0x{native.flags:08x} '
                    f'action=0x{native.action.type:08x} '
                    f'weight={actual.weight} '
                    f'effectiveWeight.type={native.effectiveWeight.type} '
                    f'providerKey.present={bool(native.providerKey)} '
                    f'providerData.size={native.providerData.size} '
                    f'providerData.present={bool(native.providerData.data)} '
                    f'rawContext.nonzero={bool(native.context.rawContext)} '
                    f'changed={",".join(changed)}')
        finally:
            self._free(pointer)


class WfpBackend:
    """Own the dynamic session until explicit revoke or process termination.

    Calls are serialized. A failed close is reported and its handle retained
    for retry; callers must kill protected processes on any exception.
    """

    def __init__(self, api=None):
        self.api = api if api is not None else NativeApi()
        self._permit_handle = None
        self._configuration = None
        self._lock = threading.RLock()

    def revoke_proxy_access(self):
        """Close all permits owned by this backend; keep persistent blocks."""
        with self._lock:
            if self._permit_handle is not None:
                self.api.close(self._permit_handle)
                self._permit_handle = None
            self._configuration = None

    def _transaction(self, handle, operation):
        self.api.begin(handle)
        try:
            operation()
            self.api.commit(handle)
        except BaseException:
            self.api.abort(handle)
            raise

    def ensure(self, programs, proxy_port):
        """Install and read back baseline, then grant a dynamic proxy lease.

        Returns the verified filter keys. Every call performs fresh readback;
        no cached success is used. Exceptions revoke this owner's permits.
        """
        with self._lock:
            try:
                if (type(proxy_port) is not int
                        or not 1 <= proxy_port <= 65535 or not programs):
                    raise WfpError('Invalid proxy isolation configuration')
                identities = [(program, self.api.app_id(program))
                              for program in programs]
                baseline = tuple(_spec(program, app_id, layer)
                                 for program, app_id in identities
                                 for layer in BASELINE_LAYERS)
                permits = tuple(_spec(program, app_id, CONNECT_V4, proxy_port)
                                for program, app_id in identities)
                configuration = (baseline, permits)
                if self._configuration != configuration:
                    self.revoke_proxy_access()
                handle = self.api.open()
                try:
                    def install_baseline():
                        self.api.ensure_sublayer(handle)
                        for spec in baseline:
                            self.api.add_filter(handle, spec, True)
                    self._transaction(handle, install_baseline)
                    self.api.verify_sublayer(handle)
                    for spec in baseline:
                        self.api.verify_filter(handle, spec)
                finally:
                    self.api.close(handle)
                if self._permit_handle is None:
                    self._permit_handle = self.api.open(dynamic=True)

                    def install_permits():
                        for spec in permits:
                            self.api.add_filter(
                                self._permit_handle, spec, False)
                    self._transaction(self._permit_handle, install_permits)
                self.api.verify_sublayer(self._permit_handle)
                for spec in baseline + permits:
                    self.api.verify_filter(self._permit_handle, spec)
                self._configuration = configuration
                return tuple(spec.key for spec in baseline + permits)
            except BaseException:
                self.revoke_proxy_access()
                raise
