//! ICLRAssemblyIdentityManager - Get assembly identity from bytes
//!
//! This is needed for AMSI bypass because the identity passed to Load_2
//! MUST match the actual identity of the assembly being loaded.
//!
//! Reference: https://github.com/xforcered/Being-A-Good-CLR-Host

use crate::primitives::{Interface, IUnknownVtbl, MemoryStream, MemoryStreamVtbl, GUID, HRESULT};
use std::ffi::c_void;
use std::ptr;

/// Flags for GetBindingIdentityFromStream
#[repr(u32)]
pub enum ECLRAssemblyIdentityFlags {
    /// Default behavior
    Default = 0,
}

#[repr(C)]
pub struct ICLRAssemblyIdentityManager {
    pub vtable: *const ICLRAssemblyIdentityManagerVtbl,
}

#[repr(C)]
pub struct ICLRAssemblyIdentityManagerVtbl {
    pub parent: IUnknownVtbl,
    pub GetCLRAssemblyReferenceList: unsafe extern "system" fn(
        this: *mut ICLRAssemblyIdentityManager,
        ppwzAssemblyReferences: *const *const u16,
        dwNumOfReferences: u32,
        ppReferenceList: *mut *mut c_void,
    ) -> HRESULT,
    pub GetBindingIdentityFromFile: unsafe extern "system" fn(
        this: *mut ICLRAssemblyIdentityManager,
        pwzFilePath: *const u16,
        dwFlags: u32,
        pwzBuffer: *mut u16,
        pcchBufferSize: *mut u32,
    ) -> HRESULT,
    pub GetBindingIdentityFromStream: unsafe extern "system" fn(
        this: *mut ICLRAssemblyIdentityManager,
        pStream: *mut c_void, // IStream*
        dwFlags: u32,
        pwzBuffer: *mut u16,
        pcchBufferSize: *mut u32,
    ) -> HRESULT,
    pub GetReferencedAssembliesFromFile: unsafe extern "system" fn(
        this: *mut ICLRAssemblyIdentityManager,
        pwzFilePath: *const u16,
        dwFlags: u32,
        pExcludeAssembliesList: *mut c_void,
        ppReferenceEnum: *mut *mut c_void,
    ) -> HRESULT,
    pub GetReferencedAssembliesFromStream: unsafe extern "system" fn(
        this: *mut ICLRAssemblyIdentityManager,
        pStream: *mut c_void,
        dwFlags: u32,
        pExcludeAssembliesList: *mut c_void,
        ppReferenceEnum: *mut *mut c_void,
    ) -> HRESULT,
    pub IsStronglyNamed: unsafe extern "system" fn(
        this: *mut ICLRAssemblyIdentityManager,
        pwzAssemblyIdentity: *const u16,
        pbIsStronglyNamed: *mut i32,
    ) -> HRESULT,
}

impl ICLRAssemblyIdentityManager {
    /// Get the binding identity string from assembly bytes
    /// This is required for AMSI bypass - the identity passed to Load_2
    /// must match the actual assembly identity!
    pub fn get_identity_from_bytes(&self, assembly_bytes: &[u8]) -> Result<String, String> {
        // Create an IStream from the bytes
        let stream = MemoryStream::new(assembly_bytes.to_vec());
        let stream_ptr = stream.into_raw();

        // Helper to release the stream
        let release_stream = |ptr: *mut c_void| unsafe {
            let stream = &mut *(ptr as *mut MemoryStream);
            let vtable = &*stream.vtable;
            (vtable.Release)(ptr);
        };

        // Helper to seek stream
        let seek_stream = |ptr: *mut c_void, pos: i64| unsafe {
            let stream = &*(ptr as *mut MemoryStream);
            let vtable = &*stream.vtable;
            (vtable.Seek)(ptr, pos, 0, ptr::null_mut()); // STREAM_SEEK_SET = 0
        };

        // First call to get required buffer size
        let mut buffer_size: u32 = 0;
        let hr = unsafe {
            self.GetBindingIdentityFromStream(
                stream_ptr,
                ECLRAssemblyIdentityFlags::Default as u32,
                ptr::null_mut(),
                &mut buffer_size,
            )
        };

        // HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) = 0x8007007A
        // This is expected - we need to know the buffer size
        if hr.0 != 0x8007007Au32 as i32 && hr.is_err() {
            release_stream(stream_ptr);
            return Err(format!(
                "GetBindingIdentityFromStream failed (size query): {:?}",
                hr
            ));
        }

        if buffer_size == 0 {
            release_stream(stream_ptr);
            return Err("Buffer size is 0".into());
        }

        // Reset stream position to beginning
        seek_stream(stream_ptr, 0);

        // Allocate buffer and get the identity
        let mut buffer: Vec<u16> = vec![0u16; buffer_size as usize];
        let hr = unsafe {
            self.GetBindingIdentityFromStream(
                stream_ptr,
                ECLRAssemblyIdentityFlags::Default as u32,
                buffer.as_mut_ptr(),
                &mut buffer_size,
            )
        };

        // Release the stream
        release_stream(stream_ptr);

        if hr.is_err() {
            return Err(format!("GetBindingIdentityFromStream failed: {:?}", hr));
        }

        // Convert to String (remove null terminator if present)
        let len = buffer_size as usize;
        let identity = if len > 0 && buffer[len - 1] == 0 {
            String::from_utf16_lossy(&buffer[..len - 1])
        } else {
            String::from_utf16_lossy(&buffer[..len])
        };
        Ok(identity)
    }

    #[inline]
    pub unsafe fn GetBindingIdentityFromStream(
        &self,
        pStream: *mut c_void,
        dwFlags: u32,
        pwzBuffer: *mut u16,
        pcchBufferSize: *mut u32,
    ) -> HRESULT {
        ((*self.vtable).GetBindingIdentityFromStream)(
            self as *const _ as *mut _,
            pStream,
            dwFlags,
            pwzBuffer,
            pcchBufferSize,
        )
    }

    #[inline]
    pub unsafe fn GetBindingIdentityFromFile(
        &self,
        pwzFilePath: *const u16,
        dwFlags: u32,
        pwzBuffer: *mut u16,
        pcchBufferSize: *mut u32,
    ) -> HRESULT {
        ((*self.vtable).GetBindingIdentityFromFile)(
            self as *const _ as *mut _,
            pwzFilePath,
            dwFlags,
            pwzBuffer,
            pcchBufferSize,
        )
    }
}

impl Interface for ICLRAssemblyIdentityManager {
    // IID_ICLRAssemblyIdentityManager: 15F0A9DA-3FF6-4393-9DA9-FDFD284E6972
    const IID: GUID = GUID::from_values(
        0x15F0A9DA,
        0x3FF6,
        0x4393,
        [0x9D, 0xA9, 0xFD, 0xFD, 0x28, 0x4E, 0x69, 0x72],
    );

    fn vtable(&self) -> *const c_void {
        self.vtable as *const _ as *const c_void
    }
}

// CLSID for CLRAssemblyIdentityManager
pub const CLSID_CLRASSEMBLYIDENTITYMANAGER: GUID = GUID::from_values(
    0x580436E4,
    0x6F37,
    0x4E36,
    [0x9D, 0x12, 0x7C, 0x53, 0x78, 0x24, 0xCC, 0x86],
);

