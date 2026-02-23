use crate::primitives::{Class, IUnknown, IUnknownVtbl, Interface, GUID, HANDLE, HRESULT};
use std::{ffi::c_void, ops::Deref};

/// ICLRRuntimeHost - runtime host with SetHostControl support
/// This is the newer interface that allows setting a custom host control
/// to intercept assembly loading via IHostAssemblyStore
#[repr(C)]
pub struct ICLRRuntimeHost {
    pub vtable: *const ICLRRuntimeHostVtbl,
}

#[repr(C)]
pub struct ICLRRuntimeHostVtbl {
    pub parent: IUnknownVtbl,
    pub Start: unsafe extern "system" fn(this: *mut ICLRRuntimeHost) -> HRESULT,
    pub Stop: unsafe extern "system" fn(this: *mut ICLRRuntimeHost) -> HRESULT,
    pub SetHostControl: unsafe extern "system" fn(
        this: *mut ICLRRuntimeHost,
        pHostControl: *mut c_void, // IHostControl*
    ) -> HRESULT,
    pub GetCLRControl: unsafe extern "system" fn(
        this: *mut ICLRRuntimeHost,
        ppCLRControl: *mut *mut c_void, // ICLRControl**
    ) -> HRESULT,
    pub UnloadAppDomain: unsafe extern "system" fn(
        this: *mut ICLRRuntimeHost,
        dwAppDomainId: u32,
        fWaitUntilDone: i32,
    ) -> HRESULT,
    pub ExecuteInAppDomain: unsafe extern "system" fn(
        this: *mut ICLRRuntimeHost,
        dwAppDomainId: u32,
        pCallback: *mut c_void,
        cookie: *mut c_void,
    ) -> HRESULT,
    pub GetCurrentAppDomainId: unsafe extern "system" fn(
        this: *mut ICLRRuntimeHost,
        pdwAppDomainId: *mut u32,
    ) -> HRESULT,
    pub ExecuteApplication: unsafe extern "system" fn(
        this: *mut ICLRRuntimeHost,
        pwzAppFullName: *const u16,
        dwManifestPaths: u32,
        ppwzManifestPaths: *const *const u16,
        dwActivationData: u32,
        ppwzActivationData: *const *const u16,
        pReturnValue: *mut i32,
    ) -> HRESULT,
    pub ExecuteInDefaultAppDomain: unsafe extern "system" fn(
        this: *mut ICLRRuntimeHost,
        pwzAssemblyPath: *const u16,
        pwzTypeName: *const u16,
        pwzMethodName: *const u16,
        pwzArgument: *const u16,
        pReturnValue: *mut u32,
    ) -> HRESULT,
}

impl ICLRRuntimeHost {
    pub fn start(&self) -> Result<(), String> {
        let hr = unsafe { self.Start() };
        if hr.is_err() {
            return Err(format!("Could not start CLR runtime host: {:?}", hr));
        }
        Ok(())
    }

    pub fn stop(&self) -> Result<(), String> {
        let hr = unsafe { self.Stop() };
        if hr.is_err() {
            return Err(format!("Could not stop CLR runtime host: {:?}", hr));
        }
        Ok(())
    }

    /// Set a custom host control to intercept assembly loading
    /// This is the key method for AMSI bypass - we provide our own IHostControl
    /// which returns an IHostAssemblyManager with a custom IHostAssemblyStore
    pub fn set_host_control(&self, host_control: *mut c_void) -> Result<(), String> {
        let hr = unsafe { self.SetHostControl(host_control) };
        if hr.is_err() {
            return Err(format!("Could not set host control: {:?}", hr));
        }
        Ok(())
    }

    pub fn get_current_appdomain_id(&self) -> Result<u32, String> {
        let mut id: u32 = 0;
        let hr = unsafe { self.GetCurrentAppDomainId(&mut id) };
        if hr.is_err() {
            return Err(format!("Could not get current AppDomain ID: {:?}", hr));
        }
        Ok(id)
    }

    #[inline]
    pub unsafe fn Start(&self) -> HRESULT {
        ((*self.vtable).Start)(self as *const _ as *mut _)
    }

    #[inline]
    pub unsafe fn Stop(&self) -> HRESULT {
        ((*self.vtable).Stop)(self as *const _ as *mut _)
    }

    #[inline]
    pub unsafe fn SetHostControl(&self, pHostControl: *mut c_void) -> HRESULT {
        ((*self.vtable).SetHostControl)(self as *const _ as *mut _, pHostControl)
    }

    #[inline]
    pub unsafe fn GetCLRControl(&self, ppCLRControl: *mut *mut c_void) -> HRESULT {
        ((*self.vtable).GetCLRControl)(self as *const _ as *mut _, ppCLRControl)
    }

    #[inline]
    pub unsafe fn UnloadAppDomain(&self, dwAppDomainId: u32, fWaitUntilDone: i32) -> HRESULT {
        ((*self.vtable).UnloadAppDomain)(self as *const _ as *mut _, dwAppDomainId, fWaitUntilDone)
    }

    #[inline]
    pub unsafe fn GetCurrentAppDomainId(&self, pdwAppDomainId: *mut u32) -> HRESULT {
        ((*self.vtable).GetCurrentAppDomainId)(self as *const _ as *mut _, pdwAppDomainId)
    }

    #[inline]
    pub unsafe fn ExecuteInDefaultAppDomain(
        &self,
        pwzAssemblyPath: *const u16,
        pwzTypeName: *const u16,
        pwzMethodName: *const u16,
        pwzArgument: *const u16,
        pReturnValue: *mut u32,
    ) -> HRESULT {
        ((*self.vtable).ExecuteInDefaultAppDomain)(
            self as *const _ as *mut _,
            pwzAssemblyPath,
            pwzTypeName,
            pwzMethodName,
            pwzArgument,
            pReturnValue,
        )
    }
}

impl Interface for ICLRRuntimeHost {
    // IID_ICLRRuntimeHost: 90F1A06C-7712-4762-86B5-7A5EBA6BDB02
    const IID: GUID = GUID::from_values(
        0x90F1A06C,
        0x7712,
        0x4762,
        [0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02],
    );

    fn vtable(&self) -> *const c_void {
        self.vtable as *const _ as *const c_void
    }
}

impl Class for ICLRRuntimeHost {
    // CLSID_CLRRuntimeHost: 90F1A06E-7712-4762-86B5-7A5EBA6BDB02
    const CLSID: GUID = GUID::from_values(
        0x90F1A06E,
        0x7712,
        0x4762,
        [0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02],
    );
}

impl Deref for ICLRRuntimeHost {
    type Target = IUnknown;

    #[inline]
    fn deref(&self) -> &IUnknown {
        unsafe { &*(self as *const ICLRRuntimeHost as *const IUnknown) }
    }
}

