# ClrOxide

`ClrOxide` is a rust library that allows you to host the CLR and dynamically execute dotnet binaries.

I wanted to call it `Kepler` for no particular reason, but there's already a package named `kepler` in cargo. :(

I have been working on hosting CLR with rust on and off for 2 years now, and finally something clicked two weeks ago!

This library wouldn't be possible without the following projects:

- [NimPlant](https://github.com/chvancooten/NimPlant) and its [execute assembly](https://github.com/chvancooten/NimPlant/tree/main/client/commands/risky/executeAssembly.nim) implementation
  - The elegance with which `winim/clr` allows overwriting the output buffer for `Console.Write` and gets the output! Striving for the same elegance is the only reason this library took two years. 
How can I convince Cas to dabble with rust if he can't replicate this!? My work for a rust implant for `NimPlant` is also how I got into this rabbit hole in the first place.
- [go-clr](https://github.com/ropnop/go-clr) by [ropnop](https://github.com/ropnop)
  - A very special thank you to ropnop here! This whole library is the result of 3 days of work thanks to something in `go-clr` that just made everything click for me!
- [dinvoke_rs](https://github.com/Kudaes/DInvoke_rs) by [Kudaes](https://github.com/Kudaes)
  - Similar to `go-clr`, Kurosh's `dinvoke_rs` project also made some rust/win32 intricacies clearer and allowed the project to move forward.
- Various CLR-related rust libraries
  - https://github.com/ZerothLaw/mscorlib-rs-sys
  - https://github.com/ZerothLaw/mscoree-rs
  - and likely a few more...


## Architecture Constraints

### ClrOxide

`ClrOxide` only works if compiled for `x86_64-pc-windows-gnu` or `x86_64-pc-windows-msvc`.  

Compiling for `i686-pc-windows-gnu` fails due to known issues with rust panic unwinding. It might work with `i686-pc-windows-msvc`, but I haven't tried it myself.

### Assembly

Although I haven't run into this issue myself, there might be cases where you need to specifically compile your assembly as `x64` instead of `Any CPU`.

## Design Constraints

`windows` crate had no type definitions for `mscoree.dll` until a few weeks ago. It looks like the definitions for `mscoree.dll` have made their way into the `windows` crate in version `0.48.0`. However, these definitions don't appear to be working correctly. Just as an example; a vtable entry that should point to a function within the CLR thread (let's say at address `0x7ffef16821a0`), somehow returns an address widely out of range (`0x750003cac9053b48`).

The `windows` crate does a lot of fancy stuff with vtables for safety, but ironically, these are likely causing the access violation above. Or something else is happening... I intended to use the official definitions for V2 to offload the maintenance burden, but this is a dealbreaker.

## Usage

You can find more examples in the [`examples/`](examples) folder.

### Run an assembly and capture its output

<img width="563" alt="assembly_arch" src="./docs/images/execute_assembly_with_different_architectures.png">

`ClrOxide` will load the CLR in the current process, resolve `mscorlib` and redirect the output for `System.Console`, finally loading and running your executable and returning its output as a string.

Streaming the output is not currently supported, although I'm sure the CLR wrangling magic used for redirecting the output could be a good guide for anyone willing to implement it.

```rust
use clroxide::clr::Clr;
use std::{env, fs, process::exit};

fn main() -> Result<(), String> {
    let (path, args) = prepare_args();

    let contents = fs::read(path).expect("Unable to read file");
    let mut clr = Clr::new(contents, args)?;

    let results = clr.run()?;

    println!("[*] Results:\n\n{}", results);

    Ok(())
}

fn prepare_args() -> (String, Vec<String>) {
    let mut args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Please provide a path to a dotnet executable");

        exit(1)
    }

    let mut command_args: Vec<String> = vec![];

    if args.len() > 2 {
        command_args = args.split_off(2)
    }

    let path = args[1].clone();

    println!("[+] Running `{}` with given args: {:?}", path, command_args);

    return (path, command_args);
}
```

### Use a custom app domain

<img width="563" alt="assembly_arch" src="./docs/images/using_custom_app_domain.png">

You can update the context to use a custom app domain. This can be useful if you want to avoid `DefaultDomain`. Check out [`examples/custom_app_domain.rs`](examples/custom_app_domain.rs) for more details.

```rust
...

  let app_domain = clr.using_runtime_host(|host| {
      let app_domain = unsafe { (*host).create_domain("CustomDomain")? };

      Ok(app_domain)
  })?;

  clr.use_app_domain(app_domain)?;

...
```



### Use a custom loader for `mscoree.dll`

We need to load the `CreateInterface` function from `mscoree.dll` to kickstart the CLR. You can provide a custom loader by disabling default features.

First, add `default-features = false` to your dependency declaration.

```toml
clroxide = { version = "1.0.6", default-features = false }
```

And then provide a function with the signature `fn() -> Result<isize, String>` that returns a pointer to the `CreateInterface` function when creating the Clr instance.

```rust
litcrypt::use_litcrypt!();

fn load_function() -> Result<isize, String> {
  let library = custom_load_library_a(lc!("mscoree.dll\0"));

  if library == 0 {
    return Err("Failed".into());
  }
  
  let function = custom_get_process_address(library, lc!("CreateInterface\0"));
  
  if function == 0 {
    return Err("Failed".into());
  }
  
  Ok(function)
}

fn main() -> Result<(), String> {
 
  // ...

  let mut context = Clr::new(contents, args, load_function)?;

  // ...
  
}
```

### Patch `System.Environment.Exit` to not exit

<img width="563" alt="assembly_arch" src="./docs/images/patching_system_environment_exit.png">

You can use the building blocks provided by `ClrOxide` to patch `System.Environment.Exit` as described in [Massaging your CLR: Preventing Environment.Exit in In-Process .NET Assemblies](https://www.mdsec.co.uk/2020/08/massaging-your-clr-preventing-environment-exit-in-in-process-net-assemblies) by MDSec.  

You can check the reference implementation at [`examples/patch_exit.rs`](examples/patch_exit.rs). Since this requires using `VirtualProtect` or `NtProtectVirtualMemory`, I don't intend to add this as a feature to `ClrOxide`. 

---

## AMSI Bypass via CLR Hosting

This fork implements an AMSI bypass technique based on CLR customization, as described in [Being a Good CLR Host](https://github.com/xforcered/Being-A-Good-CLR-Host).

### How it works

Traditionally, `Load_3` (which takes a byte array) is used to load .NET assemblies reflectively - and AMSI scans those bytes. By using `Load_2` (which takes an assembly identity string) combined with a custom `IHostAssemblyStore`, we can load assemblies from memory without AMSI ever seeing the bytes.

```
┌─────────────────────┐
│  ICLRRuntimeHost    │  ← SetHostControl() BEFORE Start()
│  SetHostControl()   │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│    IHostControl     │  ← Our implementation
│  GetHostManager()   │
└─────────┬───────────┘
          │ returns IHostAssemblyManager
          ▼
┌─────────────────────────┐
│  IHostAssemblyManager   │  ← Our implementation
│  GetAssemblyStore()     │
└─────────┬───────────────┘
          │ returns IHostAssemblyStore
          ▼
┌─────────────────────────┐
│  IHostAssemblyStore     │  ← The magic happens here!
│  ProvideAssembly()      │  → Returns IStream with in-memory bytes
└─────────────────────────┘
```

When `Load_2("MyAssembly, Version=1.0.0.0, ...")` is called:
1. The CLR calls our `ProvideAssembly` with the assembly identity
2. We return an `IStream` containing the assembly bytes from memory
3. The CLR loads the assembly thinking it came from disk
4. **AMSI never scans the bytes** because `Load_2` is not instrumented!

### New files

| File | Description |
|------|-------------|
| `primitives/iclrruntimehost.rs` | `ICLRRuntimeHost` with `SetHostControl` |
| `primitives/ihostassemblystore.rs` | `IHostControl`, `IHostAssemblyManager`, `IHostAssemblyStore`, `MemoryStream`, `AmsiBypassLoader` |
| `primitives/iclrassemblyidentitymanager.rs` | Extract assembly identity from bytes |

### New methods in `Clr`

| Method | Description |
|--------|-------------|
| `get_context_with_amsi_bypass()` | Initialize CLR with AMSI bypass enabled |
| `run_with_amsi_bypass()` | Run with explicit identity string |
| `run_with_amsi_bypass_no_redirect()` | Same without output redirection |
| `run_with_amsi_bypass_auto()` | **Recommended** - Auto-extracts identity from bytes |
| `run_with_amsi_bypass_auto_no_redirect()` | Same without output redirection |
| `get_assembly_identity()` | Get identity string from assembly bytes |

### Usage - Recommended (Auto Identity)

```rust
use clroxide::clr::Clr;
use clroxide::primitives::AmsiBypassLoader;

fn main() -> Result<(), String> {
    let assembly_bytes = std::fs::read("Seatbelt.exe").unwrap();
    let args = vec!["--all".to_string()];

    let mut bypass_loader = AmsiBypassLoader::new();
    let mut clr = Clr::new(assembly_bytes, args)?;

    // Automatically extracts the correct assembly identity
    let output = clr.run_with_amsi_bypass_auto(&mut bypass_loader)?;

    println!("{}", output);
    Ok(())
}
```

### Usage - Manual Identity

If you already know the assembly identity (e.g., extracted on client/teamserver side):

```rust
use clroxide::clr::Clr;
use clroxide::primitives::AmsiBypassLoader;

fn main() -> Result<(), String> {
    let assembly_bytes = std::fs::read("Seatbelt.exe").unwrap();
    let args = vec!["--all".to_string()];

    let mut bypass_loader = AmsiBypassLoader::new();
    let mut clr = Clr::new(assembly_bytes, args)?;

    // Identity MUST match the actual assembly!
    let identity = "Seatbelt, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null";
    let output = clr.run_with_amsi_bypass(&mut bypass_loader, identity)?;

    println!("{}", output);
    Ok(())
}
```

### Important: Identity Must Match!

> **Warning**: The assembly identity passed to `Load_2` **MUST** match the actual identity of the assembly you return from `ProvideAssembly`. The CLR verifies this and will throw an error if they don't match.

Use `run_with_amsi_bypass_auto()` to automatically extract the correct identity, or use `get_assembly_identity()` to extract it manually:

```rust
let identity = clr.get_assembly_identity()?;
// Returns: "Seatbelt, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"
```

### References

- [Being-A-Good-CLR-Host](https://github.com/xforcered/Being-A-Good-CLR-Host) - Original C implementation
- [Customizing the Microsoft .NET Framework Common Language Runtime](https://www.amazon.com/Customizing-Microsoft-Framework-Common-Language/dp/0735619883) by Steven Pratschner
