# ClrOxide — AMSI Bypass Fork

This is a fork of [yamakadi/clroxide](https://github.com/yamakadi/clroxide), a Rust library for hosting the CLR and running .NET assemblies in-process. On top of everything the original does, this fork adds an AMSI bypass technique based on CLR host customization — specifically, intercepting assembly loading through `IHostAssemblyStore` so that AMSI never gets a chance to scan the bytes.

If you just want to run assemblies without worrying about the bypass, the original API still works exactly as before. The new methods are opt-in.

---

## Why the usual approach gets caught

The standard way to run a .NET assembly reflectively is to call `Load_3`, which accepts a raw byte array. That's exactly what defenders know to watch. AMSI (and EDR hooks built on top of it) instrument `Assembly.Load(byte[])` at the CLR level, so by the time your bytes land in that function call, they're already being scanned.

The technique implemented here avoids that path entirely by using `Load_2` instead — the overload that takes an assembly *identity string* rather than raw bytes. `Load_2` is not instrumented by AMSI. The trick is getting the CLR to actually load your in-memory bytes when it processes that identity string, and that's where CLR host customization comes in.

---

## How it works

The CLR exposes a set of hosting interfaces that let the process hosting it customize its behavior. One of those interfaces is `IHostAssemblyStore`, which the CLR calls whenever it needs to resolve an assembly. If you implement it and register it before the runtime starts, you get to return the assembly bytes yourself — via an `IStream` — and the CLR loads them as if they came from disk.

The call chain looks like this:

```
ICLRRuntimeHost::SetHostControl()   ← must happen BEFORE Start()
        │
        ▼
  IHostControl::GetHostManager()    ← CLR calls this looking for managers
        │
        ▼
  IHostAssemblyManager::GetAssemblyStore()
        │
        ▼
  IHostAssemblyStore::ProvideAssembly()   ← we return an IStream here
        │
        ▼
  CLR loads the assembly from the stream
  AMSI never sees the bytes.
```

When you call `AppDomain.Load_2("MyAssembly, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null")`, the CLR asks our `ProvideAssembly` implementation to hand over the bytes. We return an in-memory `IStream` wrapping the assembly we registered ahead of time. The CLR loads it, runs it, and AMSI was never involved.

One non-obvious gotcha: **the identity string passed to `Load_2` must exactly match the actual assembly identity**. The CLR verifies this. If there's a mismatch, you'll get a load failure. The `run_with_amsi_bypass_auto()` method handles this automatically by parsing the PE metadata directly from the bytes before making the call.

Another gotcha: `SetHostControl()` must be called *before* `ICLRRuntimeHost::Start()`. Once the runtime is running, the call returns `E_ACCESSDENIED`. This means the bypass only applies on the first execution in a given process. Subsequent calls (e.g. a second execute-assembly job in a C2 implant) will fall back to normal loading because the runtime is already started.

---

## Architecture

Three new primitives power this:

| File | What it does |
|------|--------------|
| `src/primitives/iclrruntimehost.rs` | `ICLRRuntimeHost` interface with `SetHostControl` — this is separate from the `ICorRuntimeHost` the original library uses, and is the only one that exposes host control registration |
| `src/primitives/ihostassemblystore.rs` | Full COM implementation of `IHostControl`, `IHostAssemblyManager`, `IHostAssemblyStore`, and `MemoryStream` (as a proper `IStream`). Also contains `AmsiBypassLoader`, the high-level entry point |
| `src/primitives/pe_identity.rs` | Pure Rust PE metadata parser that reads the CLI header and metadata tables to extract the assembly identity string without needing COM or the CLR to be running |

The identity manager (`iclrassemblyidentitymanager.rs`) is also present for reference, but it turned out to be broken in practice — `ICLRRuntimeInfo::GetInterface` does not support `ICLRAssemblyIdentityManager`, and the CLSID is wrong. The PE parser in `pe_identity.rs` is what actually gets used.

---

## Usage

Add the dependency:

```toml
[dependencies]
clroxide = { git = "https://github.com/your-username/clroxide" }
```

### Recommended: auto-extract identity

The simplest path. The library reads the identity directly from the PE bytes so you don't have to know it ahead of time.

```rust
use clroxide::clr::Clr;
use clroxide::primitives::AmsiBypassLoader;

fn main() -> Result<(), String> {
    let bytes = std::fs::read("Seatbelt.exe").unwrap();
    let args = vec!["--all".to_string()];

    let mut bypass_loader = AmsiBypassLoader::new();
    let mut clr = Clr::new(bytes, args)?;

    let output = clr.run_with_amsi_bypass_auto(&mut bypass_loader)?;
    println!("{}", output);

    Ok(())
}
```

### Manual identity

Use this if you already know the assembly identity — for example, if the C2 server extracted it server-side and sent it along with the payload.

```rust
use clroxide::clr::Clr;
use clroxide::primitives::AmsiBypassLoader;

fn main() -> Result<(), String> {
    let bytes = std::fs::read("Rubeus.exe").unwrap();
    let args = vec!["triage".to_string()];

    let mut bypass_loader = AmsiBypassLoader::new();
    let mut clr = Clr::new(bytes, args)?;

    let identity = "Rubeus, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null";
    let output = clr.run_with_amsi_bypass(&mut bypass_loader, identity)?;
    println!("{}", output);

    Ok(())
}
```

### Without output redirection

If you don't need to capture the output — just want the assembly to run and print to the real console — use the `_no_redirect` variants:

```rust
clr.run_with_amsi_bypass_auto_no_redirect(&mut bypass_loader)?;
```

### Extract the identity manually

If you want to inspect or cache the identity string:

```rust
let clr = Clr::new(bytes, vec![])?;
let identity = clr.get_assembly_identity()?;
// "Seatbelt, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"
println!("{}", identity);
```

---

## New API surface

| Method | Description |
|--------|-------------|
| `Clr::get_context_with_amsi_bypass(loader)` | Initialize the CLR context with the host control registered. Must be called before the runtime starts |
| `Clr::run_with_amsi_bypass(loader, identity)` | Run with a manually provided identity string |
| `Clr::run_with_amsi_bypass_no_redirect(loader, identity)` | Same, without capturing output |
| `Clr::run_with_amsi_bypass_auto(loader)` | Auto-extract identity from bytes and run |
| `Clr::run_with_amsi_bypass_auto_no_redirect(loader)` | Same, without capturing output |
| `Clr::get_assembly_identity()` | Extract identity string from the loaded bytes |

The original `run()`, `run_no_redirect()`, and all other existing methods are unchanged.

---

## Original library

Everything in the base library still works. The original `ClrOxide` is a solid piece of work — huge thanks to [yamakadi](https://github.com/yamakadi) for building it. The output redirection trick alone (hooking `Console.SetOut` via reflection to capture assembly output) is elegant and saved a lot of time.

Original dependencies that made this possible:

- [NimPlant](https://github.com/chvancooten/NimPlant) — the `winim/clr` output capture technique that yamakadi was replicating
- [go-clr](https://github.com/ropnop/go-clr) — ropnop's Go implementation that made CLR hosting click
- [DInvoke_rs](https://github.com/Kudaes/DInvoke_rs) — helped clarify Rust/Win32 interop patterns

---

## References

The AMSI bypass technique is based on:

- **[Being a Good CLR Host](https://github.com/xforcered/Being-A-Good-CLR-Host)** by xforcered — the original C proof-of-concept that demonstrated using `IHostAssemblyStore` to serve in-memory assemblies via `Load_2`
- **[Customizing the Microsoft .NET Framework Common Language Runtime](https://www.amazon.com/Customizing-Microsoft-Framework-Common-Language/dp/0735619883)** by Steven Pratschner — the definitive book on CLR hosting internals
- **[Massaging your CLR: Preventing Environment.Exit in In-Process .NET Assemblies](https://www.mdsec.co.uk/2020/08/massaging-your-clr-preventing-environment-exit-in-in-process-net-assemblies)** by MDSec — related CLR customization technique (patching `System.Environment.Exit`) also demonstrated via the original `ClrOxide` examples

---

## Architecture constraints

`ClrOxide` requires `x86_64-pc-windows-gnu` or `x86_64-pc-windows-msvc`. Compiling for `i686` will fail due to known issues with Rust panic unwinding on that target.

Some assemblies may need to be compiled targeting `x64` explicitly rather than `Any CPU`, depending on how they were built.
