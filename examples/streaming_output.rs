//! Streaming-output example.
//!
//! Runs a .NET assembly while incrementally consuming its `Console.Out` /
//! `Console.Error` via [`Clr::redirect_output_streaming`]. The assembly is
//! loaded and executed on a dedicated thread; the main thread polls the
//! returned [`StreamingOutputContext`] every 100 ms and prints any new bytes.
//!
//! Usage: `streaming_output <path/to/dotnet.exe> [args...]`

use clroxide::clr::Clr;
use clroxide::primitives::_AppDomain;
use std::{env, fs, process::exit, thread, time::Duration};

fn main() -> Result<(), String> {
    let (path, args) = prepare_args();
    let contents = fs::read(path).expect("Unable to read file");

    let mut clr = Clr::new(contents.clone(), args.clone())?;

    // Initialize the runtime BEFORE redirecting output. `&_AppDomain` is
    // `Send` thanks to the explicit impls in `iappdomain.rs`, so we can move
    // it into the runner thread; the raw `*mut` would not be `Send`.
    let context = clr.get_context()?;
    let app_domain: &'static _AppDomain = unsafe { &*context.app_domain };

    // Hook stdout/stderr; the returned context is Send + Sync.
    let stream = clr.redirect_output_streaming()?;

    // Run the assembly on a dedicated thread.
    let runner = thread::spawn(move || -> Result<(), String> {
        // SAFETY: the AppDomain is owned by the `Clr` on the main thread,
        // which outlives this thread thanks to the `runner.join()` below.
        let assembly = app_domain.load_assembly(&contents)?;
        unsafe { (*assembly).run_entrypoint(&args)? };
        Ok(())
    });

    println!("[*] Streaming output:\n");

    while !runner.is_finished() {
        let chunk = stream.drain()?;
        if !chunk.is_empty() {
            print!("{}", String::from_utf8_lossy(&chunk));
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Final drain — anything written between the last poll and runner exit.
    let chunk = stream.drain()?;
    if !chunk.is_empty() {
        print!("{}", String::from_utf8_lossy(&chunk));
    }

    runner
        .join()
        .map_err(|_| "Runner thread panicked".to_string())??;

    stream.restore()?;
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

    (path, command_args)
}
