use std::{fs, io::{self, Write}, path::PathBuf};
use clap::Parser;

/// Build a blob: [size_stub][size_payload][stub bytes][payload bytes]
#[derive(Parser)]
#[command(author, version, about)]
struct Opt {
    /// Path to loader stub (EXE or raw section file)
    #[arg(short = 's', long = "stub", value_name = "FILE", default_value= "../target/x86_64-pc-windows-gnu/debug/loader_stub.exe")]
    stub: PathBuf,

    /// Path to DLL payload
    #[arg(short = 'p', long = "payload", value_name = "FILE", default_value = "../loader_stub/src/payload_messagebox.dll")]
    payload: PathBuf,

    /// Output blob path
    #[arg(short = 'o', long = "output", value_name = "FILE", default_value = "blob.bin")]
    output: PathBuf,
}

fn main() -> io::Result<()> {
    let opt = Opt::parse();

    // Read inputs
    let stub    = fs::read(&opt.stub)
        .unwrap_or_else(|e| panic!("cannot read stub {:?}: {e}", opt.stub));
    let payload = fs::read(&opt.payload)
        .unwrap_or_else(|e| panic!("cannot read payload {:?}: {e}", opt.payload));

    // Build blob
    let mut out = fs::File::create(&opt.output)?;
    out.write_all(&(stub.len()    as u32).to_le_bytes())?;
    out.write_all(&(payload.len() as u32).to_le_bytes())?;
    out.write_all(&stub)?;
    out.write_all(&payload)?;

    println!("blob written to {:?}", opt.output);
    Ok(())
}
