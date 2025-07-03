use std::{fs, io::{self, Write}, path::PathBuf};
use clap::Parser;
use goblin::pe::PE;

/// Build a blob: [size_stub][size_payload][entrypointstub_offset][stub bytes][payload bytes]
#[derive(Parser)]
#[command(author, version, about)]
struct Opt {
    /// Path to loader stub (EXE or raw section file)
    #[arg(short = 's', long = "stub", value_name = "FILE", default_value= "../target/x86_64-pc-windows-gnu/debug/loader_stub.dll")]
    stub: PathBuf,

    /// Path to DLL payload
    #[arg(short = 'p', long = "payload", value_name = "FILE", default_value = "../loader_stub/src/payload_messagebox.dll")]
    payload: PathBuf,

    /// Output blob path
    #[arg(short = 'o', long = "output", value_name = "FILE", default_value = "../injector/src/blob.bin")]
    output: PathBuf,
}

fn rva_to_offset(pe: &PE, rva: usize) -> Option<usize> {
    for section in &pe.sections {
        let virtual_address = section.virtual_address as usize;
        let virtual_size = section.virtual_size as usize;
        let range = virtual_address..(virtual_address + virtual_size);
        if range.contains(&rva) {
            let delta = rva - virtual_address;
            let file_off = section.pointer_to_raw_data as usize + delta;
            return Some(file_off);
        }
    };
    None
}

fn main() -> io::Result<()> {
    let opt = Opt::parse();

    // Read inputs
    let stub    = fs::read(&opt.stub)
        .unwrap_or_else(|e| panic!("cannot read stub {:?}: {e}", opt.stub));
    let payload = fs::read(&opt.payload)
        .unwrap_or_else(|e| panic!("cannot read payload {:?}: {e}", opt.payload));

    let pe = PE::parse(&stub).expect("Stub is not a valid PE.");
    let exports = &pe.exports;
    let entry_rva = exports
        .iter()
        .find(|e| e.name == Some("loader_entry".into()))
        .expect("loader_entry not exported")
        .rva;
    let offset = rva_to_offset(&pe, entry_rva).expect("Failed to calculate offset");
    // Build blob
    let mut out = fs::File::create(&opt.output)?;
    out.write_all(&(stub.len()    as u32).to_le_bytes())?;
    out.write_all(&(payload.len() as u32).to_le_bytes())?;
    out.write_all(&(offset     as u32).to_le_bytes())?;
    out.write_all(&stub)?;
    out.write_all(&payload)?;

    println!("blob written to {:?}", opt.output);
    Ok(())
}
