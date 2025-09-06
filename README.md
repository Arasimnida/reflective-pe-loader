# Reflective PE Loader

> **⚠️ WARNING**  
>    This is a project for demonstration, research, pentesting/red-teaming and learning purposes only. 
>    Don't use it for anything illegal, please respect the law.

This project implements a manual mapping PE loader (PE32 & PE32+) written in Rust.
The loader is designed for academic use within the scope of Windows internals and low-level security research. Its purpose is to illustrate how Windows loads Portable Executables (PE) at runtime, and how each step of the process can be replicated in userland without invoking the standard loader.

---

## Overview

The code is separated into dedicated crates for clarity:

- `pe_format/` responsible for parsing PE headers, section tables, and data directories. Provides safe abstractions over the DOS, NT, section, and directory structures.

- `pe_loader/` implements the manual mapping algorithm, step by step: Reserving memory and copying headers/sections. Applying relocations if the preferred base cannot be honored. Resolving imports and writing the Import Address Table (IAT). Adjusting memory protections according to section characteristics. Collecting TLS callbacks.

- `loader_stub/` demonstration program. Loads a test DLL (MessageBox example), invokes the loader pipeline, logs the operations for analysis and execution of the entry point. There is two different paylaods, one for each architecture, you can change main.rs in order to load the selected paylaod.

## Intended Audience

This work is intended for researchers, students, and professionals interested in:

- Understanding the internals of the Windows PE loader.
- Studying how memory managers handle relocations, imports, and section protections.
- Comparing system loader behavior against a controlled userland re-implementation.

## Project Structure

```
.
├── Cargo.lock
├── Cargo.toml
├── LICENSE
│
├── loader_stub/                    # Demonstration binary
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                 # Orchestration of the demo: parse, map, log
│       ├── payload_messagebox.dll  # Test DLL (MessageBox) used as input
│       └── utils.rs                # Utility functions (support for future extensions)
│
├── pe_format/                      # Low-level PE parsing library
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                  # Core parsing logic and high-level PeImage abstraction
│       └── types.rs                # Structs representing DOS/NT headers, sections, data directories
│
├── pe_loader/                      # Manual mapping implementation
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                  # Loader orchestrator (map_image) and public API
│       ├── copy.rs                 # Memory allocation, headers and sections copy
│       ├── reloc.rs                # Relocation handling (DIR64)
│       ├── imports.rs              # Import resolution (IAT population)
│       ├── protect.rs              # Section protection adjustment (VirtualProtect)
│       └── tls.rs                  # TLS directory parsing and callbacks collection
│
└── README.md
```

## Building

```powershell
# on a Windows host or cross‑compiled toolchain
git clone <repo>
cd loader_stub
# For x64 payload
cargo build --release --target x86_64-pc-windows-gnu
# For x86 payload
cargo build --release --target i686-pc-windows-gnu
```

Copy `loader_stub/target/x86_64-pc-windows-gnu/release/loader_stub.exe` or `loader_stub/target/i686-pc-windows-gnu/release/loader_stub.exe` to a Windows test machine and run. The program prints diagnostic output to the console and shows the MessageBox if the load succeeds.

## Limitations

- Only DLL are supported.

## Licence

MIT – see `LICENSE` for details.
