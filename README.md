# Reflective PE Loader

> **⚠️ WARNING**  
>    This is a project for demonstration, research and learning purposes only. 
>    Don't use it for anything illegal, please respect the law.

Rust‑based implementation of a fully manual PE loader for 64‑bit Windows.  The loader maps a DLL from memory, applies relocations, resolves imports, honours TLS callbacks, sets per‑section page protections, and finally transfers control to `DllMain` without ever invoking `LoadLibrary`.

---

## Repository layout

```
.
├─ Cargo.toml / Cargo.lock
├─ LICENSE                          
├─ loader_stub/                     
│  ├─ Cargo.toml    
│  └─ src/  
│     ├─ main.rs
│     └─ payload_messagebox.dll  # demo DLL (x64)
└─ README.md
```

## Current capabilities

* Section mapping and zero‑initialisation of `.bss`
* Base relocation (64‑bit `IMAGE_REL_BASED_DIR64`)
* Import Address Table fix‑up via Win32 API
* TLS directory parsing and callback execution
* Per‑section page protection (`.text` => RX, `.data` => RW, etc.)
* Execution of `DllMain` with `DLL_PROCESS_ATTACH`

Running `loader_stub.exe` on Windows opens the demo MessageBox supplied by `payload_messagebox.dll`, demonstrating a complete in‑memory load.

## Roadmap

| Phase | Description                                                     | Status       |
| ----- | --------------------------------------------------------------- | ------------ |
| 1     | In‑process loader (baseline)                                    | **complete** |
| 2     | Remote injection – `NtCreateThreadEx` with manual‑mapped buffer | in progress  |
| 3     | Silent import resolver (PEB export walk, hash lookup)           | planned      |
| 4     | Payload encryption / polymorphic stub                           | planned      |
| 5     | Graceful detach and memory cleanup                              | planned      |
| 6     | Section‑mapping hollowing                                       | planned      |
| 7     | Anti‑analysis features (ETW, anti‑debug)                        | planned      |

*The order is incremental: each phase introduces one new capability while retaining strict separation of concerns.*

## Building

```powershell
# on a Windows host or cross‑compiled toolchain
git clone <repo>
cd loader_stub
cargo build --release --target x86_64-pc-windows-gnu
```

Copy `loader_stub/target/x86_64-pc-windows-gnu/release/loader_stub.exe` to a Windows test machine and run.  The program prints diagnostic output to the console and shows the MessageBox if the load succeeds.

## Licence

MIT – see `LICENSE` for details.
