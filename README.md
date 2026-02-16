# 🐧 Static ELF Loader

A low-level system utility written in C that manually loads and executes 64-bit static ELF binaries by managing process memory and the execution stack.

🚀 Overview
This project is a custom implementation of an ELF (Executable and Linkable Format) loader for Linux. It bypasses the standard OS loading mechanism by manually mapping binary segments into memory, setting up the process environment, and handing over control to the entry point.

🏗️ Technical Implementation

1. Binary Validation & Parsing
Header Verification: The loader validates the ELF magic bytes and ensures the binary is a 64-bit executable (`ELFCLASS64`) before execution.
Program Header Iteration: It parses the Program Header table to identify and process all `PT_LOAD` segments.

2. Memory Management
Segment Mapping: Uses `mmap()` with `MAP_FIXED` to map segments at their specific virtual addresses, ensuring correct page alignment via `sysconf(_SC_PAGESIZE)`.
Permission Enforcement: Implements granular memory protection (Read, Write, Execute) using `mprotect()` based on the `p_flags` defined in the ELF structure.

3. Execution Environment (Stack Setup)
Data Passing: Manually constructs the initial process stack, including `argc`, `argv`, and environment variables (`envp`).
Auxiliary Vector (auxv): Correct de-serialization of the Auxiliary Vector, providing the loaded binary with critical system info:
    `AT_PHDR`, `AT_PHENT`, `AT_PHNUM` for header info.
    `AT_ENTRY` for the starting point.
    `AT_RANDOM` generated dynamically using `getrandom()` for security.

4. Context Switching
Inline Assembly: Uses `__asm__` blocks to manually set the Stack Pointer (`%rsp`) and perform a jump to the binary's entry point, effectively transitioning execution control.

📊 Results & Performance
Passed Tests: Successfully executes static, non-PIE binaries, passing all `no_pie` test cases (hello, argc, argv, envp, auxv).
Limitation: Support for PIE (Position Independent Executables) is currently a work-in-progress.

💻 Building and Usage

Build
```bash
make ./elf-loader test_name