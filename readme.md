# RISCV-ELF-Disassembler

##### Less pretty analogue of `riscv64-unknown-elf-objdump -d `

Input file – RISCV 32-bit little endian ELF file

Output file – assembly dump

#### Compilation

Tested with `python 3.8`

#### Usage

```
python3 disassembler.py <input_file> [output_file]
```

No `output_file` means printing to `stdout`

#### Report

There is a report (in Russian) with

- RISCV ISA description
- ELF file structure description
- algorithm description



