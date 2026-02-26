![EDR is listening](/image/edr%20is%20listening.jpg)

# Entropic Devourer

Repository dedicated to the research and hands-on practice of advanced obfuscation techniques, with a focus on Linux environments. The goal is to explore effective methods for reducing detectability and hindering static analysis of artifacts, including the encoding of payloads and sensitive indicators (such as C2 server addresses). This project draws inspiration from modern obfuscation approaches and is intended for educational purposes, helping researchers and enthusiasts understand the mechanisms sophisticated malware uses to evade detection and analysis.

## Usage

### Prerequisites

- Linux
- GCC
- `make`
- Binary payload/shellcode file (e.g., `shellcode.bin`)

### Build

![alt text](/image/make.png)

```bash
make
```

Generated binary:

`Entropic_Devourer/entropic_devourer`

### Run

```bash
./Entropic_Devourer/entropic_devourer <payload_file> <option>
```

Available options:

![alt text](/image/ex1.png)

- `mac` or `macfuscation`
- `ipv4` or `ipv4fuscation`
- `ipv6` or `ipv6fuscation`

Examples:

```bash
./Entropic_Devourer/entropic_devourer shellcode.bin ipv4
./Entropic_Devourer/entropic_devourer shellcode.bin ipv6
./Entropic_Devourer/entropic_devourer shellcode.bin mac
```

Generated output files (depending on the selected option):

- `ipv4_shellcode.c`
- `ipv6_shellcode.c`
- `mac_shellcode.c`

To clean build and generated artifacts:

```bash
make clean
```

## References

- https://github.com/NUL0x4C/HellShell/tree/main
- https://github.com/midisec/BypassAnti-Virus
- https://www.bleepingcomputer.com/news/security/hive-ransomware-uses-new-ipfuscation-trick-to-hide-payload/
