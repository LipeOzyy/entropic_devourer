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
./Entropic_Devourer/entropic_devourer <payload_file> <option> [format]
./Entropic_Devourer/entropic_devourer --help
./Entropic_Devourer/entropic_devourer --version
```

Available options:

![alt text](/image/ex1.png)

- `mac` or `macfuscation`
- `ipv4` or `ipv4fuscation`
- `ipv6` or `ipv6fuscation`
- `bytes` or `byte` or `array`

Available formats:

- `exec` or `c` (default): generate C source with decoder + execution flow
- `text` or `txt`: generate only the obfuscated block (`const char* ...[] = { ... };`)
- `json` or `jason`: generate obfuscated data as JSON

For `bytes|byte|array`, the tool generates a C byte array file named `<input_file>_bytes.txt`.

Examples:

```bash
./Entropic_Devourer/entropic_devourer --help
./Entropic_Devourer/entropic_devourer --version
./Entropic_Devourer/entropic_devourer shellcode.bin ipv4
./Entropic_Devourer/entropic_devourer shellcode.bin ipv6
./Entropic_Devourer/entropic_devourer shellcode.bin mac
./Entropic_Devourer/entropic_devourer shellcode.bin ipv4 text
./Entropic_Devourer/entropic_devourer shellcode.bin ipv6 text
./Entropic_Devourer/entropic_devourer shellcode.bin mac text
./Entropic_Devourer/entropic_devourer shellcode.bin ipv4 json
./Entropic_Devourer/entropic_devourer script.py bytes
```

Generated output files (depending on the selected option):

- `ipv4_shellcode.c`
- `ipv6_shellcode.c`
- `mac_shellcode.c`
- `ipv4_shellcode.txt`
- `ipv6_shellcode.txt`
- `mac_shellcode.txt`
- `ipv4_shellcode.json`
- `ipv6_shellcode.json`
- `mac_shellcode.json`
- `<input_file>_bytes.txt`

To clean build and generated artifacts:

```bash
make clean
```

---

## Found an issue?

If you found any error, unexpected behavior, or identified something that could be improved, please get in touch.

Feedback is extremely important to keep the project consistent and continuously evolving.

---

## References

- https://github.com/NUL0x4C/HellShell/tree/main
- https://github.com/midisec/BypassAnti-Virus
- https://www.bleepingcomputer.com/news/security/hive-ransomware-uses-new-ipfuscation-trick-to-hide-payload/
