![EDR is listening](/image/edr%20is%20listening.jpg)

# Entropic Devourer
Tool designed for research and experimentation in artifact obfuscation, capable of generating fuscation routines using formats such as IPv4, IPv6, MAC addresses, and XOR with a variable key, as well as automatically producing the corresponding decoders in C. The goal is to practically explore how sensitive data, such as C2 strings or payloads, can be transformed to reduce readability and hinder static analysis, making code comprehension significantly more complex for analysts and automated tools.

Designed as a technical laboratory for studying offensive and evasion techniques, the tool enables hands-on understanding of how small structural transformations impact detection mechanisms and reverse engineering processes. Its purpose is to enhance offensive security knowledge and strengthen the understanding of how artifacts can be protected or analyzed in real-world scenarios, always with an educational focus and responsible use.

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

The command‑line interface has been upgraded with long options, coloured
output, and support for a configuration file.

```bash
./Entropic_Devourer/entropic_devourer [options] <payload_file> <option> [format]
./Entropic_Devourer/entropic_devourer --help
./Entropic_Devourer/entropic_devourer --version
```

#### General options

- `-h`, `--help`           Show help and exit
- `-v`, `--version`        Print version
- `-c`, `--config FILE`    Read defaults (option/format) from config file
- `-q`, `--quiet`          Suppress informational messages

If `--config` is not supplied the program will look for
`$HOME/.entropicdevourerrc` automatically. Example of a configuration file:

```
# use ipv4 fuscation and output text by default
option = ipv4
format = text
xor_key = 0x5A   # only relevant when option is "xor"
```

#### Obfuscation options

- `mac`, `macfuscation`
- `ipv4`, `ipv4fuscation`
- `ipv6`, `ipv6fuscation`
- `xor`, `xorfuscation` <key>    (hex 0xNN or literal string)
- `bytes`, `byte`, `array`

#### Deobfuscation helpers

You can ask the tool to emit a decoder function in C instead of processing
payloads. The `-d` / `--desobfuscate` option accepts the same types
(`ipv4`, `ipv6`, `mac`, `xor`). For XOR you must also pass a key with
`-k`.

```bash
./Entropic_Devourer/entropic_devourer -d ipv4
./Entropic_Devourer/entropic_devourer -d xor -k 0x5A
```

#### Formats

- `exec` or `c` (default): generate C source with decoder + execution flow
- `text` or `txt`: generate only the obfuscated block (`const char* ...[] = { ... };`)
- `json` or `jason`: generate obfuscated data as JSON

Example invocations:

```bash
./Entropic_Devourer/entropic_devourer shellcode.bin ipv4
./Entropic_Devourer/entropic_devourer shellcode.bin ipv4 text
./Entropic_Devourer/entropic_devourer shellcode.bin ipv4 json
./Entropic_Devourer/entropic_devourer shellcode.bin xor 0x5A
./Entropic_Devourer/entropic_devourer shellcode.bin xor secret
./Entropic_Devourer/entropic_devourer -d ipv4
./Entropic_Devourer/entropic_devourer -d xor -k 0x5A
./Entropic_Devourer/entropic_devourer -c mycfg.cfg mypayload.bin
```

For `bytes|byte|array`, the tool generates a C byte array file named `<input_file>_bytes.txt`.

Examples:

```bash
./Entropic_Devourer/entropic_devourer --help
./Entropic_Devourer/entropic_devourer --version
./Entropic_Devourer/entropic_devourer shellcode.bin ipv4
./Entropic_Devourer/entropic_devourer shellcode.bin ipv6
./Entropic_Devourer/entropic_devourer shellcode.bin mac
./Entropic_Devourer/entropic_devourer shellcode.bin xor 0x5A
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
- `xor_shellcode.c`
- `ipv4_shellcode.txt`
- `ipv6_shellcode.txt`
- `mac_shellcode.txt`
- `xor_shellcode.txt`
- `ipv4_shellcode.json`
- `ipv6_shellcode.json`
- `mac_shellcode.json`
- `xor_shellcode.json`
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
