#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include "Common.h"
#include "code_to_bytes.h"
#include "ipv4fuscation.h"
#include "ipv6fuscation.h"
#include "MacFuscation.h"
#include "xorfuscation.h"

#define COLOR_RESET   "\x1b[0m"
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_WHITE   "\x1b[37m"

#define IPV4_FUSCATION 1000
#define MAC_FUSCATION  2000
#define IPV6_FUSCATION 3000
#define XOR_FUSCATION  4000
#define OUTPUT_EXEC    1
#define OUTPUT_TEXT    2
#define OUTPUT_JSON    3
#define TOOL_VERSION   "V 1.1 beta"

static char *strdup_trim(const char *s) {
    if (!s)
        return NULL;
    while (isspace((unsigned char)*s)) s++;
    size_t len = strlen(s);
    while (len && isspace((unsigned char)s[len-1])) len--;
    char *r = malloc(len + 1);
    if (!r) return NULL;
    memcpy(r, s, len);
    r[len] = '\0';
    return r;
}

static void load_config(const char *path, char **opt_out, char **fmt_out, char **xor_key_out) {
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0')
            continue;
        char *eq = strchr(p, '=');
        if (!eq)
            continue;
        *eq = '\0';
        char *key = strdup_trim(p);
        char *val = strdup_trim(eq + 1);
        if (key && val) {
            if (strcasecmp(key, "option") == 0 && *opt_out == NULL) {
                *opt_out = val;
                val = NULL;
            } else if (strcasecmp(key, "format") == 0 && *fmt_out == NULL) {
                *fmt_out = val;
                val = NULL;
            } else if (strcasecmp(key, "xor_key") == 0 && *xor_key_out == NULL) {
                *xor_key_out = val;
                val = NULL;
            }
        }
        free(key);
        free(val);
    }
    fclose(f);
}


void print_usage(const char* program_name) {
    printf(COLOR_CYAN "Entropic Devourer %s" COLOR_RESET "\n", TOOL_VERSION);
    printf("Usage: %s [options] <payload file> <option> [format]\n", program_name);
    printf("       %s [options] --help\n", program_name);
    printf("       %s [options] --version\n", program_name);
    printf("\n" COLOR_YELLOW "General options:" COLOR_RESET "\n");
    printf("  -h, --help           Show this help message and exit\n");
    printf("  -v, --version        Show version information\n");
    printf("  -c, --config <file>  Load defaults from configuration file\n");
    printf("  -d, --desobfuscate <type>  Print C decoder for given option and exit\n");
    printf("  -k, --key <key>      Provide XOR key for normal or decoder modes\n");
    printf("  -q, --quiet          Suppress informational messages\n");
    printf("\n" COLOR_YELLOW "Obfuscation options:" COLOR_RESET "\n");
    printf("  mac, macfuscation    Use MAC‑style 6‑byte blocks\n");
    printf("  ipv4, ipv4fuscation  Use IPv4 4‑byte blocks\n");
    printf("  ipv6, ipv6fuscation  Use IPv6 16‑byte blocks\n");
    printf("  xor, xorfuscation <key>  XOR with provided key (0xNN or string)\n");
    printf("  bytes, byte, array   Dump raw bytes as C array (no decoder)\n");
    printf("\n" COLOR_YELLOW "Deobfuscation helpers:" COLOR_RESET "\n");
    printf("  use -d <type> to emit a decoder function in C for an obfuscation\n");
    printf("    types: mac, ipv4, ipv6, xor (requires -k key)\n");
    printf("\n" COLOR_YELLOW "Formats (optional):" COLOR_RESET "\n");
    printf("  exec (default) -> generates runnable C source\n");
    printf("  text           -> generates only const char* array block\n");
    printf("  json, jason    -> generates obfuscated data as JSON\n");
    printf("\n" COLOR_YELLOW "Configuration file:" COLOR_RESET "\n");
    printf("  The program will look for ~/.entropicdevourerrc by default if\n");
    printf("  " COLOR_CYAN "--config" COLOR_RESET " is not specified. Example file:\n");
    printf("    # comment lines start with #\n");
    printf("    option = ipv4\n");
    printf("    format = text\n");
    printf("    xor_key = 0x5A   # used when option is \"xor\"\n");
    printf("\n" COLOR_YELLOW "Examples:" COLOR_RESET "\n");
    printf("  %s shellcode.bin ipv4\n", program_name);
    printf("  %s shellcode.bin ipv4 text\n", program_name);
    printf("  %s shellcode.bin ipv4 json\n", program_name);
    printf("  %s script.py bytes\n", program_name);
    printf("  %s -c myconfig.cfg mypayload.bin\n", program_name);
}

void print_version() {
    printf(COLOR_GREEN "Entropic Devourer %s" COLOR_RESET "\n", TOOL_VERSION);
}

static void print_ipv4_decoder(void) {
    puts("#include <arpa/inet.h>");
    puts("#include <string.h>");
    puts("int decode_ipv4(const char* in[], unsigned char* out, int count) {");
    puts("    struct in_addr addr;");
    puts("    int offset = 0;");
    puts("    for (int i = 0; i < count; i++) {");
    puts("        if (inet_pton(AF_INET, in[i], &addr) != 1) return -1;");
    puts("        memcpy(out + offset, &addr, 4); offset += 4;");
    puts("    }");
    puts("    return 0;");
    puts("}");
}

static void print_ipv6_decoder(void) {
    puts("#include <arpa/inet.h>");
    puts("#include <string.h>");
    puts("int decode_ipv6(const char* in[], unsigned char* out, int count) {");
    puts("    struct in6_addr addr;");
    puts("    int offset = 0;");
    puts("    for (int i = 0; i < count; i++) {");
    puts("        if (inet_pton(AF_INET6, in[i], &addr) != 1) return -1;");
    puts("        memcpy(out + offset, &addr, 16); offset += 16;");
    puts("    }");
    puts("    return 0;");
    puts("}");
}

static void print_mac_decoder(void) {
    puts("#include <stdlib.h>");
    puts("#include <string.h>");
    puts("int decode_mac(const char* in[], unsigned char* out, int count) {");
    puts("    int offset = 0;");
    puts("    for (int i = 0; i < count; i++) {");
    puts("        unsigned int bytes[6];");
    puts("        if (sscanf(in[i], \"%02x:%02x:%02x:%02x:%02x:%02x\", &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]) != 6) return -1;");
    puts("        for (int j = 0; j < 6; j++) out[offset++] = (unsigned char)bytes[j];");
    puts("    }");
    puts("    return 0;");
    puts("}");
}

static void print_xor_decoder(const unsigned char *key, size_t key_len) {
    puts("#include <stddef.h>");
    puts("void xor_decode(unsigned char* buf, size_t len) {");
    puts("    const unsigned char key[] = {");
    for (size_t i = 0; i < key_len; i++) {
        printf("    0x%02x,%s\n", key[i], i+1<key_len?"":"");
    }
    puts("    };\n    size_t klen = sizeof(key);");
    puts("    for (size_t i = 0; i < len; i++) buf[i] ^= key[i % klen];");
    puts("}");
}

void print_logo() {
    printf("\n");
    printf("███████╗███╗   ██╗████████╗██████╗  ██████╗ ██████╗ ██╗ ██████╗\n");
    fflush(stdout);
    printf("██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔═══██╗██╔══██╗██║██╔════╝\n");
    printf("█████╗  ██╔██╗ ██║   ██║   ██████╔╝██║   ██║██████╔╝██║██║     \n");
    printf("██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██║   ██║██╔═══╝ ██║██║     \n");
    printf("███████╗██║ ╚████║   ██║   ██║  ██║╚██████╔╝██║     ██║╚██████╗\n");
    printf("╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝\n");
    printf("██████╗ ███████╗██╗   ██╗ ██████╗ ██╗   ██╗██████╗ ███████╗██████╗\n");
    printf("██╔══██╗██╔════╝██║   ██║██╔═══██╗██║   ██║██╔══██╗██╔════╝██╔══██╗\n");
    printf("██║  ██║█████╗  ██║   ██║██║   ██║██║   ██║██████╔╝█████╗  ██████╔╝\n");
    printf("██║  ██║██╔══╝  ╚██╗ ██╔╝██║   ██║██║   ██║██╔══██╗██╔══╝  ██╔══██╗\n");
    printf("██████╔╝███████╗ ╚████╔╝ ╚██████╔╝╚██████╔╝██║  ██║███████╗██║  ██║\n");
    printf("╚═════╝ ╚══════╝  ╚═══╝   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝\n");
    printf("\t\t\t\t\t\t\t\t\t\t\t\tBY Ozyy (Linux Port)\n\n");
}

int main(int argc, char* argv[]) {
    int type = 0;
    int output_mode = OUTPUT_EXEC;
    bool quiet = false;
    char *payload_file = NULL;

    print_logo();
    char *option = NULL;
    char *format = NULL;
    char *xor_key = NULL;
    char *config_path = NULL;


    static struct option longopts[] = {
        {"help",           no_argument,       NULL, 'h'},
        {"version",        no_argument,       NULL, 'v'},
        {"config",         required_argument, NULL, 'c'},
        {"quiet",          no_argument,       NULL, 'q'},
        {"desobfuscate",   required_argument, NULL, 'd'},
        {"key",            required_argument, NULL, 'k'},
        {NULL, 0, NULL, 0}
    };

    bool des_mode = false;
    char *des_type = NULL;
    int ch;
    while ((ch = getopt_long(argc, argv, "hvc:qd:k:", longopts, NULL)) != -1) {
        switch (ch) {
            case 'h':
                if (!quiet) print_logo();
                print_usage(argv[0]);
                return 0;
            case 'v':
                if (!quiet) print_logo();
                print_version();
                return 0;
            case 'c':
                config_path = strdup(optarg);
                break;
            case 'q':
                quiet = true;
                break;
            case 'd':
                des_mode = true;
                des_type = strdup(optarg);
                break;
            case 'k':
                if (des_mode) {
                    xor_key = strdup(optarg);
                } else {
                    xor_key = strdup(optarg);
                }
                break;
            default:
                print_usage(argv[0]);
                return -1;
        }
    }

    if (!config_path) {
        const char *home = getenv("HOME");
        if (home) {
            size_t len = strlen(home) + strlen("/.entropicdevourerrc") + 1;
            config_path = malloc(len);
            snprintf(config_path, len, "%s/.entropicdevourerrc", home);
        }
    }

    if (config_path) {
        load_config(config_path, &option, &format, &xor_key);
    }

    if (!des_mode) {
        if (optind < argc) {
            payload_file = argv[optind++];
        }
        if (optind < argc) {
            option = argv[optind++];
        }
        if (option && (strcasecmp(option, "xor") == 0 || strcasecmp(option, "xorfuscation") == 0)) {
            if (optind < argc) {
                xor_key = argv[optind++];
            }
        }
        if (optind < argc) {
            format = argv[optind++];
        }

        if (!payload_file || !option) {
            print_usage(argv[0]);
            return -1;
        }
        if ((strcasecmp(option, "xor") == 0 || strcasecmp(option, "xorfuscation") == 0) && !xor_key) {
            if (!quiet) fprintf(stderr, COLOR_RED "[!] xor option requires a key argument\n" COLOR_RESET);
            print_usage(argv[0]);
            return -1;
        }
    }

    if (des_mode) {
        if (!des_type) {
            if (!quiet) fprintf(stderr, COLOR_RED "[!] desobfuscation type missing\n" COLOR_RESET);
            print_usage(argv[0]);
            return -1;
        }
        for (int i = 0; des_type[i]; i++) des_type[i] = tolower(des_type[i]);
        if (strcmp(des_type, "ipv4") == 0) {
            print_ipv4_decoder();
        } else if (strcmp(des_type, "ipv6") == 0) {
            print_ipv6_decoder();
        } else if (strcmp(des_type, "mac") == 0) {
            print_mac_decoder();
        } else if (strcmp(des_type, "xor") == 0) {
            if (!xor_key) {
                if (!quiet) fprintf(stderr, COLOR_RED "[!] xor decoder requires key (-k)\n" COLOR_RESET);
                return -1;
            }
            unsigned char tmpbuf[256];
            size_t tmp_len=0;
            if (strlen(xor_key)>2 && xor_key[0]=='0' && xor_key[1]=='x') {
                unsigned int v; sscanf(xor_key, "%x", &v);
                tmpbuf[0]=v&0xFF; tmp_len=1;
            } else {
                tmp_len = strlen(xor_key);
                memcpy(tmpbuf, xor_key, tmp_len);
            }
            print_xor_decoder(tmpbuf,tmp_len);
        } else {
            if (!quiet) fprintf(stderr, COLOR_RED "[!] unknown desobfuscation type '%s'\n" COLOR_RESET, des_type);
            return -1;
        }
        return 0;
    }

    print_logo();

    for (int i = 0; option[i]; i++) {
        option[i] = tolower(option[i]);
    }

    if (strcmp(option, "bytes") == 0 || strcmp(option, "byte") == 0 || strcmp(option, "array") == 0) {
        const char* suffix = "_bytes.txt";
        size_t out_len = strlen(payload_file) + strlen(suffix) + 1;
        char* output_filename = malloc(out_len);
        if (!output_filename) {
            perror(COLOR_RED "[!] malloc failed" COLOR_RESET);
            return -1;
        }

        snprintf(output_filename, out_len, "%s%s", payload_file, suffix);

        if (convert_code_to_bytes(payload_file, output_filename)) {
            if (!quiet) printf(COLOR_GREEN "[✓] Successfully generated %s" COLOR_RESET "\n", output_filename);
            free(output_filename);
            return 0;
        }

        if (!quiet) printf(COLOR_RED "[✗] Failed to generate byte array" COLOR_RESET "\n");
        free(output_filename);
        return -1;
    }

    if (!read_bin_file(payload_file) || g_payload.p_shell == NULL || g_payload.bytes_number == 0) {
        return -1;
    }
    
    if (!quiet) printf(COLOR_BLUE "[i] Original shellcode size: %zu bytes" COLOR_RESET "\n", g_payload.bytes_number);
    
    if (format) {
        for (int i = 0; format[i]; i++) {
            format[i] = tolower(format[i]);
        }

        if (strcmp(format, "text") == 0 || strcmp(format, "txt") == 0) {
            output_mode = OUTPUT_TEXT;
        } else if (strcmp(format, "json") == 0 || strcmp(format, "jason") == 0) {
            output_mode = OUTPUT_JSON;
        } else if (strcmp(format, "exec") == 0 || strcmp(format, "c") == 0) {
            output_mode = OUTPUT_EXEC;
        } else {
            if (!quiet) printf(COLOR_RED "[!] Unknown format: %s" COLOR_RESET "\n", format);
            print_usage(argv[0]);
            free(g_payload.p_shell);
            return -1;
        }
    }
    
    if (strcmp(option, "mac") == 0 || strcmp(option, "macfuscation") == 0) {
        if (g_payload.bytes_number % 6 == 0) {
            if (!quiet) printf(COLOR_BLUE "[i] Shellcode is already multiple of 6" COLOR_RESET "\n");
            g_payload.p_new_shell = malloc(g_payload.bytes_number);
            memcpy(g_payload.p_new_shell, g_payload.p_shell, g_payload.bytes_number);
            g_payload.final_size = g_payload.bytes_number;
        } else {
            if (!quiet) printf(COLOR_BLUE "[i] Shellcode is not multiple of 6" COLOR_RESET "\n");
            append_shellcode(6);
        }
        type = MAC_FUSCATION;
    }
    else if (strcmp(option, "ipv4") == 0 || strcmp(option, "ipv4fuscation") == 0) {
        if (g_payload.bytes_number % 4 == 0) {
            if (!quiet) printf(COLOR_BLUE "[i] Shellcode is already multiple of 4" COLOR_RESET "\n");
            g_payload.p_new_shell = malloc(g_payload.bytes_number);
            memcpy(g_payload.p_new_shell, g_payload.p_shell, g_payload.bytes_number);
            g_payload.final_size = g_payload.bytes_number;
        } else {
            if (!quiet) printf(COLOR_BLUE "[i] Shellcode is not multiple of 4" COLOR_RESET "\n");
            append_shellcode(4);
        }
        type = IPV4_FUSCATION;
    }
    else if (strcmp(option, "ipv6") == 0 || strcmp(option, "ipv6fuscation") == 0) {
        if (g_payload.bytes_number % 16 == 0) {
            if (!quiet) printf(COLOR_BLUE "[i] Shellcode is already multiple of 16" COLOR_RESET "\n");
            g_payload.p_new_shell = malloc(g_payload.bytes_number);
            memcpy(g_payload.p_new_shell, g_payload.p_shell, g_payload.bytes_number);
            g_payload.final_size = g_payload.bytes_number;
        } else {
            if (!quiet) printf(COLOR_BLUE "[i] Shellcode is not multiple of 16" COLOR_RESET "\n");
            append_shellcode(16);
        }
        type = IPV6_FUSCATION;
    }
    else {
        if (!quiet) printf(COLOR_RED "[!] Unknown option: %s" COLOR_RESET "\n", option);
        print_usage(argv[0]);
        free(g_payload.p_shell);
        return -1;
    }
    
    printf("[i] Final shellcode size: %zu bytes\n", g_payload.final_size);
    
    bool success = false;
    const char* output_filename = NULL;
    
    unsigned char *xor_key_bytes = NULL;
    size_t xor_key_len = 0;
    if (type == XOR_FUSCATION) {
        if (xor_key) {
            if (strlen(xor_key) > 2 && xor_key[0]=='0' && xor_key[1]=='x') {
                unsigned int v;
                if (sscanf(xor_key, "%x", &v) == 1) {
                    xor_key_bytes = malloc(1);
                    xor_key_bytes[0] = v & 0xFF;
                    xor_key_len = 1;
                }
            }
            if (xor_key_len == 0) {
                xor_key_len = strlen(xor_key);
                xor_key_bytes = malloc(xor_key_len);
                memcpy(xor_key_bytes, xor_key, xor_key_len);
            }
        }
        if (!xor_key_bytes || xor_key_len == 0) {
            if (!quiet) fprintf(stderr, COLOR_RED "[!] failed to parse xor key\n" COLOR_RESET);
            free(g_payload.p_shell);
            return -1;
        }
        apply_xor(xor_key_bytes, xor_key_len);
        /* payload already processed; skip other generation switch? We'll generate based on g_payload.p_new_shell etc. */
    }
    
    switch (type) {
        case IPV4_FUSCATION:
            if (output_mode == OUTPUT_TEXT) {
                output_filename = "ipv4_shellcode.txt";
                success = generate_ipv4_text_output(output_filename);
            } else if (output_mode == OUTPUT_JSON) {
                output_filename = "ipv4_shellcode.json";
                success = generate_ipv4_json_output(output_filename);
            } else {
                output_filename = "ipv4_shellcode.c";
                success = generate_ipv4_output(output_filename);
            }
            break;
        case MAC_FUSCATION:
            if (output_mode == OUTPUT_TEXT) {
                output_filename = "mac_shellcode.txt";
                success = generate_mac_text_output(output_filename);
            } else if (output_mode == OUTPUT_JSON) {
                output_filename = "mac_shellcode.json";
                success = generate_mac_json_output(output_filename);
            } else {
                output_filename = "mac_shellcode.c";
                success = generate_mac_output(output_filename);
            }
            break;
        case IPV6_FUSCATION:
            if (output_mode == OUTPUT_TEXT) {
                output_filename = "ipv6_shellcode.txt";
                success = generate_ipv6_text_output(output_filename);
            } else if (output_mode == OUTPUT_JSON) {
                output_filename = "ipv6_shellcode.json";
                success = generate_ipv6_json_output(output_filename);
            } else {
                output_filename = "ipv6_shellcode.c";
                success = generate_ipv6_output(output_filename);
            }
            break;
        case XOR_FUSCATION:
            if (output_mode == OUTPUT_TEXT) {
                output_filename = "xor_shellcode.txt";
                success = generate_xor_text_output(output_filename, xor_key_bytes, xor_key_len);
            } else if (output_mode == OUTPUT_JSON) {
                output_filename = "xor_shellcode.json";
                success = generate_xor_json_output(output_filename, xor_key_bytes, xor_key_len);
            } else {
                output_filename = "xor_shellcode.c";
                success = generate_xor_output(output_filename, xor_key_bytes, xor_key_len);
            }
            break;
    }
    
    if (success) {
        printf("[✓] Successfully generated %s\n", output_filename);
        if (output_mode == OUTPUT_EXEC) {
            printf("[i] To compile: gcc -o shellcode %s -pthread\n", output_filename);
            printf("[i] To run: ./shellcode\n");
        }
    } else {
        printf("[✗] Failed to generate output\n");
    }
    
    if (g_payload.p_shell) {
        free(g_payload.p_shell);
    }
    if (g_payload.p_new_shell && g_payload.p_new_shell != g_payload.p_shell) {
        free(g_payload.p_new_shell);
    }
    if (config_path) {
        free(config_path);
    }
    if (xor_key_bytes) {
        free(xor_key_bytes);
    }
   
    return success ? 0 : -1;
}
