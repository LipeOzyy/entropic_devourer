#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "Common.h"
#include "code_to_bytes.h"
#include "ipv4fuscation.h"
#include "ipv6fuscation.h"
#include "MacFuscation.h"

#define IPV4_FUSCATION 1000
#define MAC_FUSCATION  2000
#define IPV6_FUSCATION 3000
#define OUTPUT_EXEC    1
#define OUTPUT_TEXT    2
#define OUTPUT_JSON    3
#define TOOL_VERSION   "V 1.1 beta"

void print_usage(const char* program_name) {
    printf("Entropic Devourer %s\n", TOOL_VERSION);
    printf("Usage: %s <payload file> <option> [format]\n", program_name);
    printf("       %s --help\n", program_name);
    printf("       %s --version\n", program_name);
    printf("\nOptions:\n");
    printf("  mac, macfuscation \n");
    printf("  ipv4, ipv4fuscation \n");
    printf("  ipv6, ipv6fuscation \n");
    printf("  bytes, byte, array \n");
    printf("\nFormats (optional):\n");
    printf("  exec (default) -> generates runnable C source\n");
    printf("  text           -> generates only const char* array block\n");
    printf("  json, jason    -> generates obfuscated data as JSON\n");
    printf("\nExample:\n");
    printf("  %s shellcode.bin ipv4\n", program_name);
    printf("  %s shellcode.bin ipv4 text\n", program_name);
    printf("  %s shellcode.bin ipv4 json\n", program_name);
    printf("  %s script.py bytes\n", program_name);
}

void print_version() {
    printf("Entropic Devourer %s\n", TOOL_VERSION);
}

void print_logo() {
    printf("\n");
    printf("███████╗███╗   ██╗████████╗██████╗  ██████╗ ██████╗ ██╗ ██████╗\n");
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
    
    if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        print_usage(argv[0]);
        return 0;
    }

    if (argc == 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0)) {
        print_version();
        return 0;
    }

    print_logo();
    
    if (argc != 3 && argc != 4) {
        print_usage(argv[0]);
        return -1;
    }
    
    char* option = argv[2];
    
    for (int i = 0; option[i]; i++) {
        option[i] = tolower(option[i]);
    }

    if (strcmp(option, "bytes") == 0 || strcmp(option, "byte") == 0 || strcmp(option, "array") == 0) {
        const char* suffix = "_bytes.txt";
        size_t out_len = strlen(argv[1]) + strlen(suffix) + 1;
        char* output_filename = (char*)malloc(out_len);
        if (!output_filename) {
            perror("[!] malloc failed");
            return -1;
        }

        snprintf(output_filename, out_len, "%s%s", argv[1], suffix);

        if (convert_code_to_bytes(argv[1], output_filename)) {
            printf("[✓] Successfully generated %s\n", output_filename);
            free(output_filename);
            return 0;
        }

        printf("[✗] Failed to generate byte array\n");
        free(output_filename);
        return -1;
    }

    if (!read_bin_file(argv[1]) || g_payload.p_shell == NULL || g_payload.bytes_number == 0) {
        return -1;
    }
    
    printf("[i] Original shellcode size: %zu bytes\n", g_payload.bytes_number);
    
    if (argc == 4) {
        char* format = argv[3];
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
            printf("[!] Unknown format: %s\n", argv[3]);
            print_usage(argv[0]);
            free(g_payload.p_shell);
            return -1;
        }
    }
    
    if (strcmp(option, "mac") == 0 || strcmp(option, "macfuscation") == 0) {
        if (g_payload.bytes_number % 6 == 0) {
            printf("[i] Shellcode is already multiple of 6\n");
            g_payload.p_new_shell = (unsigned char*)malloc(g_payload.bytes_number);
            memcpy(g_payload.p_new_shell, g_payload.p_shell, g_payload.bytes_number);
            g_payload.final_size = g_payload.bytes_number;
        } else {
            printf("[i] Shellcode is not multiple of 6\n");
            append_shellcode(6);
        }
        type = MAC_FUSCATION;
    }
    else if (strcmp(option, "ipv4") == 0 || strcmp(option, "ipv4fuscation") == 0) {
        if (g_payload.bytes_number % 4 == 0) {
            printf("[i] Shellcode is already multiple of 4\n");
            g_payload.p_new_shell = (unsigned char*)malloc(g_payload.bytes_number);
            memcpy(g_payload.p_new_shell, g_payload.p_shell, g_payload.bytes_number);
            g_payload.final_size = g_payload.bytes_number;
        } else {
            printf("[i] Shellcode is not multiple of 4\n");
            append_shellcode(4);
        }
        type = IPV4_FUSCATION;
    }
    else if (strcmp(option, "ipv6") == 0 || strcmp(option, "ipv6fuscation") == 0) {
        if (g_payload.bytes_number % 16 == 0) {
            printf("[i] Shellcode is already multiple of 16\n");
            g_payload.p_new_shell = (unsigned char*)malloc(g_payload.bytes_number);
            memcpy(g_payload.p_new_shell, g_payload.p_shell, g_payload.bytes_number);
            g_payload.final_size = g_payload.bytes_number;
        } else {
            printf("[i] Shellcode is not multiple of 16\n");
            append_shellcode(16);
        }
        type = IPV6_FUSCATION;
    }
    else {
        printf("[!] Unknown option: %s\n", argv[2]);
        print_usage(argv[0]);
        free(g_payload.p_shell);
        return -1;
    }
    
    printf("[i] Final shellcode size: %zu bytes\n", g_payload.final_size);
    
    bool success = false;
    const char* output_filename = NULL;
    
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
    
    return success ? 0 : -1;
}
