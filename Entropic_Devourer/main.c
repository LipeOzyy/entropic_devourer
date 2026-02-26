#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "Common.h"
#include "ipv4fuscation.h"
#include "ipv6fuscation.h"
#include "MacFuscation.h"

#define IPV4_FUSCATION 1000
#define MAC_FUSCATION  2000
#define IPV6_FUSCATION 3000

void print_usage(const char* program_name) {
    printf("Usage: %s <payload file> <option>\n", program_name);
    printf("\nOptions:\n");
    printf("  mac, macfuscation \n");
    printf("  ipv4, ipv4fuscation \n");
    printf("  ipv6, ipv6fuscation \n");
    printf("\nExample:\n");
    printf("  %s shellcode.bin ipv4\n", program_name);
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
    
    print_logo();
    
    if (argc != 3) {
        print_usage(argv[0]);
        return -1;
    }
    
    if (!read_bin_file(argv[1]) || g_payload.p_shell == NULL || g_payload.bytes_number == 0) {
        return -1;
    }
    
    printf("[i] Original shellcode size: %zu bytes\n", g_payload.bytes_number);
    
    char* option = argv[2];
    
    for (int i = 0; option[i]; i++) {
        option[i] = tolower(option[i]);
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
            output_filename = "ipv4_shellcode.c";
            success = generate_ipv4_output(output_filename);
            break;
        case MAC_FUSCATION:
            output_filename = "mac_shellcode.c";
            success = generate_mac_output(output_filename);
            break;
        case IPV6_FUSCATION:
            output_filename = "ipv6_shellcode.c";
            success = generate_ipv6_output(output_filename);
            break;
    }
    
    if (success) {
        printf("[✓] Successfully generated %s\n", output_filename);
        printf("[i] To compile: gcc -o shellcode %s -pthread\n", output_filename);
        printf("[i] To run: ./shellcode\n");
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
