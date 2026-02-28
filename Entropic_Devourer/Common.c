#include "Common.h"

PayloadData g_payload = {0};

bool read_bin_file(const char* file_input) {
    FILE* file = fopen(file_input, "rb");
    if (!file) {
        perror("[!] fopen failed");
        return false;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size <= 0) {
        fprintf(stderr, "[!] Invalid file size\n");
        fclose(file);
        return false;
    }
    
    unsigned char* buffer = (unsigned char*)malloc(file_size);
    if (!buffer) {
        perror("[!] malloc failed");
        fclose(file);
        return false;
    }
    
    size_t bytes_read = fread(buffer, 1, file_size, file);
    if (bytes_read != (size_t)file_size) {
        perror("[!] fread failed");
        free(buffer);
        fclose(file);
        return false;
    }
    
    g_payload.bytes_number = bytes_read;
    g_payload.p_shell = buffer;
    
    fclose(file);
    printf("[+] Successfully read %zu bytes from %s\n", bytes_read, file_input);
    return true;
}

int round_up(int num_to_round, int multiple) {
    if (multiple == 0) {
        return num_to_round;
    }
    int remainder = num_to_round % multiple;
    if (remainder == 0) {
        return num_to_round;
    }
    return num_to_round + multiple - remainder;
}

void append_shellcode(int n) {
    unsigned char nop = 0x90;
    int multiple_by_n = round_up(g_payload.bytes_number, n);
    printf("[+] Constructing shellcode to be multiple of %d, target size: %d\n", 
           n, multiple_by_n);
    
    int bytes_to_add = multiple_by_n - g_payload.bytes_number;
    unsigned char* new_padded = (unsigned char*)malloc(g_payload.bytes_number + bytes_to_add + 1);
    
    if (!new_padded) {
        perror("[!] malloc failed in append_shellcode");
        return;
    }
    
    memcpy(new_padded, g_payload.p_shell, g_payload.bytes_number);
    
    for (int i = 0; i < bytes_to_add; i++) {
        new_padded[g_payload.bytes_number + i] = nop;
    }
    
    printf("[+] Added %d NOP bytes\n", bytes_to_add);
    g_payload.final_size = g_payload.bytes_number + bytes_to_add;
    g_payload.p_new_shell = new_padded;
}

void apply_xor(const unsigned char* key, size_t key_len) {
    if (key == NULL || key_len == 0) {
        fprintf(stderr, "[!] apply_xor called with empty key\n");
        return;
    }
    g_payload.final_size = g_payload.bytes_number;
    unsigned char *out = malloc(g_payload.final_size);
    if (!out) {
        perror("[!] malloc failed in apply_xor");
        return;
    }
    for (size_t i = 0; i < g_payload.final_size; i++) {
        out[i] = g_payload.p_shell[i] ^ key[i % key_len];
    }
    g_payload.p_new_shell = out;
    printf("[+] Applied XOR with key length %zu\n", key_len);
}

void apply_rc4(const unsigned char* key, size_t key_len) {
    if (key == NULL || key_len == 0) {
        fprintf(stderr, "[!] apply_rc4 called with empty key\n");
        return;
    }
    g_payload.final_size = g_payload.bytes_number;
    unsigned char *out = malloc(g_payload.final_size);
    if (!out) {
        perror("[!] malloc failed in apply_rc4");
        return;
    }
    unsigned char s[256];
    for (int i = 0; i < 256; i++) {
        s[i] = (unsigned char)i;
    }
    unsigned int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % key_len]) & 0xFF;
        unsigned char tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }
    unsigned int i = 0;
    j = 0;
    for (size_t k = 0; k < g_payload.final_size; k++) {
        i = (i + 1) & 0xFF;
        j = (j + s[i]) & 0xFF;
        unsigned char tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
        unsigned char rnd = s[(s[i] + s[j]) & 0xFF];
        out[k] = g_payload.p_shell[k] ^ rnd;
    }
    g_payload.p_new_shell = out;
    printf("[+] Applied RC4 with key length %zu\n", key_len);
}

bool write_shellcode_file(const char* file_name) {
  
    FILE* file = fopen(file_name, "w");
    if (!file) {
        fprintf(stderr, "[!] fopen failed for output file '%s': ", file_name);
        perror(NULL);
        return false;
    }
    
    g_payload.output_file = file;
    return true;
}