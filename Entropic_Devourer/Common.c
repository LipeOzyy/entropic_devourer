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

bool write_shellcode_file(const char* file_name) {
    FILE* file = fopen(file_name, "w");
    if (!file) {
        perror("[!] fopen failed for output file");
        return false;
    }
    
    g_payload.output_file = file;
    return true;
}