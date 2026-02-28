#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    size_t bytes_number;      
    unsigned char* p_shell;    
    unsigned char* p_new_shell; 
    size_t final_size;         
    FILE* output_file;         
} PayloadData;

extern PayloadData g_payload;

bool read_bin_file(const char* file_input);
int round_up(int num_to_round, int multiple);
void append_shellcode(int n);

/* apply XOR obfuscation to payload (key repeats if shorter than payload) */
void apply_xor(const unsigned char* key, size_t key_len);

/* apply RC4 stream cipher to payload using given key */
void apply_rc4(const unsigned char* key, size_t key_len);

bool write_shellcode_file(const char* file_name);

#endif 