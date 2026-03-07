#ifndef AESFUSCATION_H
#define AESFUSCATION_H

#include <stdbool.h>
#include <stddef.h>

bool generate_aes256_output(const char* output_file, const unsigned char* key, size_t key_len);
bool generate_aes256_text_output(const char* output_file, const unsigned char* key, size_t key_len);
bool generate_aes256_json_output(const char* output_file, const unsigned char* key, size_t key_len);

#endif
