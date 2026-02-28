#ifndef RC4FUSCATION_H
#define RC4FUSCATION_H

#include <stdbool.h>
#include <stddef.h>

bool generate_rc4_output(const char* output_file, const unsigned char* key, size_t key_len);
bool generate_rc4_text_output(const char* output_file, const unsigned char* key, size_t key_len);
bool generate_rc4_json_output(const char* output_file, const unsigned char* key, size_t key_len);

#endif
