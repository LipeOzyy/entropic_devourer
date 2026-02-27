#ifndef XORFUSCATION_H
#define XORFUSCATION_H

#include <stdbool.h>
#include <stddef.h>

bool generate_xor_output(const char* output_file, const unsigned char* key, size_t key_len);
bool generate_xor_text_output(const char* output_file, const unsigned char* key, size_t key_len);
bool generate_xor_json_output(const char* output_file, const unsigned char* key, size_t key_len);

#endif
