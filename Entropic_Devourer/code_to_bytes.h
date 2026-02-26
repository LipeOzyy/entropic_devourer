#ifndef CODE_TO_BYTES_H
#define CODE_TO_BYTES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

bool convert_code_to_bytes(const char* input_file, const char* output_file);
void print_bytes_array(FILE* output, const unsigned char* buffer, size_t size);
bool read_file_to_buffer(const char* filename, unsigned char** buffer, size_t* size);

#endif
