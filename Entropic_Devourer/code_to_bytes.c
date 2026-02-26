#include "code_to_bytes.h"

#include <stdint.h>
#include <stdlib.h>

bool read_file_to_buffer(const char* filename, unsigned char** buffer, size_t* size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("[!] Failed to open file");
        return false;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        perror("[!] Failed to seek file");
        fclose(file);
        return false;
    }

    long file_size = ftell(file);
    if (file_size < 0) {
        perror("[!] Failed to get file size");
        fclose(file);
        return false;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        perror("[!] Failed to seek file");
        fclose(file);
        return false;
    }

    *buffer = NULL;
    *size = 0;

    if (file_size == 0) {
        fclose(file);
        return true;
    }

    *buffer = (unsigned char*)malloc((size_t)file_size);
    if (!*buffer) {
        perror("[!] Memory allocation failed");
        fclose(file);
        return false;
    }

    size_t bytes_read = fread(*buffer, 1, (size_t)file_size, file);
    fclose(file);

    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "[!] Failed to read entire file\n");
        free(*buffer);
        *buffer = NULL;
        return false;
    }

    *size = bytes_read;
    return true;
}

void print_bytes_array(FILE* output, const unsigned char* buffer, size_t size) {
    fprintf(output, "unsigned char buf[] = {\n");
    if (size > 0) {
        fprintf(output, "    ");
    }

    for (size_t i = 0; i < size; i++) {
        fprintf(output, "0x%02X", buffer[i]);
        if (i < size - 1) {
            fprintf(output, ", ");
        }
        if ((i + 1) % 8 == 0 && i < size - 1) {
            fprintf(output, "\n    ");
        }
    }

    fprintf(output, "\n};\n");
}

bool convert_code_to_bytes(const char* input_file, const char* output_file) {
    unsigned char* buffer = NULL;
    size_t size = 0;
    FILE* output = NULL;
    bool success = false;

    printf("[*] Converting %s to byte array...\n", input_file);

    if (!read_file_to_buffer(input_file, &buffer, &size)) {
        goto cleanup;
    }

    printf("[+] Successfully read %zu bytes from %s\n", size, input_file);

    if (output_file == NULL) {
        print_bytes_array(stdout, buffer, size);
        success = true;
        goto cleanup;
    }

    output = fopen(output_file, "w");
    if (!output) {
        perror("[!] Failed to create output file");
        goto cleanup;
    }

    print_bytes_array(output, buffer, size);
    printf("[+] Byte array written to %s\n", output_file);
    success = true;

cleanup:
    if (buffer) {
        free(buffer);
    }
    if (output) {
        fclose(output);
    }
    return success;
}
