CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -std=c11
LDFLAGS := -pthread -lssl -lcrypto

SRC_DIR := Entropic_Devourer
TARGET := $(SRC_DIR)/entropic_devourer

SOURCES := \
	$(SRC_DIR)/main.c \
	$(SRC_DIR)/Common.c \
	$(SRC_DIR)/ipv4fuscation.c \
	$(SRC_DIR)/ipv6fuscation.c \
	$(SRC_DIR)/MacFuscation.c \
	$(SRC_DIR)/xorfuscation.c \
	$(SRC_DIR)/rc4fuscation.c \
	$(SRC_DIR)/aesfuscation.c \
	$(SRC_DIR)/code_to_bytes.c

.PHONY: all clean run test-bytes

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

test-bytes: $(TARGET)
	@echo "\n[*] Testing byte array conversion..."
	@echo "Hello World" > test.txt
	./$(TARGET) test.txt bytes
	@cat test.txt_bytes.txt
	@rm -f test.txt test.txt_bytes.txt

clean:
	rm -f $(TARGET)
	rm -f ipv4_shellcode.c ipv6_shellcode.c mac_shellcode.c xor_shellcode.c rc4_shellcode.c aes256_shellcode.c shellcode
	rm -f ipv4_shellcode.txt ipv6_shellcode.txt mac_shellcode.txt xor_shellcode.txt rc4_shellcode.txt aes256_shellcode.txt
	rm -f ipv4_shellcode.json ipv6_shellcode.json mac_shellcode.json xor_shellcode.json rc4_shellcode.json aes256_shellcode.json
	rm -f *.txt_bytes.txt
