CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -std=c11
LDFLAGS := -pthread

SRC_DIR := Entropic_Devourer
TARGET := $(SRC_DIR)/entropic_devourer

SOURCES := \
	$(SRC_DIR)/main.c \
	$(SRC_DIR)/Common.c \
	$(SRC_DIR)/ipv4fuscation.c \
	$(SRC_DIR)/ipv6fuscation.c \
	$(SRC_DIR)/MacFuscation.c

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
	rm -f ipv4_shellcode.c ipv6_shellcode.c mac_shellcode.c shellcode
	rm -f ipv4_shellcode.txt ipv6_shellcode.txt mac_shellcode.txt
