CC=gcc
CFLAGS=-Wall -Werror -lpcap -pedantic -pipe -std=gnu99

BIN_DIR=./bin/
SRC_DIR=./src/

all:
	$(CC) -o $(BIN_DIR)packet_analyzer.out $(SRC_DIR)main.c $(CFLAGS)
