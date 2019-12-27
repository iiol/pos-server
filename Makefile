CC = gcc

LIBS = mysqlclient libssl libcrypto libcurl json-c
CFLAGS = -Wall -std=gnu99 -Iinclude -ggdb `pkg-config --cflags $(LIBS)` -O2
LFLAGS = `pkg-config --libs $(LIBS)`

TARGET = a.out
SRC = $(wildcard src/*.c)
OBJ = $(subst src, build, $(SRC:.c=.o))

.PHONY: clean test

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(LFLAGS) -o $@ $^

build/%.o: src/%.c
	mkdir -p build
	$(CC) $(CFLAGS) $(LFLAGS) -c -o $@ $<

test: $(TARGET)
	./test.sh

clean:
	rm -fr $(TARGET) build
