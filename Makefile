CC = gcc

LIBS = mysqlclient libssl libcrypto
CFLAGS = -Wall -Iinclude -ggdb `pkg-config --cflags $(LIBS)`
LFLAGS = `pkg-config --libs $(LIBS)`

TARGET = a.out
SRC = $(wildcard src/*.c)
OBJ = $(subst src, build, $(SRC:.c=.o))

.PHONY: clean

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(LFLAGS) -o $@ $^

build/%.o: src/%.c
	mkdir -p build
	$(CC) $(CFLAGS) $(LFLAGS) -c -o $@ $<

clean:
	rm -fr $(TARGET) build
