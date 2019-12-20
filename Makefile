CC = gcc

LIBS = mysqlclient libssl libcrypto
CFLAGS = -Wall -Iinclude -ggdb `pkg-config --cflags $(LIBS)`
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

test:
	xterm -T "bank host" -e 'openssl s_server -tlsextdebug -accept *:2020 -cert ssl/cert_bank.pem -key ssl/key_bank.pem -Verify 1; cat -' &
	xterm -T "terminal server" -e './a.out; cat -' &
	sleep 1
	xterm -T "terminal client" -e 'cat ./pkts/session.bin | openssl s_client -tlsextdebug 127.0.0.1:1085; cat -' &

clean:
	rm -fr $(TARGET) build
