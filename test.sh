#!/bin/sh

BANK_MSG="./pkts/bank2ser.success.bin"
BANK_KEY="./ssl/key_bank.pem"
BANK_CERT="./ssl/cert_bank.pem"

xterm -T "bank host" -geometry 80x25+100+0 -e "
    cat $BANK_MSG |
    openssl s_server -ign_eof -accept *:2020 -cert $BANK_CERT -key $BANK_KEY -Verify 1;
    echo TEST DONE;
    cat -" &

xterm -T "terminal server" -geometry 80x25+300+200 -e '
    ./a.out;
    echo TEST DONE;
    cat -' &

sleep 1

xterm -T "terminal client" -geometry 80x25+500+400 -e '
    cat ./pkts/session.bin |
    openssl s_client -ign_eof 127.0.0.1:1085;
    echo TEST DONE;
    cat -' &
