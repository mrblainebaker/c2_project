#!/bin/bash


gcc -o baker_door backdoor.c -static -I/usr/local/ssl/include -L/usr/local/ssl/lib -lssl -lcrypto -lz -lzstd -ldl -lpthread

gcc -o controller controller.c -static -I/usr/local/ssl/include -L/usr/local/ssl/lib -lssl -lcrypto -lz -lzstd -ldl -lpthread -lresolv
