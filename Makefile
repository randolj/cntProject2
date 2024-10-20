#################################################################
##
## FILE:	Makefile
## PROJECT:	CNT 4007 Project 1 - Professor Traynor
## DESCRIPTION: Compile Project 1
##
#################################################################

CC=g++

OS := $(shell uname -s)

# Extra LDFLAGS if Solaris
ifeq ($(OS), SunOS)
	LDFLAGS=-lsocket -lnsl
    endif

all: client server 

client: client.cpp
	$(CC) client.cpp -o client_P2 -lcrypto

server: server.cpp
	$(CC) server.cpp -o server_P2 -lcrypto

clean:
	    rm -f client server *.o

