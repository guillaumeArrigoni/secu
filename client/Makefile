# Makefile for mon_programme_client

CC = gcc
CFLAGS = -Wall -Werror
LDFLAGS = -ldl -lpthread -L. -lclient -lserver -lssl -lcrypto
SOURCES = client.c
EXECUTABLE = mon_programme_client

all: $(EXECUTABLE)

$(EXECUTABLE): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean

clean:
	rm -f $(EXECUTABLE)
