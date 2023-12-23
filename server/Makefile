# Makefile for mon_programme_server

CC = gcc
CFLAGS = -Wall -Werror
LDFLAGS = -ldl -lpthread -L. -lserver -lclient
SOURCES = server.c
EXECUTABLE = mon_programme_server

all: $(EXECUTABLE)

$(EXECUTABLE): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean

clean:
	rm -f $(EXECUTABLE)
