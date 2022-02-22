CC=gcc
CFLAGS=-O3
LDFLAGS=-lpthread 

must: must.c
	$(CC) $(CFLAGS) must.c -o must $(LDFLAGS)
