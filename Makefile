VERSION = 1
HANDINDIR = /labs/proxylab/handin/$(shell whoami)

CC = gcc
CFLAGS = -Wall -g 
LDFLAGS = -pthread

OBJS = proxy.o csapp.o

all: proxy

proxy: $(OBJS)

csapp.o: csapp.c
	$(CC) $(CFLAGS) -c csapp.c

proxy.o: proxy.c
	$(CC) $(CFLAGS) -c proxy.c

handin:
	cp proxy.c $(HANDINDIR)/$(shell whoami)-$(VERSION)-proxy.c
	chmod 600 $(HANDINDIR)/$(shell whoami)-$(VERSION)-proxy.c


clean:
	rm -f *~ *.o proxy core

