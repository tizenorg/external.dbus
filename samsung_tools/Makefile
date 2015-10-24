#CROSS_COMPILE = arm-linux-gnueabi-
CC            = $(CROSS_COMPILE)gcc

SERVER_DBUS_SOURCES=server.c

CLIENT_DBUS_SOURCES=client.c

SERVERCLIENT_BROADCAST_SOURCES=serverClient-broadcast.c

SERVERCLIENT_BROADCAST_REMOVE_MATCH_SOURCES=serverClient-broadcast-remove-match.c

#SQLITE_CFLAGS=`pkg-config --cflags sqlite3`
#SQLITE_LIBS=`pkg-config --libs sqlite3`

ifndef CROSS_COMPILE
DBUS_CFLAGS=-I../
DBUS_LIBS=-L../dbus/.libs/ -ldbus-1
else
DBUS_CFLAGS=-I/home/`whoami`/GBS-ROOT/local/BUILD-ROOTS/scratch.armv7l.0/.build.packages/BUILD/com.samsung.dbus-1.7.5
DBUS_LIBS=-L/home/`whoami`/GBS-ROOT/local/BUILD-ROOTS/scratch.armv7l.0/.build.packages/BUILD/com.samsung.dbus-1.7.5/dbus/.libs -ldbus-1
endif

INCLUDES=-Wall -g -O0

SUBDIRS = test_foxp_latency

.PHONY: test_foxp_latency all

all: ping-server ping-client test_foxp_latency serverClient-broadcast serverClient-broadcast-remove-match serverClient

test_foxp_latency:
	$(MAKE) -C $@

ping-server:
	$(CC) -o $@ $(SERVER_DBUS_SOURCES) $(INCLUDES) $(DBUS_CFLAGS) $(CFLAGS) $(DBUS_LIBS) $(SQLITE_CFLAGS) $(SQLITE_LIBS)

ping-client: 
	$(CC) -o $@ $(CLIENT_DBUS_SOURCES) $(INCLUDES) $(DBUS_CFLAGS) $(CFLAGS) $(DBUS_LIBS) $(SQLITE_CFLAGS) $(SQLITE_LIBS) 

serverClient-broadcast:
	$(CC) -o $@ $(SERVERCLIENT_BROADCAST_SOURCES) $(INCLUDES) $(DBUS_CFLAGS) $(CFLAGS) $(DBUS_LIBS) $(SQLITE_CFLAGS) $(SQLITE_LIBS)

serverClient-broadcast-remove-match:
	$(CC) -o $@ $(SERVERCLIENT_BROADCAST_REMOVE_MATCH_SOURCES) $(INCLUDES) $(DBUS_CFLAGS) $(CFLAGS) $(DBUS_LIBS) $(SQLITE_CFLAGS) $(SQLITE_LIBS)

serverClient:
	$(CC) -o $@ $@.c $(INCLUDES) $(DBUS_CFLAGS) $(CFLAGS) $(DBUS_LIBS)

install:

install-samsung-tools:
	mkdir -p $(DESTDIR)
	install -m0755 serverClient $(DESTDIR)
	install -m0755 serverClient-broadcast $(DESTDIR)
	install -m0755 serverClient-broadcast-remove-match $(DESTDIR)
	install -m0755 ping-* $(DESTDIR)
	install -m0755 test-broadcast* $(DESTDIR)
	install -m0755 run_with_env $(DESTDIR)

clean:
	rm -f *.o ping-server ping-client serverClient-broadcast serverClient-broadcast-remove-match serverClient
