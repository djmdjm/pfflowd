WARNFLAGS=\
	-Wall -Waggregate-return -Wcast-align -Wcast-qual \
	-Wmissing-declarations -Wmissing-prototypes -Wno-conversion \
	-Wpointer-arith -Wshadow -Wuninitialized -Wcast-align \
	-Wcast-qual -WformatC=2 -Wformat-nonliteral -Werror

LIBS=-lpcap -lutil #-lefence
LDFLAGS=-g

CFLAGS=-g -O $(WARNFLAGS)

# Uncomment this if you are using pfflowd on OpenBSD <=3.4
#CFLAGS+=-DOLD_PFSYNC

TARGETS=pfflowd

all: $(TARGETS)

pfflowd: pfflowd.o
	$(CC) $(LDFLAGS) -o $@ pfflowd.o  $(LIBS)

clean:
	rm -f $(TARGETS) *.o core *.core

strip:
	strip $(TARGETS)

