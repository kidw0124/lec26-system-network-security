LDLIBS=-lpcap

all: tcp-block

tcp-block: main.o ethhdr.o ip.o iphdr.o mac.o tcp.o boyer_moore_search.o
	$(LINK.cc) $^ $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o