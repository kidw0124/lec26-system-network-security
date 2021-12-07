LDLIBS=-lpcap

all: airodump

airodump: main.o mac.o
	$(LINK.cc) $^ $(LDLIBS) -o $@

clean:
	rm -f airodump *.o