LDLIBS=-lpcap

all: deauth-attack

deauth-attack: main.o mac.o
	$(LINK.cc) $^ $(LDLIBS) -o $@

clean:
	rm -f deauth-attack *.o