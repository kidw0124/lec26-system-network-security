#Makefile
LDLIBS += -lpcap

all: pcap-test

pcap-test: pcap-test.o main.o
	g++ -o pcap-test pcap-test.o main.o -lpcap

main.o: libnet.h pcap-test.h main.cpp

pcap-test.o: libnet.h pcap-test.h pcap-test.cpp

clean:
	rm -f pcap-test *.o
