all: netfilter-test

netfilter-test: main.o
	g++ -o netfilter-test main.o -lnetfilter_queue

main.o: libnet.h main.cpp

clean:
	rm -f netfilter-test
	rm -f main.o