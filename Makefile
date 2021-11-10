all: 1m-block

1m-block: main.o
	g++ -o 1m-block main.o -lnetfilter_queue

main.o: libnet.h main.cpp

clean:
	rm -f 1m-block
	rm -f main.o