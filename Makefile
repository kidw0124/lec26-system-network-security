#Makefile
all: add-nbo

add-nbo: add-nbo.o main.o
	g++ -o add-nbo add-nbo.o main.o

main.o: add-nbo.h main.cpp

add-nbo.o: add-nbo.h add-nbo.cpp

clean:
	rm -f add-nbo
	rm -f *.o

