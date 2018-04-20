CFLAGS := -Wall -Wextra -O2 -g

all: minidbg_test

minidbg.o: minidbg.cpp
	g++ $(CFLAGS) -c minidbg.cpp

minidbg_test.o: minidbg_test.c
	gcc $(CFLAGS) -c minidbg_test.c

minidbg_test: minidbg.o minidbg_test.o
	g++ -o minidbg_test minidbg.o minidbg_test.o

clean:
	rm -f *.o minidbg_test.o
