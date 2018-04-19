all: minidbg

minidbg: minidbg.cpp
	g++ -Wall -Wextra -O2 -g -o minidbg minidbg.cpp

clean:
	rm -f minidbg
