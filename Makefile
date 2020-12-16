CC=g++
CFLAGS=-O3 -fPIC -Wall.
LIBS=-lclamav

clamavaddon: clamavaddon.o
	g++ -O3 -fPIC -Wall -lclamav -o clamavaddon clamavaddon.o
	

	
	
