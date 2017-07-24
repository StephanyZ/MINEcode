cutpcap:cutpcap.o
	gcc -o cutpcap cutpcap.o
cutpcap.o:cutpcap.c GRE.h
	gcc -g -std=c99 -c cutpcap.c
clean:
	rm cutpcap cutpcap.o
