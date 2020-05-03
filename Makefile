all: simpledns 


simpledns: simpledns.c hex.c hex.h read.h read.c
	gcc -O3 simpledns.c hex.c read.c -lowfat -o simpledns

	
