FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++
FUNCOBJ= common.o tesi_certs.o key_certify.o

main: ../lib/libtesi.a
../lib/libtesi.a: $(FUNCOBJ) ../include/tesi.h	
	ar cr libtesi.a $(FUNCOBJ) 
	cp libtesi.a ../lib
common.o: common.c common.h
	$(CC) $(CFLAGS) common.c
tesi_certs.o: tesi_certs.c ../include/tesi.h
	$(CC) $(CFLAGS) tesi_certs.c
key_certify.o: key_certify.c ../include/tesi.h ../include/tesi_key.h
	$(CC) $(CFLAGS) key_certify.c
clean:
	rm -f *~ *.o *.a
