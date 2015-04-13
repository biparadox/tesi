FLAGS= -g -o 
CFLAGS= -g -c -DUSER_MODE 
CC=gcc
CCP=g++

main: TESI_test  TESI_init TESI_clear TESI_AIK_CASign TESI_AIK_GenerateReq TESI_AIK_Activate Tspi_Data_Unbind05
TESI_test: TESI_test.c 
	$(CC) $(FLAGS) TESI_test TESI_test.c -L/usr/local/lib -L../lib -ltesi -ltspi -lcrypto -lstruct -lcrypto_func
TESI_init: TESI_init.c 
	$(CC) $(FLAGS) TESI_init TESI_init.c -L/usr/local/lib -L../lib -ltesi -ltspi -lcrypto -lstruct -lcrypto_func
TESI_clear: TESI_clear.c 
	$(CC) $(FLAGS) TESI_clear TESI_clear.c -L/usr/local/lib -L../lib -ltesi -ltspi -lcrypto -lstruct -lcrypto_func
TESI_AIK_GenerateReq: TESI_AIK_GenerateReq.c 
	$(CC) $(FLAGS) TESI_AIK_GenerateReq TESI_AIK_GenerateReq.c -L/usr/local/lib -L../lib -ltesi -ltspi -lcrypto -lstruct -lcrypto_func -lsysfunc
TESI_AIK_CASign: TESI_AIK_CASign.c 
	$(CC) $(FLAGS) TESI_AIK_CASign TESI_AIK_CASign.c -L/usr/local/lib -L../lib -ltesi -ltspi -lcrypto -lstruct -lcrypto_func
TESI_AIK_Activate: TESI_AIK_Activate.c 
	$(CC) $(FLAGS) TESI_AIK_Activate TESI_AIK_Activate.c -L/usr/local/lib -L../lib -ltesi -ltspi -lcrypto -lstruct -lcrypto_func
Tspi_Data_Unbind05: Tspi_Data_Unbind05.c 
	$(CC) $(FLAGS) Tspi_Data_Unbind05 Tspi_Data_Unbind05.c ../tesi/common.o -L/usr/local/lib -L../lib -ltspi -lcrypto -lcrypto_func
clean:
	rm -f TESI_test TESI_init TESI_clear TESI_AIK_Activate TESI_AIK_CASign TESI_AIK_GenerateReq *~ *.o *.a
