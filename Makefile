# # # # # # #
# Name: Qianqian Zheng
#Student #: 813288
#gitlab login id: q.zheng11@student.unimelb.edu.au

CC     = gcc
CFLAGS = -Wall -lssl -lcrypto
# exe name and a list of object files that make up the program
EXE    = certcheck
OBJ    = certcheck.o



$(EXE): $(OBJ) # <-- the target is followed by a list of prerequisites
	$(CC) $(CFLAGS) -o $(EXE) $(OBJ)

server.o: certcheck.c certcheck.h
	$(CC) $(CFLAGS) -c certcheck.c

# this can be accessed by specifying this target directly: 'make clean'
clean:
	rm -f $(OBJ) $(EXE)
