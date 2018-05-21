# # # # # # #
# Name: Qianqian Zheng
#Student #: 813288
#gitlab login id: q.zheng11@student.unimelb.edu.au

CC     = gcc
CFLAGS = -Wall -lssl -lcrypto
# exe name and a list of object files that make up the program
EXE    = certcheck
OBJ    = certcheck.o list.o

# add any new object files here ^

# top (default) target
all: $(EXE)

# how to link executable
$(EXE): $(OBJ)
	$(CC) -o $(EXE) $(OBJ) $(CFLAGS)

certcheck.o: list.h
list.o: list.h


# this can be accessed by specifying this target directly: 'make clean'
clean:
	rm -f $(OBJ) $(EXE)
