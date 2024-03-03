.POSIX:

SHARED_OBJ = netlimit.so
SRC = netlimit.c

all: $(SHARED_OBJ)
clean:
	rm -f $(SHARED_OBJ)

$(SHARED_OBJ): $(SRC)
	$(CC) $(CFLAGS) -fPIC -shared $(SRC) -o $(SHARED_OBJ)
