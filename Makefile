.POSIX:

EXE = netlimit
SRC = netlimit.c

LDFLAGS = -lseccomp

all: $(EXE)
clean:
	rm -f $(EXE)

$(SHARED_OBJ): $(SRC)
