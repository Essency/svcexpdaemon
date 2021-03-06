RM=/bin/rm

CC= gcc
# Compile flags
CFLAGS= -pipe -Wall -O3 -g -m32
# linker flags.
LDFLAGS=-lcrypt


SRCS = datafiles.c crypt_shs1.c main.c export.c
OBJS = datafiles.o crypt_shs1.o main.o export.o


all: svcexpd

svcexpd: $(OBJS)
	$(CC) -m32 $(LIBS) $(OBJS) $(LDFLAGS) -o $@

.c.o:
	$(CC) $(CFLAGS) -c $<
datafiles.o:	datafiles.c
crypt_shs1.o:	crypt_shs1.c
export.o:	export.c	datafiles.c crypt_shs1.c
main.o:		main.c		export.c

clean:
	@${RM} -f svcexpd
	@${RM} -f *.o
