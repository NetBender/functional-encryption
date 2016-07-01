CC = gcc -std=gnu99
LD = gcc
DEPS_GEN = gcc -M
DEPS_FILE = Makefile.deps
LIBS = gmp
CFLAGS = -Wall -g -I/usr/local/include/
LDFLAGS = $(addprefix -l,$(LIBS))
RM = rm -f

SRCS = misc.c functional-enc.c
OBJS = $(patsubst %.c, %.o, $(SRCS))
PROGS = test-functional-enc

all: $(PROGS)

test-functional-enc: $(OBJS) test-functional-enc.o
	$(LD) $(OBJS) $@.o -o $@ $(LDFLAGS)

%.o: %.c Makefile
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(PROGS) $(OBJS) *.o $(DEPS_FILE)

depend:
	$(DEPS_GEN) $(CFLAGS) $(SRCS) > $(DEPS_FILE)

$(DEPS_FILE): *.[Cch]
	for i in *.[Cc]; do gcc -MM "$${i}"; done > $@

include $(DEPS_FILE)
