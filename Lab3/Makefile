CFLAGS = -Wall -Wextra -fpic
all: libmaze.so maze libsolver.so libsolverlocal.so

libmaze.so: libmaze_dummy.c
	gcc $(CFLAGS) -shared -o $@ $<
maze: maze.c libmaze.so
	gcc $(CFLAGS) -o $@ $^ -L. -lmaze
libsolver.so: libsolver.c
	gcc $(CFLAGS) -shared -o $@ $<
libsolverlocal.so: libsolverlocal.c
	gcc $(CFLAGS) -shared -o $@ $<
clean:
	rm -f libmaze.so maze libsolver.so libsolverlocal.so