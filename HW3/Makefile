CFLAGS = -Wall -Wextra

all: sdb

%.o: %.cpp
	g++ $(CFLAGS) -c $<

sdb: sdb.o dbg.o
	g++ $(CFLAGS) -o sdb $^ -lcapstone

clean:
	rm -f *.o sdb