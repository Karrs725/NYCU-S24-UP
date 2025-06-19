CFLAGS = -Wall -Wextra
all: logger logger.so

logger: logger.c
	gcc $(CFLAGS) -o logger logger.c
logger.so: liblogger.c
	gcc $(CFLAGS) -shared -o logger.so -fPIC liblogger.c
clean:
	rm -f logger logger.so