
obj-m     += maze.o
ccflags-y += -DEXPORT_SYMTAB

all: hello
	make -C ../dist/modulebuild M=$(PWD) modules

hello: hello.c
	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

clean:
	rm -f hello
	make -C ../dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../rootfs/modules
	cp hello maze.ko ../rootfs/modules
