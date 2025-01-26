all: libx.c libx.h kaslr.c fuse.c
	gcc -c kaslr.c -o kaslr.o -fPIC -w 
	gcc -c fuse.c -o fuse.o -fPIC -lpthread -lfuse -D_FILE_OFFSET_BITS=64 -w 
	gcc -c net.c -o net.o -fPIC -w 
	gcc -c -masm=intel  ./libx.c -o ./libx.o -fPIC -w 
	gcc  -fPIC -shared -o libx.so libx.o kaslr.o net.o fuse.o -w 
	ar rcs libx.a libx.o kaslr.o fuse.o net.o
test: main.c
	gcc -masm=intel ./main.c -o ./main --static -L . -lx -w -fPIE && ./main
clean:
	rm -rf ./libx.o ./libx.so ./libx.a ./net.o ./kaslr.o ./fuse.o
install: libx.so
	cp ./libx.so /lib/x86_64-linux-gnu/
	cp ./libx.a /lib/x86_64-linux-gnu/
	cp ./libx.h /usr/include/
uninstall: 
	rm -rf /lib/x86_64-linux-gnu/libx.so
	rm -rf /lib/x86_64-linux-gnu/libx.a
	rm -rf /usr/include/libx.h
