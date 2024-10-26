all: libx.c libx.h kaslr.c xfuse.c
	gcc -c kaslr.c -o kaslr.o -fPIC -w 
	gcc -c xfuse.c -o xfuse.o -fPIC -lpthread -lfuse -D_FILE_OFFSET_BITS=64 -w 
	gcc -c net.c -o net.o -fPIC -w 
	gcc -c -masm=intel  ./libx.c -o ./libx.o -fPIC -w 
	gcc  -fPIC -shared -o libx.so libx.o kaslr.o net.o xfuse.o -w 
	ar rcs libx.a libx.o kaslr.o xfuse.o net.o
test: main.c
	gcc -masm=intel ./main.c -o ./main --static -L . -lx -w -fPIE && ./main
clean:
	rm -rf ./libx.o ./libx.so ./libx.a
install: libx.so
	cp ./libx.so /lib/x86_64-linux-gnu/
	cp ./libx.a /lib/x86_64-linux-gnu/
	cp ./libx.h /usr/include/
uninstall: 
	rm -rf /lib/x86_64-linux-gnu/libx.so
	rm -rf /lib/x86_64-linux-gnu/libx.a
	rm -rf /usr/include/libx.h
