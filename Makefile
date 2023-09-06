all: libx.c libx.h
	gcc -c -masm=intel ./libx.c -o ./libx.o -w -fPIC
	gcc -shared -o libx.so libx.o -w -fPIC
clean:
	rm -rf ./libx.o ./libx.so
install: libx.so
	cp ./libx.so /lib/x86_64-linux-gnu/
remove: 
	rm -rf /lib/x86_64-linux-gnu/libx.so