all: libx.c libx.h
	gcc -c -masm=intel ./libx.c -o ./libx.o -fPIC -w 
	gcc -shared -o libx.so libx.o -fPIC -w 
	ar rcs libx.a libx.o
test: main.c
	gcc -c ./main.c -o ./main -L . -lx
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
