CC = gcc
CFLAGS_OBJ = -Wall -g -c
CFLAGS_REL = -Wall -g -o
    
all:
	rm -R tmp/
	mkdir tmp/
	${CC} ${CFLAGS_OBJ} src/main.c -o tmp/main.o
	${CC} ${CFLAGS_OBJ} src/protcheck_x86.c -o tmp/protcheck_x86.o
	${CC} ${CFLAGS_OBJ} src/protcheck_x86_64.c -o tmp/protcheck_x86_64.o
	${CC} ${CFLAGS_REL} ./protcheck tmp/protcheck_x86.o tmp/protcheck_x86_64.o tmp/main.o -Wl,-z,relro,-z,now -fstack-protector-all -D_FORTIFY_SOURCE=2
	chmod +x ./protcheck

clean:
	rm -R tmp/

install:
	sudo cp ./protcheck /usr/bin/protcheck
	sudo chmod +x /usr/bin/protcheck
	sudo rm -R /usr/bin/lib/
	sudo cp -r lib/ /usr/bin/lib/
