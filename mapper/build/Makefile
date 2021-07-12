$(PWD) = `pwd`

all:
	gcc -L$(PWD)/build ../main.c -o main -ldryadalis

dryadalis:
	sudo apt update
	gcc -c -Wall -Werror -fPIC $(PWD)/core_mapper.c $(PWD)/elf_parsing.c
	gcc -shared -Wl,-soname,libdryadalis.so.1.0 -o libdryadalis.so.1.0.0 *.o
	ldconfig -n $(PWD)/build
	ln -s libdryadalis.so.1.0 libdryadalis.so
	export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$(PWD)/build"

clean:
	rm *.o libdryadalis.so libdryadalis.so.1.0.0 main