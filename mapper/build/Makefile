# TODO: switch on cmake!

$(PWD) = `pwd`

dryadalis:
	sudo apt update
	gcc -c -Wall -Werror -fPIC ../core_mapper.c ../elf_parsing.c
	gcc -shared -Wl,-soname,libdryadalis.so.1.0 -o libdryadalis.so.1.0.0 *.o
	ldconfig -n .
	ln -s libdryadalis.so.1.0 libdryadalis.so
	export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$(PWD)"

clean:
	rm *.o libdryadalis.so libdryadalis.so.1.0.0 libdryadalis.so.1.0