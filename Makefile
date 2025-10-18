all:
	gcc -march=native -fPIE -pie src/*.c -g  -lcapstone -lkeystone -lm -lstdc++ -o main
