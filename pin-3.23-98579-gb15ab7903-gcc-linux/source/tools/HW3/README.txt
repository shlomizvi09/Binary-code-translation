name: Shlomi Zvenyashvili
ID: 312425192

name: Arik Berenshtein
ID: 314259243

1. All the files we attached in the submission ZIP should be located in /pin-3.23-98579-gb15ab7903-gcc-linux/source/tools/HW3/

2. run in terminal (opened in HW3 folder mentioed in (1.):
	make ex3.test
	../../../pin -t ./obj-intel64/ex2.so -prof -- ./bzip2 -k -f ./input.txt
	../../../pin -t ./obj-intel64/ex2.so -inst -- ./bzip2 -k -f ./input.txt

3. CSV outputs will be created in the same folder the command line was executed from.