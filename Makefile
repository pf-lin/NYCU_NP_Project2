all:
	g++ -o np_simple np_simple.cpp
	g++ -o np_single_proc np_single_proc.cpp
	g++ -o np_multi_proc np_multi_proc.cpp
	mkdir -p bin
	cp /bin/ls /bin/cat bin/
	make -C commands

clean:
	rm -rf np_simple np_single_proc np_multi_proc
	rm -rf bin