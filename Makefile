all: packets_creator
	

packets_creator:
	gcc -g src/packet/*.c -o ./release/packets_creator


clean:
	rm -rf ./release/packets_creator


start:
	make clean && make && ./release/packets_creator
