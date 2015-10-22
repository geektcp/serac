all: packets_creator
	

packets_creator:
	gcc -g main.c arp.c udp.c tcp.c checksum.c payload.c icmp.c -o packets_creator


clean:
	rm -rf ./packets_creator


start:
	make clean && make && ./packets_creator
