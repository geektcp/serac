#include        "macros.h"
#include	"checksum.h"
#include	"payload.h"

#include        <syslog.h>
#include        <stdio.h>
#include        <unistd.h>
#include        <string.h>
#include        <stdlib.h>
#include        <arpa/inet.h>
#include        <sys/socket.h>
#include        <sys/types.h>
#include        <netinet/in.h>
#include        <netinet/ip.h>
#include        <netinet/udp.h>

int sock_init_udp(struct sockaddr_in *src_addr, struct sockaddr_in *dst_addr);

int
creator_udphdr_ip(struct ip *header_ip, struct sockaddr_in *src_addr,
		  struct sockaddr_in *dst_addr, int len_total);

int creator_header_udp(struct udphdr *header_udp, int len_total);

int
send_udp(int sockfd, struct sockaddr_in *dst_addr, char *buf, int len_total);
