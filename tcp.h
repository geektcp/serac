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
#include        <netinet/tcp.h>

int sock_init_tcp(struct sockaddr_in *src_addr, struct sockaddr_in *dst_addr);

int
creator_tcphdr_ip(struct ip *header_ip, struct sockaddr_in *src_addr,
		  struct sockaddr_in *dst_addr, int len_total);

int creator_header_tcp(struct tcphdr *header_tcp);

int
send_tcp(int sockfd, struct sockaddr_in *dst_addr, char *buf, int len_payload);
