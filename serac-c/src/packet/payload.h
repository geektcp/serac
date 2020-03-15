//定义各协议所有上层应用数据，即payload
#include	"macros.h"


#include 	<stdio.h>
#include	<string.h>
#include	<syslog.h>

int
domain_split(char *domain, char **buf_str, int *buf_size);


int payload_udp(char *payload);

int payload_udp_dns(char *payload);

int payload_tcp(char *payload);
