#include        "macros.h"

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

#include        <sys/ioctl.h>	//获取mac地址SIOCGIFHWADDR
#include        <netdb.h>	//AI_CANONNAME和addrinfo
#include        <net/if.h>	//ifreq
#include        <net/if_arp.h>	//struct arphdr
#include        <linux/if_packet.h>	//stuct sockaddr_ll
#include        <netinet/if_ether.h>	//ether_arp报头和ETH_P_ALL

int mac_local(uint8_t * src_mac);
int get_ifindex(struct sockaddr_ll *point_dev);
int arphdr_build(uint8_t * src_mac, uint8_t * dst_mac, char *src_ip,
		 char *dst_ip, uint8_t * ether_frame);
int send_packet(struct sockaddr_ll *point_dev, uint8_t * ether_frame,
		int frame_length);
