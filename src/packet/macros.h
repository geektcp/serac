//定义所有跟数据包构造相关的宏

//ARP
#define ETH_HDRLEN 14		// Ethernet header length
#define IP4_HDRLEN 20		// IPv4 header length
#define ARP_HDRLEN 28		// ARP header length
#define ARPOP_REQUEST 1		// Taken from <linux/if_arp.h>
#define ARPOP_REPLY 2

#define DST_MAC         { 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F }

#define INTERFACE       "eth0"

//ARP,IP,UDP,TCP的报文都会用到
#define SRC_PORT        15000		//源端口
#define SRC_IP          "192.168.1.31"	//源IP
#define DST_PORT        53		//目的端口
//#define DST_IP          "198.52.106.25"	//目的IP
//#define DST_IP          "202.96.134.133"	//目的IP
#define DST_IP          "192.168.1.32"	//目的IP


//#define DOMAIN		"www.geektcp.com"	//构造DNS包用到的域名
#define DOMAIN		"baidu.com"	//构造DNS包用到的域名
