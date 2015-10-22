#include	"icmp.h"


int creator_icmp(void)
{
	int sockfd, len_payload, len_total;
	struct sockaddr_in *src_addr, *dst_addr;

	char *buf, *payload;
	struct ip *header_ip;
	struct icmphdr *header_icmp;

	buf = malloc(100);
	payload = malloc(50);
	src_addr = malloc(sizeof(struct sockaddr_in));
	dst_addr = malloc(sizeof(struct sockaddr_in));

	header_ip = (struct ip *)buf;
	header_icmp = (struct icmphdr *)(buf + sizeof(struct ip));
	payload = buf + sizeof(struct ip) + sizeof(struct icmphdr);

	memset(buf, '\0', sizeof(buf));

	memset(src_addr, '\0', sizeof(struct sockaddr_in));
	memset(dst_addr, '\0', sizeof(struct sockaddr_in));

	len_payload = payload_icmp(payload);

	len_total = sizeof(struct ip) + sizeof(struct icmphdr) + len_payload;
	
	printf("2222222222222 len_total is %d======\n", len_total);

	//构建原始套接字
	sockfd = sock_init_icmp(src_addr, dst_addr);

	//初始化ip报头
	creator_icmphdr_ip(header_ip, src_addr, dst_addr, len_total);

	//初始化icmp报头，并填充数据
	creator_header_icmp(header_icmp);

	//ip校验和是否填充无所谓，网卡会自动计算出来
	header_ip->ip_sum = creator_check_sum(buf, IPPROTO_IP);

	//icmp校验和
	header_icmp->checksum = creator_check_sum(buf, IPPROTO_ICMP);

	//发送icmp数据包
	send_icmp(sockfd, dst_addr, buf, len_payload);

	return 0;
}

int sock_init_icmp(struct sockaddr_in *src_addr, struct sockaddr_in *dst_addr)
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
creator_icmphdr_ip(struct ip *header_ip, struct sockaddr_in *src_addr,
		  struct sockaddr_in *dst_addr, int len_total)
{
	/*开始填充IP数据报的头部 */
	header_ip->ip_v   = IPVERSION;	                //IPV4
	header_ip->ip_hl  = sizeof(struct ip) >> 2;     //IP数据报的头部长度
	header_ip->ip_tos = 0;	                        //服务类型
	header_ip->ip_len = htons(len_total);	        //IP数据报及其载荷长度，整形且不要转字节序
	header_ip->ip_id  = 0;	                        //IP id 由内核填写
	header_ip->ip_off = 0;	                        //有内核填写
	header_ip->ip_ttl = 30;	                        //MAXTTL;
	header_ip->ip_p   = IPPROTO_ICMP;               //指定上层协议为ICMP
	header_ip->ip_sum = 0;	                        //0表示禁用校验和，由网卡来校验
	header_ip->ip_src = src_addr->sin_addr;         //源地址，即攻击来源
	header_ip->ip_dst = dst_addr->sin_addr;	        //目的地址，即攻击目标

	printf("dst address is %s\n", inet_ntoa(dst_addr->sin_addr));
	printf("src address is %s\n", inet_ntoa(src_addr->sin_addr));

	return 0;
}

int creator_header_icmp(struct icmphdr *header_icmp)
{
	//这里的type是icmp协议类型共有18种，0表示响应包，8表示请求包
	//code是代码，统一类型可能有若干种类，细分就用code，比如3和3组合是端口不达
	//由于只占1个字节，没有高低之分，直接填整数即可
	header_icmp->type               = 8;
	header_icmp->code               = 0;
	header_icmp->checksum           = htons(0);

	header_icmp->un.echo.id         = htons(11);
	header_icmp->un.echo.sequence   = htons(230);
	
	return 0;
}


int
send_icmp(int sockfd, struct sockaddr_in *dst_addr, char *buf, int len_payload)
{
	int ret;
	while (1) {
		//开始发送icmp协议包
		ret = sendto(sockfd, buf, 20 + 8 + len_payload, 0,
			     (struct sockaddr *)dst_addr,
			     sizeof(struct sockaddr));
		printf("the ret is %d===\n", ret);

		sleep(1);
	}

	return 0;
}
