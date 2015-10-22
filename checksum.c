#include	"checksum.h"

unsigned short creator_check_sum(char *buf, int protocol)
{
	//这个函数是个可重用的函数，方便计算ip，udp，tcp的校验和
	//udp和tcp的校验和计算完全一致。
	//需要注意的是伪报头是不存在的，只是用于计算校验和而已。

	//计算校验和，必须确保所有字段的数据类型正确
	//ip_v,ip_hl,ip_ttl必须是整形
	//ip_tos，只能是特定的二进制或16进制
	//ip_id用什么类型无所谓
	//除了上面5个字段，其他所有字段必须是网络字节序数字

	unsigned short ret, len, tmp_ttl, tmp_ip_sum;
	unsigned long sum = 0;

	//根据ip字段的第3,4字节的值得到数据包总长度，
	//然后对于奇数需要扩展1个字节
	len = ntohs(*(unsigned short *)(buf + 2));
	len = ((len + 1) / 2) * 2;

	printf("##############the len is %d====\n", len);

	//这里如果不引入中间变量check_buf，而直接调用buf并做强制类型转换
	//会得到不一样的结果，如果仅仅只对buf强制类型转换，
	//那么buf++还是以char为单位划分内存，会导致累加出问题
	//要么就在传入参数时就先进行强制类型转换，效果是一样的
	unsigned short *check_buf;

	switch (protocol) {
		//按协议号来区分不同的校验和
		//IPPROTO_IP   = 0
		//IPPROTO_ICMP = 1
		//IPPROTO_TCP  = 6
		//IPPROTO_UDP  = 17
		//IPPROTO_RAW  = 255

	case IPPROTO_IP:
		//ip校验和参与计算的长度固定是20
		len = 20;
		check_buf = (unsigned short *)buf;
		break;

	case IPPROTO_ICMP:
		//icmp协议参与校验和计算的是:ip报头+icmp报头+icmp数据
		//也就是全部都参加，len是ip的第二字节对应的值也就是总长度，
		//所以这里不需要做任何改变
		check_buf = (unsigned short *)buf;
		break;


	case IPPROTO_TCP:
		//tcp和udp的校验和计算，涉及到12字节的伪报头，
		//参与计算的长度，刚好是总长度减去8字节
		len -= 8;
		//tmp_ttl只占一个字节而且是整形，必须先提取出来
		tmp_ttl = *(buf + 8);
		check_buf = (unsigned short *)(buf + 8);
		tmp_ip_sum = *(check_buf + 2);
		*check_buf = htons(0x0006);

		//之所以用下面种方式，是因为udp报头有长度字段，
		//而tcp报头没有长度字段，统一从ip报头中取出来
		*(check_buf + 1) = *(unsigned short *)(buf + 2) - htons(20);
		break;

	case IPPROTO_UDP:
		len -= 8;
		//tmp_ttl只占一个字节而且是整形，必须先提取出来
		tmp_ttl = *(buf + 8);
		check_buf = (unsigned short *)(buf + 8);
		tmp_ip_sum = *(check_buf + 2);
		*check_buf = htons(0x0011);
		*(check_buf + 1) = *(unsigned short *)(buf + 2) - htons(20);
		break;

	default:
		break;
	}

	//开始循环累加，通过与运算0x80000000，判读sum的第8位是否是1
	//如果是就进行一次移位累加运算,这个是校验和的计算规则
	while (len > 1) {
		sum += *check_buf++;
		if (sum & 0x80000000) {
			sum = (sum & 0xFFFF) + (sum >> 16);
		}
		len -= 2;
	}

	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	ret = (unsigned short)~sum;

	switch (protocol) {
		//还原之前为了计算校验和填充的字节，主要针对tcp，udp的伪报头
	case IPPROTO_IP:
		printf(">>> ip  >>>chesum result is 0x%04x*****\n\n",
		       ntohs(ret));
		break;

	case IPPROTO_ICMP:
		printf(">>> icmp >>>chesum result is 0x%04x*****\n\n",
                       ntohs(ret));
		break;

	case IPPROTO_TCP:
		printf(">>> tcp >>>chesum result is 0x%04x*******\n",
		       ntohs(ret));
		*(buf + 8) = tmp_ttl;
		*(check_buf + 2) = tmp_ip_sum;
		break;

	case IPPROTO_UDP:
		printf(">>> udp >>>chesum result is 0x%04x******\n\n",
		       ntohs(ret));
		*(buf + 8) = tmp_ttl;
		*(check_buf + 1) = tmp_ip_sum;
		break;

	default:
		break;
	}

	//注意ret的计算过程中所有值都是网络字节序，得出的结果当然也是网络字节序，
	//所以这里不需要再转成网络字节序,赋值给对应的校验和字段是不需要htons转换了
	return ret;
}
