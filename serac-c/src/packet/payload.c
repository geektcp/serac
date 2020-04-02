#include		"payload.h"

struct dnshdr 
{
	//这是个自定义的结构体，系统没有现成的
	//这个结构体是每个DNS包必须要有的
	//DNS通过这个结构体的id来维持回话
	//支持查询多个域名或者多个响应
	unsigned short id;
	unsigned short flags;
	unsigned short num_questions;
	unsigned short num_answers;
	unsigned short num_authority;
	unsigned short num_additional;
};	

//在dnshdr和dns_question_section还有一段可变长数据，即域名
//但这里的域名填写方式不是简单的字符串，而是带有每段长度
//具体参考响应文档

struct dns_question_section
{	
	//dns查询结构体，只有两个类型
	//type是定义记录类型，比如A记录，别名记录等
	unsigned short type;
	unsigned short class;
};


struct dns_answer_section
{	
	//dns响应结构体
	unsigned short name;
	unsigned short type;
	unsigned short class;
	unsigned short ttl_top;
	unsigned short ttl;
	unsigned short data_len;
};



int
domain_split(char *domain, char **buf_str, int *buf_size)
{
	//这个函数用来传入域名，传出域名的每个段，及每段的长度
        char *running = domain;

        char *str_tok = NULL;
        char *delim = ".";
        int num = 0;


        while( (str_tok = strsep(&running, delim)) != NULL )
        {
                *(buf_str+num)  = str_tok;
                *(buf_size+num) = strlen(str_tok);
                num++;
        }

        return num;
}


int payload_udp(char *payload)
{
	//这里构造一个最简单但是没用的DNS包，可以正常发出，但提示malformed packet
	//必须先定义udp的负载，因为要确定长度。
	//这里既可以用指针，也可以用数组，还可以用malloc分配
	//char payload[100];    char * payload = malloc(100);
	int len_payload;
	char *data_dns = "123456abcd";

	len_payload = strlen(data_dns);
	printf("len payload is %d===\n", len_payload);

	//指针和指针之间的赋值时,有两种技巧都可以；
	//第一种用strcat，这种方式是只能用于字符类型指针；
	//strcat((buf + sizeof(struct ip) + sizeof(struct udphdr)), data);

	//第二种直接赋值，这种方式可以用于任何类型指针；
	//如果被赋值的指针带有+号不能出现在等号左边，可以引入临时变量data来解决

	//填写udp载荷数据，这里使用指针间的直接赋值这个技巧。      
	memcpy(payload, data_dns, len_payload);

	return len_payload;
}


int payload_udp_dns(char *payload)
{
	//操作系统没有自带的DNS结果体，上面是根据理解自定义的
	//构造一个dns查询包，向dns服务器发起查询，可以得到A记录的IP地址
	//不需要发起一个ip反查的数据包，但是对于对于某些域名如果要求IP反查则不行
	int len_payload, len_domain;
	struct dnshdr *payload_dns;


	char *domain1, *domain2, *domain3;
	int len1, len2, len3;
	struct dns_question_section *payload_dns_question;

	
	payload_dns 			= (struct dnshdr *)payload;

	payload_dns->id 		= htons(0xfde7);
	payload_dns->flags 		= htons(0x0100);
	payload_dns->num_questions 	= htons(1);
	payload_dns->num_answers 	= htons(0);
	payload_dns->num_authority 	= htons(0);
	payload_dns->num_additional 	= htons(0);

	//由于域名长度不确定，这里单独填充域名，注意.号替换为字节数


	//buf_str这个数组，这里不能用指针表示，会提示内存越界段错误
	//但是如果把完全一样的代码单独放到一个测试文件中编译可以用指针表示
	//char **buf_str;
	//所以domain也必须是数组形式，否则会有问题
	//处于安全考量，限制域名长度为15字节不过会提示too long，
	//因为确实明显超过了，还是留空直接用宏赋值好了
	//域名深度最多为5，这个没问题
        char domain[] = DOMAIN;
	char *buf_str[5];
        int buf_size[5];
        int domain_section;


        domain_section = domain_split(domain, buf_str, buf_size);

        printf("the domain_section is %d===\n", domain_section);

        int j;
        for(j=0; j<domain_section; j++)
        {
                printf("buf_str %s===\n", buf_str[j]);
                printf("buf_size %d===\n", buf_size[j]);

        }

	//下面这个printf语句非常诡异，这里只要已开启，就会导致udp报头的目的端口被重置成len1
	//并且dns查询数据包无法发送出去，只要注释掉，或只打印1个，2个就正常，非常奇怪
	//printf("the str len1 len2 len3 is %d,%d,%d====\n",len1,len2,len3);
	
	//换成syslog打印确实是完全正常的
	syslog(LOG_INFO,"the str len1 len2 len3 is %d,%d,%d====\n",len1,len2,len3);	
	
	//由于dns报文结构的前面12字节是固定，上面的代码已经分别填充了，
	//域名部分是紧接着的数据，所有要定义len_payload长度
	len_payload = sizeof(struct dnshdr);
	

	//开始填充dns负载报文中的域名部分,这部分是可变长度，不能用结构体，也不能最后填充
	int i;
	for(i = 0; i < domain_section; i++)
	{
		*(char *)(payload + len_payload)        = buf_size[i];
		len_payload ++;
        
		memcpy( (char *)(payload + len_payload ), buf_str[i], buf_size[i] );
		len_payload += buf_size[i];
	}

	
	*(char *)(payload + len_payload)   	= 0;
	len_payload ++;

	payload_dns_question = (struct dns_question_section *)(payload + len_payload);
	
	payload_dns_question->type  = htons(1);
	payload_dns_question->class = htons(1);


	//指针和指针之间的赋值时,有两种技巧都可以；
	//第一种用strcat，这种方式是只能用于字符类型指针；
	//strcat((buf + sizeof(struct ip) + sizeof(struct udphdr)), data);

	//第二种直接赋值，这种方式可以用于任何类型指针；
	//如果被赋值的指针带有+号不能出现在等号左边，可以引入临时变量data来解决

	//填写udp载荷数据，这里使用指针间的直接赋值这个技巧。      
	//memcpy(payload, data_dns, len_payload);

	//len_payload是结构体dnshdr加域名再加结构体dns_question_section总长度,
	//注意不是udp的总长度，而是udp出去udp的报头的负载数据的总长度
	len_payload += sizeof(struct dns_question_section);
	
	return len_payload;
}

int payload_tcp(char *payload)
{
	//必须先定义tcp的负载，因为要确定长度。
	//这里既可以用指针，也可以用数组，还可以用malloc分配
	//char payload[100];    char * payload = malloc(100);
	char *data_http;
	int len_payload;

	//payload  =  "123456abcd";
	data_http = "HTTP/1.1 200 OK\r\n\r\n";
	//get /thy.html HTTP/1.1 /r/n";

	len_payload = strlen(data_http);
	printf("len payload is %d===\n", len_payload);

	//指针和指针之间的赋值时,有两种技巧都可以；
	//第一种用strcat，这种方式是只能用于字符类型指针；
	//strcat((buf + sizeof(struct ip) + sizeof(struct tcphdr)), data);

	//第二种直接赋值，这种方式可以用于任何类型指针；
	//如果被赋值的指针带有+号不能出现在等号左边，可以引入临时变量data来解决

	//填写tcp载荷数据，这里使用指针间的直接赋值这个技巧。      
	// data = payload;
	// payload  =  "123456abcd";
	memcpy(payload, data_http, len_payload);

	return len_payload;
}



int payload_icmp(char *payload)
{
	//icmp协议的数据部分没有什么限制，可以随便填写
        int len_payload;
	
	//对于icmp协议中ping包，这部分数据是完全回显的，
	//也就是说服务端不做任何变更直接返回过来
        //char *data_icmp = "1234567890abcdefghij123456789012thy";
        char *data_icmp = "ip a";

        len_payload = strlen(data_icmp);
        printf("len payload is %d===\n", len_payload);

        //填写icmp载荷数据，这里使用指针间的直接赋值这个技巧。      
        memcpy(payload, data_icmp, len_payload);

        return len_payload;
}
