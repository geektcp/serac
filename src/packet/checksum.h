//可能要要用到memcpy，strlen，printf等函数，添加标准io头文件
#include	<stdio.h>
#include	<netinet/in.h>


unsigned short 
creator_check_sum(char *buf, int protocol);
