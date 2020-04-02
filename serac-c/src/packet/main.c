/*
 * =====================================================================================
 *
 *    ProgramName:  数据包生成器(Packets Creator)
 *
 *    Description:  集成ARP,UDP,TCP,DNS,ICMP,OSPF等数据包的构造器
 *
 *        Version:  1.0
 *        Created:  2015年10月3日 19时12分
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Haiyang Tang
 *        Website:  http://geektcp.com
 *          Email:  geektcp@163.com
 *
 * =====================================================================================
 */

#include	"arp.h"
#include	"udp.h"
#include	"tcp.h"

#include	<syslog.h>

int main(int argc, char **argv)
{
//      creator_arp();

//	creator_udp();

//      creator_tcp();

//      creator_dns();

      creator_icmp();

	return 0;
}
