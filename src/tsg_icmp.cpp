#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "tsg_entry.h"
#include <MESA/MESA_handle_logger.h>
#include "tsg_protocol_common.h"

#define IPV4_TYPE               1     //ADDR_TYPE_IPV4 ==1 , 取的enum 0x0800
#define IPV6_TYPE               2     //ADDR_TYPE_IPV6 ==2 0x86dd   
#define TCP_TYPE                0x06
#define UDP_TYPE                0x11
#define ICMP_PROTOCOL_TYPE      0x01  //ipv4 icmp  proctocol
#define ICMPV6_PROTOCAL_TYPE    0x3a  //ipv6 icmpv6 protocl

#define ICMPV4_UNREACHABLE                  0x03
#define ICMPV4_PORT_UNREACHABLE             0x03
#define ICMPV4_ADMINISTRATIVELY_PROHIBITED  0x0d
#define ICMPV6_UNREACHABLE                  0x01
#define ICMPV6_PORT_UNREACHABLE             0X04
#define ICMPV6_ADMINISTRATIVELY_PROHIBITED  0x01


//icmp
#define ICMP_HEADR_BYTE_LEN   8
#define ICMP_MAX_LEN   2048

//icmpv4
#define IPV4_HEADR_BYTE_LEN 20
#define IPV4_IPADDR_BYTE_LEN 4
#define IPV4_TOTAL_LEN_INDEX  2
#define IPV4_TOTAL_BYTE_LEN  2
#define IPV4_SIP_INDEX 12
#define IPV4_DIP_INDEX 16
#define IPV4_PROTOCOL_INDEX 9
#define IPV4_CHECKSUM_INDEX 10
#define IPV4_CHECKSUM_BYTE_LEN 2
#define ICMPV4_SRCPACKET_MAX_LEN    548  // 548 == ipv4(max_len 576)-ip_len(20)-icmp_head_len(8)

//icmpv6
//#define ICMPV6_ICMP_INDEX 40
#define IPV6_HEADR_BYTE_LEN 40
#define IPV6_IPADDR_BYTE_LEN 16
#define IPV6_PAYLOAD_BYTE_LEN 2
#define IPV6_SIP_INDEX 8
#define IPV6_DIP_INDEX 24
#define IPV6_PAYLOAD_INDEX 4
#define IPV6_NEXT_HEADR_INDEX 6
#define IPV6_2IP_BYTE_LEN  32
#define IPV6_PESUDO_HEADR_BYTE_LEN 40
#define IPV6_PESUDO_UPPER_LAYER_PACKET_AND_ZERO_LEN 7
#define IPV6_PESUDO_HEAD_PAYLOAD_BYTE_LEN  4
#define ICMPV6_SRCPACKET_MTU 1232 // 1232 == ipv6(max_len 1280)-ipv6_headr_len(40)-icmp_head_len(8)
#define ICMPV6_MTU 1280               // ICMPV6_SRCPACKET_MTU + IPV6_HEADR_BYTE_LEN + ICMPV6_HEARD_LEN

typedef struct icmp_st_{
    char type;
    char code;
    short checksum;
    char un_user[4];
    char origin_data[ICMPV6_SRCPACKET_MTU];
}icmp_st;

static short in_checksum(void *pkg, int size)
{
    int             nleft   = size;
    int             sum     = 0;
    unsigned short  *w      = (unsigned short *)pkg;
    unsigned short  answer  = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        * (unsigned char *) (&answer) = *(unsigned char *)w;
        sum += answer;
    }

    while (sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    answer = ~sum &0xffff;

    return answer;
}


static void four_byte_alignment(short *icmp_len, short *icmp_checksum_len){
    short temp = 0;

    temp = *icmp_len % 4;
    if(temp >0){
        *icmp_len = *icmp_len+(4-temp);
        *icmp_checksum_len = *icmp_checksum_len+(4-temp);
    }

    return ;
}

/*
 *  ICMP 报文格式
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Type      |     Code      |          Checksum             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                             unused                            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |      Internet Header + 64 bits of Original Data Datagram      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  ICMPV4 = [ipv4_headr]+[icmp]
 *  ICMPV4(MTU)  576
 */

static void format_icmpv4(const char *raw_pkt, char *ret_icmpv4, int *ret_len){
    icmp_st icmp = {0};
    char ipv4_headr[IPV4_HEADR_BYTE_LEN] = {0};
    short raw_ipv4_total_len = 0;
    short icmpv4_len = 0;
    short ipv4_total_len = 0;
    short ipv4_checksum = 0;             
    short icmp_len = 0;
    short icmp_original_data_len = 0;
    short icmp_start_len = IPV4_HEADR_BYTE_LEN;

    memcpy(&raw_ipv4_total_len, &raw_pkt[IPV4_TOTAL_LEN_INDEX], IPV4_TOTAL_BYTE_LEN);
    raw_ipv4_total_len = htons(raw_ipv4_total_len);

    //src_packet_len = raw_ipv4_total_len + ETH_LEN;
    if(raw_ipv4_total_len >= ICMPV4_SRCPACKET_MAX_LEN){
        icmp_original_data_len = ICMPV4_SRCPACKET_MAX_LEN;
    }else{
        icmp_original_data_len = raw_ipv4_total_len;
    }

    icmp_len = icmp_original_data_len + ICMP_HEADR_BYTE_LEN;
    ipv4_total_len = icmp_len + IPV4_HEADR_BYTE_LEN;
    icmpv4_len = ipv4_total_len;

    //format ipv4 headr
    memcpy(ipv4_headr, raw_pkt, IPV4_HEADR_BYTE_LEN);                                        //copy source data
    memcpy(&ipv4_headr[IPV4_SIP_INDEX], &raw_pkt[IPV4_DIP_INDEX], IPV4_IPADDR_BYTE_LEN);     //format ipv4 sip
    memcpy(&ipv4_headr[IPV4_DIP_INDEX], &raw_pkt[IPV4_SIP_INDEX], IPV4_IPADDR_BYTE_LEN);     //format ipv4 dip
    ipv4_headr[IPV4_PROTOCOL_INDEX] = ICMP_PROTOCOL_TYPE;                                    //set ipv4 protocol type (0x01 == ICMP)
    ipv4_total_len = htons(ipv4_total_len);
    memcpy(&ipv4_headr[IPV4_TOTAL_LEN_INDEX], &ipv4_total_len, IPV4_TOTAL_BYTE_LEN);         //format ipv4 total len
    memset(&ipv4_headr[IPV4_CHECKSUM_INDEX], 0, IPV4_CHECKSUM_BYTE_LEN);                     //empty checksum data
    ipv4_checksum = in_checksum(ipv4_headr, IPV4_HEADR_BYTE_LEN);                            //calc ipv4 checksum
    memcpy(&ipv4_headr[IPV4_CHECKSUM_INDEX], &ipv4_checksum, IPV4_CHECKSUM_BYTE_LEN);        //format ipv4 checksum

    //format icmp
    memset(&icmp, 0, sizeof(icmp_st));
    memcpy(icmp.origin_data, raw_pkt, icmp_original_data_len);
    icmp.type = ICMPV4_UNREACHABLE;
    icmp.code = ICMPV4_ADMINISTRATIVELY_PROHIBITED;
    icmp.checksum = in_checksum((void*)&icmp, icmp_len);

    //format complete icmpv4 packet
    memcpy(ret_icmpv4, ipv4_headr, IPV4_HEADR_BYTE_LEN);
    memcpy(&ret_icmpv4[icmp_start_len], &icmp, icmp_len);
    *ret_len = icmpv4_len;

    return;
}

/*
 *  icmpv6数据包组装
 *  [ICMPV6] = [ipv6_headr]+[icmp]
 *
 *  icmpv6的最大MTU应是ipv6的最小MTU(1280)
 *  <本端内容来自RFC443>
 *  Every ICMPv6 error message (type < 128) MUST include as much of
 *  the IPv6 offending (invoking) packet (the packet that caused the
 *  error) as possible without making the error message packet exceed
 *  the minimum IPv6 MTU [IPv6].
 *
 *  [ICMPV6] = [ipv6_headr]+[icmp]
 *
 *  计算ICMPV6的校验和： (ICMP + 伪首部) 作为计算数据部分
 *  注意： ICMPV6数据要补充成四字节对齐
 *  ipv6伪首部数据: 长度
 *  {
 *      Soucre Address :            16
 *      Destination Address:        16
 *      Upper-Layer Packet Length:  4
 *      zero:                       3
 *      Next Heard:                 1
 *  }
 *
 **  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  +                                                               +
 *  ~                                                               ~
 *  ~                         icmp                                  ~
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +                         Source Address                        +
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +                      Destination Address                      +
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                   Upper-Layer Packet Length                   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                      zero                     |  Next Header  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  [ICMPV6] = [ipv6_headr]+[icmp]
 *  ICMPV6(MTU) 1280
 */

static void format_icmpv6(const char *raw_pkt, char *ret_icmpv6, int *ret_len){
    icmp_st icmp = {0};
    char icmp_checksum_buf[ICMPV6_MTU] = {0};
    char ipv6_headr[IPV6_HEADR_BYTE_LEN] = {0};
    short ipv6_payload_len = 0;
    short raw_ipv6_payload_len = 0;
    short raw_pkt_len = 0;
    short icmpv6_len = 0;
    short icmp_len = 0;
    short icmp_original_data_len = 0;
    short icmp_checksum_len = 0;
    int upper_layer_packet_len = 0;

    memcpy(&raw_ipv6_payload_len, &raw_pkt[IPV6_PAYLOAD_INDEX], IPV6_PAYLOAD_BYTE_LEN);  //get ipv6_payload_len
    raw_pkt_len = ntohs(raw_ipv6_payload_len) + IPV6_HEADR_BYTE_LEN;

    if(raw_pkt_len >= ICMPV6_SRCPACKET_MTU){
        icmp_original_data_len = ICMPV6_SRCPACKET_MTU;
    }else{
        icmp_original_data_len = raw_pkt_len;
    }

    icmp_len = icmp_original_data_len + ICMP_HEADR_BYTE_LEN;
    icmpv6_len = IPV6_HEADR_BYTE_LEN + icmp_len;
    icmp_checksum_len = icmp_len + IPV6_PESUDO_HEADR_BYTE_LEN;
    ipv6_payload_len = htons(icmp_len);

    //format ipv6 headr
    memcpy(ipv6_headr, raw_pkt, IPV6_HEADR_BYTE_LEN);                                     //format source ipv6 data
    memcpy(&ipv6_headr[IPV6_SIP_INDEX], &raw_pkt[IPV6_DIP_INDEX], IPV6_IPADDR_BYTE_LEN);  //modify format sip
    memcpy(&ipv6_headr[IPV6_DIP_INDEX], &raw_pkt[IPV6_SIP_INDEX], IPV6_IPADDR_BYTE_LEN);  //modify format dip
    memcpy(&ipv6_headr[IPV6_PAYLOAD_INDEX], &ipv6_payload_len, IPV6_PAYLOAD_BYTE_LEN);    //modify format ipv6 payload
    ipv6_headr[IPV6_NEXT_HEADR_INDEX] = ICMPV6_PROTOCAL_TYPE;                             //modify format ipv6 protocol (icmpv6 == 0X3a);

    //format icmp
    memset(&icmp, 0, sizeof(icmp_st));
    icmp.type = ICMPV6_UNREACHABLE;
    icmp.code = ICMPV6_ADMINISTRATIVELY_PROHIBITED;
    memcpy(icmp.origin_data, raw_pkt, icmp_original_data_len);

    upper_layer_packet_len = htonl((int)icmp_len);
    four_byte_alignment(&icmp_len, &icmp_checksum_len); //icmp_len和icmp_checksum_len 补充为4字节对齐

    //calc icmp checksum
    memcpy(icmp_checksum_buf, &icmp, icmp_len);
    memcpy(&icmp_checksum_buf[icmp_len], &ipv6_headr[IPV6_SIP_INDEX], IPV6_2IP_BYTE_LEN);
    memcpy(&icmp_checksum_buf[icmp_len+IPV6_2IP_BYTE_LEN], &upper_layer_packet_len, IPV6_PESUDO_HEAD_PAYLOAD_BYTE_LEN);
    icmp_checksum_buf[icmp_len+IPV6_2IP_BYTE_LEN+IPV6_PESUDO_UPPER_LAYER_PACKET_AND_ZERO_LEN] = ICMPV6_PROTOCAL_TYPE;
    icmp.checksum = in_checksum(icmp_checksum_buf, icmp_checksum_len);

    //format complete icmpv6 packet
    memcpy(ret_icmpv6, ipv6_headr, IPV6_HEADR_BYTE_LEN);
    memcpy(&ret_icmpv6[IPV6_HEADR_BYTE_LEN], &icmp, icmp_len);
    *ret_len = icmpv6_len;

    return;
}

static void format_icmp(const char *raw_pkt, char *icmp_buf, int *icmp_len, int ip_type){
    if(IPV4_TYPE == ip_type) {
        format_icmpv4(raw_pkt, icmp_buf, icmp_len);
    } else{ //IPV6_TYPE
        format_icmpv6(raw_pkt, icmp_buf, icmp_len);
    }
    return;
}

unsigned char send_icmp_unreachable(const struct streaminfo *a_stream, const void *raw_pkt)
{
    char icmp_buf[ICMP_MAX_LEN] = {0}; 
    char debug_buf[512] = {0};
    int  icmp_len = 0;

    if((a_stream==NULL)||(raw_pkt==NULL)){
        return STATE_DROPPKT;
    }                                                                                                                        

    format_icmp((char *)raw_pkt, icmp_buf, &icmp_len, a_stream->addr.addrtype);
    if (0 == tsg_send_inject_packet(a_stream, SIO_EXCLUDE_THIS_LAYER_HDR, icmp_buf, icmp_len, MESA_dir_reverse(a_stream->routedir))){
        sprintf(debug_buf, "Addr: %s, send_icmp_unreachable sucess, raw_pkt %p, icmp_buf %p, icmp_len %d", PRINTADDR(a_stream, g_tsg_para.level), raw_pkt, icmp_buf, icmp_len);
    }else{
        sprintf(debug_buf, "Addr: %s, send_icmp_unreachable failed, raw_pkt %p, icmp_buf %p, icmp_len %d", PRINTADDR(a_stream, g_tsg_para.level), raw_pkt, icmp_buf, icmp_len);
    }

    MESA_handle_runtime_log(g_tsg_para.logger,
            RLOG_LV_DEBUG,
            __FUNCTION__,
            debug_buf);

    return STATE_DROPPKT;
}

