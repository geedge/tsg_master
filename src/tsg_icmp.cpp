#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "tsg_entry.h"
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

#define MAC_LEN 6
#define MAC_LEN_2  ((MAC_LEN)+(MAC_LEN))
#define ETH_IP_TYPE_LEN 2
#define ETH_LEN ((MAC_LEN_2)+(ETH_IP_TYPE_LEN))


#define TCP_MAX_LEN             60
#define ICMP_IPV4_TCP_MAX_LEN   44 //64-20 = 44       
#define IPV4_SHAM_FIXED_LEN     12   

#define IPV4_LEN        20
#define IPV4_IP_LEN     4
#define IPV4_IP_LEN_INDEX   2   //eth_len(14)+ ip_len_index(2)
#define IPV6_LEN        40
#define IPV6_IP_LEN     16
#define IPV6_IP_PAYLOAD_INDEX  4  // ipv6_payload_index(4)
#define ICMP_IPV4_PROTOCOL_TYPE_LEN 24
#define ICMP_HEAD_LEN               8
#define ICMPV4_SOURCE_MAX_LEN       64
#define ICMPV4_MAX_LEN  ((ICMPV4_SOURCE_MAX_LEN)+(ICMP_HEAD_LEN))
#define IPV6_PESUDO_HEAD_LEN        40

#define ICMP_MAX_LEN   65535     
#define ICMP_SRCPACKET_MAX_LEN    548  // 548 == ipv4(max_len 576)-ip_len(20)-icmp_head_len(8)
#define ICMPV6_SRCPACKET_MAX_LEN  1232 // 1232 == ipv6(max_len 1280)-ipv6_len(40)-icmp_head_len(8)
#define ICMPV6_MTU  1280     

typedef struct icmpv4{
    char type;
    char code;
    short checksum;
    char un_user[4];
    char srcPacket[ICMPV6_SRCPACKET_MAX_LEN];
}icmpv4_st, icmpv6_st;

short in_checksum(void *pkg, int size)
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

static void format_icmpv4(const char *raw_pkt, char *buf, int *len){
    char ipv4[IPV4_LEN] = {0};
    icmpv4_st icmpst = {0};
    short src_ipv4_total_len = 0;
    short icmpv4_complete_len = 0;
    short icmp_len = 0;
    short icmp_srcpacket_len = 0;
    short icmp_start_len = IPV4_LEN;
    short ipv4_total_len = 0;
    short ipv4_checksum = 0;             
    short sip_len = 12;                 //skip sip start index
    short dip_len = 16;                 //skip dip start index

    memcpy(&src_ipv4_total_len, &raw_pkt[IPV4_IP_LEN_INDEX], sizeof(short));
    src_ipv4_total_len = htons(src_ipv4_total_len);

    //src_packet_len = src_ipv4_total_len + ETH_LEN;
    if(src_ipv4_total_len >= ICMP_SRCPACKET_MAX_LEN){
        icmp_srcpacket_len = ICMP_SRCPACKET_MAX_LEN;
    }else{
        icmp_srcpacket_len = src_ipv4_total_len;
    }

    icmp_len = icmp_srcpacket_len + ICMP_HEAD_LEN;
    ipv4_total_len = icmp_len + IPV4_LEN;
    icmpv4_complete_len = IPV4_LEN + icmp_len;

    //format icmp information
    memset(&icmpst, 0, sizeof(icmpv4_st));
    memcpy(icmpst.srcPacket, raw_pkt, icmp_srcpacket_len); //
    icmpst.type = ICMPV4_UNREACHABLE;
    icmpst.code = ICMPV4_ADMINISTRATIVELY_PROHIBITED;
    icmpst.checksum = in_checksum((void*)&icmpst, icmp_len);

    //format ipv4
    memcpy(ipv4, raw_pkt, IPV4_LEN);             //copy source data
    memcpy(&ipv4[12], &raw_pkt[dip_len], IPV4_IP_LEN);     //get sip 
    memcpy(&ipv4[16], &raw_pkt[sip_len], IPV4_IP_LEN);     //get dip 
    ipv4[9] = ICMP_PROTOCOL_TYPE;                       //set ipv4 protocol type (0x01 == ICMP)
    ipv4_total_len = htons(ipv4_total_len);
    memcpy(&ipv4[2], &ipv4_total_len, sizeof(short));   //format ipv4 len
    memset(&ipv4[10], 0, sizeof(short));                //empty checksum data
    ipv4_checksum = in_checksum(ipv4, IPV4_LEN);        //calc ipv4 checksum
    memcpy(&ipv4[10], &ipv4_checksum, sizeof(short));   //format checksum

    //format complete icmpv4 packet
    memcpy(buf, ipv4, IPV4_LEN);
    memcpy(&buf[icmp_start_len], &icmpst, icmp_len);
    *len = icmpv4_complete_len;

    return;
}

static void format_icmpv6(const char *data, char *buf, int *len){
    char checksum_str[ICMPV6_MTU] = {0}; 
    char ipv6[IPV6_LEN] = {0};
    icmpv6_st icmpst = {0};
    short src_ipv6_total_len = 0;
    short icmpv6_complete_len = 0;
    short icmp_len = 0;
    short icmp_srcpacket_len = 0;
    short icmp_start_len = IPV6_LEN;
    short checksum_len = 0;
    short sip_len = 8;  //skip sip start index
    short dip_len = 24; //skip dip start index, 16+8 == 24
    short ipv6_ip2 = IPV6_IP_LEN + IPV6_IP_LEN;
    short payload_len = 0;
    short fill_icmp_len = 0;       
    int checksum_payload_len = 0;  

    memcpy(&src_ipv6_total_len, &data[IPV6_IP_PAYLOAD_INDEX], sizeof(short));  //get ipv6_payload_len 
    src_ipv6_total_len = htons(src_ipv6_total_len) + IPV6_LEN;

    if(src_ipv6_total_len >= ICMPV6_SRCPACKET_MAX_LEN){
        icmp_srcpacket_len = ICMPV6_SRCPACKET_MAX_LEN;
    }else{
        icmp_srcpacket_len = src_ipv6_total_len;
    }

    icmp_len = icmp_srcpacket_len + ICMP_HEAD_LEN;
    icmpv6_complete_len = IPV6_LEN + icmp_len;
    checksum_len = icmp_len + IPV6_PESUDO_HEAD_LEN;
    payload_len = htons(icmp_len);

    //format ipv6
    memcpy(ipv6, data, IPV6_LEN);                       //copy source ipv6 data
    memcpy(&ipv6[8], &data[dip_len], IPV6_IP_LEN);      //get sip 
    memcpy(&ipv6[24],&data[sip_len], IPV6_IP_LEN);      //get dip 
    memcpy(&ipv6[4], &payload_len, sizeof(short));      //format ipv6 payload
    ipv6[6] = ICMPV6_PROTOCAL_TYPE;                     //format ipv6 protocol (icmpv6 == 0X3a);

    //format icmp
    memset(&icmpst, 0, sizeof(icmpv6_st));
    icmpst.type = ICMPV6_UNREACHABLE;
    icmpst.code = ICMPV6_ADMINISTRATIVELY_PROHIBITED;
    memcpy(icmpst.srcPacket, data, icmp_srcpacket_len);

    //补充为4字节
    checksum_payload_len = htonl((int)icmp_len);            
    fill_icmp_len = icmp_len % 4;                           
    if( fill_icmp_len > 0){                                 
        icmp_len = icmp_len + (4-fill_icmp_len);            
        checksum_len = checksum_len + (4-fill_icmp_len);    
    }                                                       

    //calc icmpv6 checksum
    memcpy(checksum_str, &icmpst, icmp_len);  
    memcpy(&checksum_str[icmp_len], &ipv6[8], ipv6_ip2);
    memcpy(&checksum_str[icmp_len+ipv6_ip2], &checksum_payload_len, sizeof(int)); 
    checksum_str[icmp_len+ipv6_ip2+7] = ICMPV6_PROTOCAL_TYPE;
    icmpst.checksum = in_checksum(checksum_str, checksum_len);

    //format complete icmpv6 packet
    memcpy(buf, ipv6, IPV6_LEN);
    memcpy(&buf[icmp_start_len], &icmpst, icmp_len);
    *len = icmpv6_complete_len;

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
    int  icmp_len = 0;

    if((a_stream==NULL)||(raw_pkt==NULL)){
        return STATE_DROPPKT;
    }                                                                                                                        

    format_icmp((char *)raw_pkt, icmp_buf, &icmp_len, a_stream->addr.addrtype);
    tsg_send_inject_packet(a_stream, SIO_EXCLUDE_THIS_LAYER_HDR, icmp_buf, icmp_len, MESA_dir_reverse(a_stream->routedir)); 
    return STATE_DROPPKT;
}

