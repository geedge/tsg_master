#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "tsg_entry.h"
#include "tsg_protocol_common.h"

#define MTU_LEN 65535
#define MAC_LEN 6
#define MAC_LEN_2  ((MAC_LEN)+(MAC_LEN))
#define ETH_IP_TYPE_LEN 2
#define ETH_LEN ((MAC_LEN_2)+(ETH_IP_TYPE_LEN))

#define IPV4_TYPE   1 //ADDR_TYPE_IPV4 ==1 , 取的enum 0x0800
#define IPV6_TYPE   2 //ADDR_TYPE_IPV6 ==2 0x86dd   
#define TCP_TYPE 0x06
#define UDP_TYPE 0x11

#define IPV4_LEN                   20    //ip_len(20) 
#define IPV4_PROTOCOL_INDEX         9     //ipv4_protocol_index_len
#define IPV4_TCP_HEAD_LEN_INDEX     32    //ip_len(20) + tcp_head_len_index()
#define ETH_IPV4_IP_UPD_LEN         28    //ip_len(20) + udp_len(8) 
#define IPV4_IP_LEN_INDEX   2             //ip_len_index(2)

#define IPV6_PROTOCOL_INDEX         6    //ipv6_protocol_index(6)
#define IPV6_LEN        40
#define ETH_IPV6_LEN                40    //ipv6_len(40)
#define IPV6_TCP_OPTION_LEN_INDEX   52    //ipv6_len(40) + tcp_head_len_index(12)
#define IPV6_UDP_PALYLOAD_START_INDEX 48  //ipv6_len(40) + udp_len(8)
#define IPV6_IP_PAYLOAD_INDEX  4         //ipv6_payload_index(4)

int tamper_calc(char *str, int startlen, int endlen)
{
    int i = 0;
    int j = 0;
    char temp;

    //最小交换paythod的第2个字节和第四个字节，否则不处理
    if ((endlen - startlen) < 4){
        return STATE_DROPPKT;
    }

    //start_len+1 : 因为计算校验和是16bit为单位，这里调换16bit的低8bit。
    for(i = startlen+1; i < endlen; i++){
        for (j = i+2; j < endlen; j++){
            if(str[i] != str[j]){
                temp = str[i];
                str[i] = str[j];
                str[j] = temp;
                return STATE_GIVEME;
            }
        }
    }
    return STATE_DROPPKT;
}

int stamp_calc2(char *str, int startlen, int endlen)
{               
    int i = 0;
    char temp;

    if(endlen - startlen < 4){
        return STATE_DROPPKT;
    }

    for(i = startlen; (i < endlen) && (i+3 < endlen); i=i+4){
        printf("ii = %d \n", i);
        if(str[i+1] != str[i+3]){
            temp = str[i+1];
            str[i+1] = str[i+3];
            str[i+3] = temp;
            return STATE_GIVEME;
        }
    }
    return STATE_DROPPKT;
}

int tamper_ipv4(const char *packet, char *ret_packet, int *ret_len){
    int packet_len = 0;
    int src_ipv4_total_len = 0;
    char tcp_head_len;
    char protocol_type = packet[IPV4_PROTOCOL_INDEX]; 
    int  payload_start_index = 0; 
    int  tcp_head_all_len = 0;

    //get packet_len
    memcpy(&src_ipv4_total_len, &packet[IPV4_IP_LEN_INDEX], sizeof(short));
    packet_len = htons(src_ipv4_total_len);

    if(protocol_type == TCP_TYPE){
        tcp_head_len = ret_packet[IPV4_TCP_HEAD_LEN_INDEX];
        tcp_head_len = ((tcp_head_len>>4)&0x0f)*4;
        tcp_head_all_len = tcp_head_len + IPV4_LEN;
        if(packet_len == tcp_head_all_len){
            return -1;
        }
        payload_start_index = IPV4_LEN + tcp_head_len;
    }else if(protocol_type == UDP_TYPE){
        if(ETH_IPV4_IP_UPD_LEN == packet_len){
            return -1;
        }
        payload_start_index = ETH_IPV4_IP_UPD_LEN;
    }

    *ret_len = packet_len-payload_start_index+1;
    memcpy(ret_packet, &packet[payload_start_index], *ret_len);
    return tamper_calc(ret_packet, payload_start_index, packet_len);
}

//int tamper_ipv6(char *packet, int packet_len){
int tamper_ipv6(const char *packet, char *ret_packet, int *ret_len){
    int packet_len = 0;
    short src_ipv6_total_len = 0;
    char tcp_head_len;
    char protocol_type = packet[IPV6_PROTOCOL_INDEX]; 
    int  payload_start_index = 0; 
    int  packet_all_len = 0;

    memcpy(&src_ipv6_total_len, &packet[IPV6_IP_PAYLOAD_INDEX], sizeof(short));  //get ipv6_payload_len 
    packet_len = htons(src_ipv6_total_len) + IPV6_LEN;
    *ret_len =  packet_len;

    if(protocol_type == TCP_TYPE){
        tcp_head_len = ret_packet[IPV6_TCP_OPTION_LEN_INDEX];
        tcp_head_len = ((tcp_head_len>>4)&0x0f)*4;
        packet_all_len =  tcp_head_len + IPV6_LEN;
        if(packet_len == packet_all_len){
            return -1;
        }
        payload_start_index = IPV6_LEN + tcp_head_len;
    }else if(protocol_type == UDP_TYPE){
        if(IPV6_UDP_PALYLOAD_START_INDEX == packet_len){
            return -1;
        }
        payload_start_index = IPV6_UDP_PALYLOAD_START_INDEX;
    }

    *ret_len = packet_len-payload_start_index+1;
    memcpy(ret_packet, &packet[payload_start_index], *ret_len);
    return tamper_calc(ret_packet, payload_start_index, packet_len);
}

static int format_tamper(const char *packet, char *tamper_buf, int *tamper_len, int ip_type){
    int ret = 0;

    if(IPV4_TYPE == ip_type) {
        ret = tamper_ipv4((char *)packet, tamper_buf, tamper_len);
    }else{
        ret = tamper_ipv6((char *)packet, tamper_buf, tamper_len);
    }

    return ret;
}

unsigned char send_tamper_xxx(const struct streaminfo *a_stream, const void *raw_pkt)
{
    char tamper_buf[MTU_LEN] = {0}; 
    unsigned char raw_route_dir = 0;
    int  tamper_len = 0;
    int  ret = 0;

    ret = format_tamper((char *)raw_pkt, tamper_buf, &tamper_len, a_stream->addr.addrtype);
    if (ret < 0){
        return STATE_DROPPKT;   
    }

    raw_route_dir=(a_stream->curdir==DIR_C2S) ? a_stream->routedir : MESA_dir_reverse(a_stream->routedir);
    tsg_send_inject_packet(a_stream, SIO_DEFAULT, tamper_buf, tamper_len, raw_route_dir); 

    return STATE_DROPPKT|STATE_DROPME;
}

