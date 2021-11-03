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
        return -1;
    }

    //start_len+1 : 因为计算校验和是16bit为单位，这里调换16bit的低8bit。
    for(i=startlen+1; i<endlen; i=i+2){
        for (j=i+2; j<endlen; j=j+2){
            if(str[i] != str[j]){
                temp = str[i];
                str[i] = str[j];
                str[j] = temp;
                return 0;
            }
        }
    }
    return -1;
}

unsigned char send_tamper_xxx(const struct streaminfo *a_stream, const void *raw_pkt)
{
    const char *p_trans_payload = (char *)a_stream->ptcpdetail->pdata;
    int trans_layload_len = a_stream->ptcpdetail->datalen;
    char tamper_buf[MTU_LEN] = {0}; 
    unsigned char raw_route_dir = 0;
    int  ret = 0;
    
    if(a_stream == NULL){
        return STATE_DROPPKT;   
    }

    if((p_trans_payload==NULL)||(trans_layload_len<=0)||(a_stream->curdir== DIR_S2C)){
        return STATE_DROPPKT;   
    }

    memcpy(tamper_buf, p_trans_payload, trans_layload_len);
    ret = tamper_calc(tamper_buf, 0, trans_layload_len);
    if (ret < 0){
        return STATE_DROPPKT; 
    }

    raw_route_dir = (a_stream->curdir==DIR_C2S) ? a_stream->routedir : MESA_dir_reverse(a_stream->routedir);
    tsg_send_inject_packet(a_stream, SIO_DEFAULT, tamper_buf, trans_layload_len, raw_route_dir); 

    return STATE_DROPPKT;
}
