#ifndef __TSG_TRAFFIC_MIRROR_H__
#define __TSG_TRAFFIC_MIRROR_H__

#define TRRAFFIC_MIRROR_DISABLE 0
#define TRRAFFIC_MIRROR_ENABLE 1

#define TRRAFFIC_MIRROR_SEND_SUCCESS 0
#define SEND_ERROR_NOT_INIT -1
#define SEND_ERROR_THREAD_SEQ_ERR -2
#define SEND_ERROR_PKT_BUFFER_IS_NULL -3
#define SEND_ERROR_PKT_LEN_ERROR -4
#define SEND_ERROR_VLAN_BUFFER_IS_NULL -5
#define SEND_ERROR_VLAN_NUM_ERROR -6
#define SEND_ERROR_VLAN_NUM_EXCEED_BURST_MAX -7
#define SEND_ERROR_BUFF_MALLOC_ERROR -8
#define TRRAFFIC_MIRROR_SEND_ERROR_DROP -9

struct traffic_mirror;

struct traffic_mirror *tsg_traffic_mirror_init(const char *conffile, void *logger);
int tsg_traffic_mirror_send_burst(struct traffic_mirror *ttm,char * pkt_ptr,int pkt_len,int *vlan_array,int vlan_num,int thread_seq);

#endif