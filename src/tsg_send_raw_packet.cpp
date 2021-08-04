#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_rule.h"
#include "tsg_entry.h"


static int send_raw_packet(struct traffic_mirror *ttm,char * pkt_ptr,int pkt_len, struct mirrored_vlan *vlan,int vlan_num,int thread_seq)
{
	int i=0,ret=0;
	for(i=0; i<vlan_num; i++)
	{
		ret=tsg_traffic_mirror_send_burst(ttm, (char *)pkt_ptr, pkt_len, &(vlan[i].vlan_id), 1, thread_seq);		
		if(ret==TRAFFIC_MIRROR_SEND_SUCCESS)
		{				
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_MIRRORED_PKT_SUCCESS], 0, FS_OP_ADD, 1);
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_MIRRORED_BYTE_SUCCESS], 0, FS_OP_ADD, pkt_len); 		
		}
		else
		{
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_MIRRORED_PKT_FAILED], 0, FS_OP_ADD, 1);
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_MIRRORED_BYTE_FAILED], 0, FS_OP_ADD, pkt_len);
		}

		vlan[i].mirrored_pkts+=1;
		vlan[i].mirrored_bytes+=pkt_len;
	}
	
	return 0;
}

int tsg_send_raw_packet(const struct streaminfo *a_stream, struct mirrored_vlan *vlan, int vlan_num, int thread_seq)
{
	int ret=0;
	void *p_eth_rawpkt=NULL;
	int eth_rawpkt_len=0;
	raw_ipfrag_list_t *frag_pkt=NULL;
	
	if(g_tsg_para.mirror_switch==0 || vlan==NULL || vlan_num<=0)
	{
		return 0;
	}

	ret=get_rawpkt_opt_from_streaminfo(a_stream, RAW_PKT_GET_DATA, &p_eth_rawpkt);
	switch(0)
	{
		case	0:
			ret=get_rawpkt_opt_from_streaminfo(a_stream, RAW_PKT_GET_TOT_LEN, &eth_rawpkt_len);
			if(ret<0)
			{
				break;
			}
			
			send_raw_packet(g_tsg_para.mirror_handle, (char *)p_eth_rawpkt, eth_rawpkt_len, vlan, vlan_num, thread_seq);
			break;
		case	1:
			frag_pkt=(raw_ipfrag_list_t *)p_eth_rawpkt;
			while(frag_pkt)
			{
				send_raw_packet(g_tsg_para.mirror_handle, (char *)(frag_pkt->frag_packet), frag_pkt->pkt_len, vlan, vlan_num, thread_seq);				
				frag_pkt = frag_pkt->next;
			}
			break;
		default:
			break;
	}
		
	return 0;
}

int tsg_notify_hited_monitor_result(const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, int thread_seq)
{
	if(g_tsg_para.mirror_switch==0)
	{
		return 0;
	}

	int vlan_num=0;
	struct mirrored_vlan vlan[MAX_RESULT_NUM]={0};
	struct tcpall_context *context=NULL;

	vlan_num=tsg_get_vlan_id_by_monitor_rule(g_tsg_maat_feather, result, result_num, vlan, MAX_RESULT_NUM);
	tsg_set_vlan_id_to_tcpall(a_stream, &context, vlan, vlan_num, thread_seq);

	return 1;
}

int tsg_send_raw_packet_init(const char* conffile, void *logger)
{
	MESA_load_profile_short_def(conffile, "TRAFFIC_MIRROR", "TRAFFIC_MIRROR_ENABLE", &g_tsg_para.mirror_switch, 0);
	if(g_tsg_para.mirror_switch==0)
	{
		return 0;
	}
	
	g_tsg_para.mirror_handle=tsg_traffic_mirror_init(conffile, g_tsg_para.logger);
	if(g_tsg_para.mirror_handle==NULL)
	{
		return -1;
	}

	return 0;
}
