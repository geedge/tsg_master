#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>

#include <MESA/stream.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include "app_label.h"
#include "tsg_entry.h"
#include "tsg_send_log.h"
#include "tsg_send_log_internal.h"

char TSG_SEND_LOG_VERSION_20200729=0;
struct tsg_log_instance_t *g_tsg_log_instance;


const id2field_t tld_type[TLD_TYPE_MAX]={{TLD_TYPE_UNKNOWN,	TLD_TYPE_UNKNOWN, 	"UNKOWN"},
								 			{TLD_TYPE_LONG, 	TLD_TYPE_LONG,		"LONG"},
								 			{TLD_TYPE_STRING, 	TLD_TYPE_STRING, 	"STRING"},
											{TLD_TYPE_FILE,		TLD_TYPE_FILE,		"FILE"},
											{TLD_TYPE_TOPIC,	TLD_TYPE_TOPIC,		"TOPIC"}
										   };

extern "C" int MESA_get_dev_ipv4(const char *device, int *ip_add);

static int is_tunnels(struct streaminfo *a_stream)
{
	const struct streaminfo *ptmp = a_stream;
	const struct streaminfo *pfather=NULL;
	int is_tunnel=0;
	
	while(ptmp)
	{
		pfather = ptmp->pfather;
		switch(ptmp->addr.addrtype)
		{
			case	ADDR_TYPE_GRE:
			case	ADDR_TYPE_VLAN:
			case	ADDR_TYPE_L2TP:
			case	ADDR_TYPE_PPTP:
			case	ADDR_TYPE_VXLAN:
			case	ADDR_TYPE_GPRS_TUNNEL:
			case	__ADDR_TYPE_IP_PAIR_V4:
			case	__ADDR_TYPE_IP_PAIR_V6:
				is_tunnel=1;
				break;
			case	ADDR_TYPE_MPLS:
				if(ptmp->addr.mpls->s2c_layer_num==0 && ptmp->addr.mpls->c2s_layer_num==0)
				{
					break;
				}
				is_tunnel=1;
				break;
			default:
				break;
		}
		
		ptmp = pfather;
	}

	return is_tunnel;
}

static int set_isn(struct TLD_handle_t *_handle, struct streaminfo *a_stream, char *field_name, enum MESA_stream_opt type)
{
	int ret=0;
	unsigned int isn=0;
	int size=sizeof(unsigned long long);

	size=sizeof(unsigned int);
	ret=MESA_get_stream_opt(a_stream, type, &isn, &size);
	if(ret==0)
	{		
		TLD_append(_handle, field_name, (void *)(long)isn, TLD_TYPE_LONG);
	}

	return 1;
}

static int set_tcp_isn(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream)
{
	if(a_stream->type==STREAM_TYPE_TCP)
	{
		switch(a_stream->dir)
		{
			case	DIR_C2S:				
				set_isn(_handle, a_stream, _instance->id2field[LOG_COMMON_TCP_CLIENT_ISN].name, MSO_TCP_ISN_C2S);
				break;
			case	DIR_S2C:				
				set_isn(_handle, a_stream, _instance->id2field[LOG_COMMON_TCP_SERVER_ISN].name, MSO_TCP_ISN_S2C);
				break;
			case	DIR_DOUBLE:
				set_isn(_handle, a_stream, _instance->id2field[LOG_COMMON_TCP_CLIENT_ISN].name, MSO_TCP_ISN_C2S);
				set_isn(_handle, a_stream, _instance->id2field[LOG_COMMON_TCP_SERVER_ISN].name, MSO_TCP_ISN_S2C);
				break;
			default:
				break;
		}
	}
	
	return 1;
}

static int set_asn(struct TLD_handle_t *_handle, struct streaminfo *a_stream, char *field_name, struct _asn_info_t *asn_info)
{
	char buff[1024]={0};
	
	if(asn_info!=NULL)
	{
		snprintf(buff, sizeof(buff), "%s(%s)", asn_info->asn, asn_info->organization);
		TLD_append(_handle, field_name, (void *)buff, TLD_TYPE_STRING);
	}

	return 1;
}

static int set_location(struct TLD_handle_t *_handle, struct streaminfo *a_stream, char *field_name, struct _location_info_t *location_info)
{
	char buff[1024]={0};
	
	if(location_info!=NULL)
	{
		snprintf(buff, sizeof(buff), "%s,%s,%s", location_info->city_full, location_info->province_full, location_info->country_full);
		TLD_append(_handle, field_name, (void *)buff, TLD_TYPE_STRING);
	}

	return 1;
}


static int set_direction(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream)
{
	int direction=0,i_or_e=0;

	i_or_e=MESA_dir_link_to_human(a_stream->routedir);
	switch(a_stream->curdir)
	{
		case	DIR_C2S:
			if(i_or_e=='E' || i_or_e=='e')
			{
				direction='E';
			}
			else
			{
				direction='I';
			}
			break;
		case	DIR_S2C:
			if(i_or_e=='E' || i_or_e=='e')
			{
				direction='I';
			}
			else
			{
				direction='E';
			}
			break;
		default:
			break;
	}

	
	TLD_append(_handle, _instance->id2field[LOG_COMMON_DIRECTION].name, (void *)(long)direction, TLD_TYPE_LONG);

	return 1;
}

static int set_address_list(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream)
{
	int ret=0;
	unsigned short tunnel_type=0;
	char nest_addr_buf[1024];
	int tunnel_type_size=sizeof(tunnel_type);
	
	ret=MESA_get_stream_opt(a_stream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &tunnel_type_size);
	assert(ret==0);
	if(tunnel_type==STREAM_TUNNLE_NON)
	{	
		layer_addr_ntop_r(a_stream,nest_addr_buf, sizeof(nest_addr_buf));
	}
	else
	{		
		stream_addr_list_ntop(a_stream,nest_addr_buf, sizeof(nest_addr_buf));
	}
	
	TLD_append(_handle, _instance->id2field[LOG_COMMON_ADDRESS_LIST].name, (void *)nest_addr_buf, TLD_TYPE_STRING);

	return 1;
}

static int set_tuple4(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream)
{
	int addr_type=0;
	unsigned short c_port=0, s_port=0;
	struct layer_addr_ipv4 *ipv4=NULL;
	struct layer_addr_ipv6 *ipv6=NULL;
	char server_ip[MAX_IPV4_LEN*8]={0};
	char client_ip[MAX_IPV4_LEN*8]={0};
	
	switch(a_stream->addr.addrtype)
	{
		case	ADDR_TYPE_IPV4:
		case	__ADDR_TYPE_IP_PAIR_V4:
			ipv4=a_stream->addr.ipv4;
			addr_type=4;
			c_port=ntohs(ipv4->source);
			s_port=ntohs(ipv4->dest);
			
			inet_ntop(AF_INET, (void *)&ipv4->saddr, client_ip, sizeof(client_ip));
			inet_ntop(AF_INET, (void *)&ipv4->daddr, server_ip, sizeof(server_ip));
			break;
		case	ADDR_TYPE_IPV6:
		case	__ADDR_TYPE_IP_PAIR_V6:
			ipv6=a_stream->addr.ipv6;
			addr_type=6;
			c_port=ntohs(ipv6->source);
			s_port=ntohs(ipv6->dest);
			
			inet_ntop(AF_INET6, (void *)ipv6->saddr, client_ip, sizeof(client_ip));
			inet_ntop(AF_INET6, (void *)ipv6->daddr, server_ip, sizeof(server_ip));
			break;
		default:
			break;
	}

	
	TLD_append(_handle, _instance->id2field[LOG_COMMON_SERVER_IP].name, (void *)server_ip, TLD_TYPE_STRING);
	TLD_append(_handle, _instance->id2field[LOG_COMMON_CLIENT_IP].name, (void *)client_ip, TLD_TYPE_STRING);
	TLD_append(_handle, _instance->id2field[LOG_COMMON_SERVER_PORT].name, (void *)(long)s_port, TLD_TYPE_LONG);
	TLD_append(_handle, _instance->id2field[LOG_COMMON_CLIENT_PORT].name, (void *)(long)c_port, TLD_TYPE_LONG);
	
	TLD_append(_handle, _instance->id2field[LOG_COMMON_STREAM_DIR].name, (void *)(long)a_stream->dir, TLD_TYPE_LONG);	
	TLD_append(_handle, _instance->id2field[LOG_COMMON_ADDRESS_TYPE].name, (void *)(long)addr_type, TLD_TYPE_LONG);

	return 1;
}


static int set_duraction(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream)
{
	int ret=0;
	struct timespec tv;
	long common_con_duration_ms=0;
	unsigned long long create_time=0;
	int size=sizeof(unsigned long long);

	if(a_stream->ptcpdetail!=NULL)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_START_TIME].name, (void *)(a_stream->ptcpdetail->createtime), TLD_TYPE_LONG);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_END_TIME].name, (void *)(a_stream->ptcpdetail->lastmtime), TLD_TYPE_LONG);

		ret=MESA_get_stream_opt(a_stream, MSO_STREAM_CREATE_TIMESTAMP_MS, (void *)&create_time, &size);
		if(ret>=0)
		{
			clock_gettime(CLOCK_REALTIME, &tv);
			common_con_duration_ms=tv.tv_sec*1000+tv.tv_nsec/1000/1000 - create_time;
		}
		
		if(common_con_duration_ms>0)
		{
			TLD_append(_handle, _instance->id2field[LOG_COMMON_CON_DURATION_MS].name, (void *)(common_con_duration_ms), TLD_TYPE_LONG);
		}
	}
	else
	{
		time_t cur_time=time(NULL);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_START_TIME].name, (void *)cur_time, TLD_TYPE_LONG);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_END_TIME].name, (void *)cur_time, TLD_TYPE_LONG);		
		TLD_append(_handle, _instance->id2field[LOG_COMMON_CON_DURATION_MS].name, (void *)(common_con_duration_ms), TLD_TYPE_LONG);
	}
	
	return 1;
}

static int set_fqdn_category(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream, unsigned int *category_id, int category_id_num)
{
	int i=0;
	if(category_id_num<=0 || category_id==NULL)
	{
		return 0;
	}
	
	cJSON *fqdn_array=cJSON_CreateArray();
	for(i=0; i<category_id_num; i++)
	{
		cJSON_AddNumberToObject(fqdn_array, _instance->id2field[LOG_COMMON_FQDN_CATEGORY].name, category_id[i]);
	}

	cJSON_AddItemToObject(_handle->object, _instance->id2field[LOG_COMMON_FQDN_CATEGORY].name, fqdn_array);

	return 1;
}

static int set_umts_user_info(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream, struct umts_user_info *user_info)
{
	if(user_info==NULL)
	{
		return 0;
	}

	if(user_info->apn!=NULL)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_GTP_APN].name, (void *)user_info->apn, TLD_TYPE_STRING);
	}

	if(user_info->imsi!=NULL)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_GTP_IMSI].name, (void *)user_info->imsi, TLD_TYPE_STRING);
	}

	if(user_info->imei!=NULL)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_GTP_IMEI].name, (void *)user_info->imei, TLD_TYPE_STRING);
	}

	if(user_info->msisdn!=NULL)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_GTP_MSISDN].name, (void *)user_info->msisdn, TLD_TYPE_STRING);	//phone number
	}

	return 1;
}

static int set_packet_bytes(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream)
{
	struct tcp_flow_stat *tflow_project=NULL;
    struct udp_flow_stat *uflow_project=NULL;
	
	switch(a_stream->type)
	{
		case	STREAM_TYPE_TCP:
			tflow_project=(struct tcp_flow_stat *)project_req_get_struct(a_stream, _instance->tcp_flow_project_id);
			if(tflow_project!=NULL)
			{
				TLD_append(_handle, _instance->id2field[LOG_COMMON_S2C_PKT_NUM].name, (void *)(long)tflow_project->S2C_all_pkt, TLD_TYPE_LONG);
				TLD_append(_handle, _instance->id2field[LOG_COMMON_S2C_BYTE_NUM].name, (void *)(long)tflow_project->S2C_all_byte_raw, TLD_TYPE_LONG);
				TLD_append(_handle, _instance->id2field[LOG_COMMON_C2S_PKT_NUM].name, (void *)(long)tflow_project->C2S_all_pkt, TLD_TYPE_LONG);
				TLD_append(_handle, _instance->id2field[LOG_COMMON_C2S_BYTE_NUM].name, (void *)(long)tflow_project->C2S_all_byte_raw, TLD_TYPE_LONG);
			}
			break;
		case	STREAM_TYPE_UDP:
			uflow_project=(struct udp_flow_stat *)project_req_get_struct(a_stream, _instance->udp_flow_project_id);
			if(uflow_project!=NULL)
			{
				TLD_append(_handle, _instance->id2field[LOG_COMMON_S2C_PKT_NUM].name, (void *)(long)uflow_project->S2C_pkt, TLD_TYPE_LONG);
				TLD_append(_handle, _instance->id2field[LOG_COMMON_S2C_BYTE_NUM].name, (void *)(long)uflow_project->S2C_all_byte_raw, TLD_TYPE_LONG);
				TLD_append(_handle, _instance->id2field[LOG_COMMON_C2S_PKT_NUM].name, (void *)(long)uflow_project->C2S_pkt, TLD_TYPE_LONG);
				TLD_append(_handle, _instance->id2field[LOG_COMMON_C2S_BYTE_NUM].name, (void *)(long)uflow_project->C2S_all_byte_raw, TLD_TYPE_LONG);
			}
			break;
		default:
			break;
	}

	return 1;
}

static int get_l7_protocol(struct app_identify_result *result, char *protocol_list, int protocol_list_len,  int *flag)
{
	int i=0,offset=0;
	char *name=NULL;

	if((*flag)==1)
	{
		return 0;
	}
	
	for(i=0; i<result->app_id_num; i++)
	{
		(*flag)=1;
		name=tsg_l7_protocol_id2name(result->app_id[i]);
		if(name!=NULL)
		{
			if(i>0 && offset>0 && (protocol_list_len-offset)>0)
			{
				protocol_list[offset]='.';
				offset++;
			}
			offset+=snprintf(protocol_list+offset, protocol_list_len-offset, "%s", name);
		}
	}

	return 1;
}

static int get_app_id(struct app_identify_result *result, unsigned int *app_id, unsigned int *surrogate_id, int *flag)
{
	if(result->app_id_num>0 && (*flag)==0)
	{
		(*flag)=1;
		(*app_id)=result->app_id[result->app_id_num-1];
		(*surrogate_id)=result->surrogate_id[result->app_id_num-1];

		return 1;
	}

	return 0;
}

static int get_app_id_list(struct app_identify_result *result, char *app_list, int app_list_len, char *surrogate_list, int surrogate_list_len)
{
	int i=0;
	int offset1=0,offset2=0;
	
	for(i=0; i<result->app_id_num; i++)
	{
		offset1+=snprintf(app_list+offset1, app_list_len-offset1, "APP%d=%d;", result->origin, result->app_id[i]);
		offset2+=snprintf(surrogate_list+offset2, surrogate_list_len-offset2, "SURROGATE%d=%d;", result->origin, result->surrogate_id[i]);
	}

	return 1;
}

static int get_app_name_list(struct app_identify_result *result, char *app_name, int app_name_len, int *flag, int is_joint_parent)
{
	int i=0;
	int offset=0;

	if((*flag)==1)
	{
		return 0;
	}
	
	for(i=0; i<result->app_id_num; i++)
	{
		(*flag)=1;

		if(i>0 && offset>0 && (app_name_len-offset)>0)
		{
			app_name[offset]='.';
			offset++;
		}
		
		offset+=tsg_app_id2name(result->app_id[i], app_name+offset, app_name_len-offset, is_joint_parent);
	}

	return 1;
}

static int set_app_id(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream)
{
	int app_id_flag=0;
	int app_offset=0;
	int surrogate_offset=0;
	int l7_protocol_flag=0;
	char app_list[512]={0};
	char app_name[512]={0};
	char protocol_list[256]={0};
	char surrogate_list[512]={0};
	unsigned int one_app_id=0;
	unsigned int one_surrogate_id=0;
	struct gather_app_result *label=NULL;
	
	label=(struct gather_app_result *)project_req_get_struct(a_stream, g_tsg_para.gather_app_project_id);
	if(label==NULL)
	{		
		TLD_append(_handle, _instance->id2field[LOG_COMMON_L7_PROTOCOL].name, (void *)_instance->l7_unknown_name, TLD_TYPE_STRING);
		return 0;
	}
	
	get_l7_protocol(&(label->result[ORIGIN_BASIC_PROTOCOL]), protocol_list, sizeof(protocol_list), &l7_protocol_flag);
	if(l7_protocol_flag==1)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_L7_PROTOCOL].name, (void *)protocol_list, TLD_TYPE_STRING);
	}
	else
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_L7_PROTOCOL].name, (void *)_instance->l7_unknown_name, TLD_TYPE_STRING);
	}

	if(_instance->app_id_type==0) // int
	{
		get_app_id(&(label->result[ORIGIN_USER_DEFINE]), &one_app_id, &one_surrogate_id, &app_id_flag);
		get_app_id(&(label->result[ORIGIN_DKPT]), &one_app_id, &one_surrogate_id, &app_id_flag);
		get_app_id(&(label->result[ORIGIN_QM_ENGINE]), &one_app_id, &one_surrogate_id, &app_id_flag);
		
		if(app_id_flag==1)
		{
			TLD_append(_handle, _instance->id2field[LOG_COMMON_APP_ID].name, (void *)(long)one_app_id, TLD_TYPE_LONG);		
			TLD_append(_handle, _instance->id2field[LOG_COMMON_APP_SURROGATE_ID].name, (void *)(long)one_surrogate_id, TLD_TYPE_LONG);
		}
	}
	else //string
	{
		app_offset=0;
		surrogate_offset=0;
		get_app_id_list(&(label->result[ORIGIN_USER_DEFINE]), app_list+app_offset, sizeof(app_list)-app_offset, surrogate_list+surrogate_offset, sizeof(surrogate_list)-surrogate_offset);

		app_offset=strlen(app_list);
		surrogate_offset=strlen(surrogate_list);
		get_app_id_list(&(label->result[ORIGIN_DKPT]), app_list+app_offset, sizeof(app_list)-app_offset, surrogate_list+surrogate_offset, sizeof(surrogate_list)-surrogate_offset);

		app_offset=strlen(app_list);
		surrogate_offset=strlen(surrogate_list);
		get_app_id_list(&(label->result[ORIGIN_QM_ENGINE]), app_list+app_offset, sizeof(app_list)-app_offset, surrogate_list+surrogate_offset, sizeof(surrogate_list)-surrogate_offset);

		get_app_name_list(&(label->result[ORIGIN_USER_DEFINE]), app_name, sizeof(app_name), &app_id_flag, 1);
		if(app_id_flag!=1)
		{
			get_app_name_list(&(label->result[ORIGIN_DKPT]), app_name, sizeof(app_name), &app_id_flag, 0);
		}

		if(app_id_flag!=1)
		{
			get_app_name_list(&(label->result[ORIGIN_QM_ENGINE]), app_name, sizeof(app_name), &app_id_flag, 1);
		}
		
		if(app_id_flag==1)
		{
			TLD_append(_handle, _instance->id2field[LOG_COMMON_APP_ID].name, (void *)app_list, TLD_TYPE_STRING);		
			TLD_append(_handle, _instance->id2field[LOG_COMMON_APP_SURROGATE_ID].name, (void *)surrogate_list, TLD_TYPE_STRING);

			TLD_append(_handle, _instance->id2field[LOG_COMMON_APP_LABEL].name, (void *)app_name, TLD_TYPE_STRING);
		}
	}
	
	return 1;
}

static int set_vlan(struct tsg_log_instance_t *_instance, struct single_layer_vlan_addr *vlan_addr, int layer_num, cJSON *tunnel_object, tsg_log_field_id_t id)
{
	if(layer_num==0)
	{
		return 0;
	}
	
	int i=0;
	cJSON *vlan_array=cJSON_CreateArray();
	for(i=0; i<layer_num; i++)
	{
		cJSON_AddNumberToObject(vlan_array, _instance->id2field[id].name, ntohs(vlan_addr[i].VID));
	}

	cJSON_AddItemToObject(tunnel_object, _instance->id2field[id].name, vlan_array);

	return 1;
}

static int set_mpls(struct tsg_log_instance_t *_instance, struct single_layer_mpls_addr *mpls_addr, int layer_num, cJSON *tunnel_object, tsg_log_field_id_t id)
{
	if(layer_num==0)
	{
		return 0;
	}

	int i=0;
	cJSON *mpls_array=cJSON_CreateArray();
	for(i=0; i<layer_num; i++)
	{
		cJSON_AddNumberToObject(mpls_array, _instance->id2field[id].name, ntohl(mpls_addr[i].label));
	}
	
	cJSON_AddItemToObject(tunnel_object, _instance->id2field[id].name, mpls_array);

	return 1;
}


static int mac_to_string(unsigned char *mac, char *buff)
{
	int i=0,len=0;
	
	for(i=0; i<6; i++)
	{
		len+=sprintf(buff+len, "%02x:", mac[i]);
	}

	buff[len-1]='\0';

	return 0;
}

static int set_link_mac(struct tsg_log_instance_t *_instance, struct layer_addr_mac *mac, cJSON *tunnel_object)
{
	int flag=0;
	char default_mac[6]={0,0,0,0,0,0};
	char c2s_source_mac[128]={0};
	char c2s_dest_mac[128]={0};
	char s2c_source_mac[128]={0};
	char s2c_dest_mac[128]={0};

	if((memcmp(mac->src_addr.h_source, default_mac, 6)))
	{
		flag|=1;
		mac_to_string(mac->src_addr.h_source, c2s_source_mac);
		mac_to_string(mac->src_addr.h_dest, c2s_dest_mac);
	}

	if((memcmp(mac->dst_addr.h_source, default_mac, 6)))
	{
		flag|=2;
		mac_to_string(mac->dst_addr.h_source, s2c_source_mac);
		mac_to_string(mac->dst_addr.h_dest, s2c_dest_mac);	
	}

	switch(flag)
	{
		case	1:			
			cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "ETHERNET");
			cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_MAC_SOURCE].name, c2s_source_mac);
			cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_MAC_DEST].name, c2s_dest_mac);
			break;
		case	2:			
			cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "ETHERNET");
			cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_MAC_SOURCE].name, s2c_source_mac);
			cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_MAC_DEST].name, s2c_dest_mac);
			break;
		case	3:			
			cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "MULTIPATH_ETHERNET");
			cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_C2S_MAC_SOURCE].name, c2s_source_mac);
			cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_C2S_MAC_DEST].name, c2s_dest_mac);
			cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_S2C_MAC_SOURCE].name, s2c_source_mac);
			cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_S2C_MAC_DEST].name, s2c_dest_mac);
			break;
		default:
			break;
	}
	
	return 1;
}

static int action2fs_id(int action)
{
	switch(action)
	{
		case	TSG_ACTION_DENY:
			return TSG_FS2_ABORT_DENY; 
			break;
		case	TSG_ACTION_BYPASS:
			return TSG_FS2_ABORT_ALLOW;
			break;
		case	TSG_ACTION_MONITOR:
			return TSG_FS2_ABORT_MONITOR;
			break;
		case	TSG_ACTION_INTERCEPT:
			return TSG_FS2_ABORT_INTERCEPT;
			break;
		default:
			return TSG_FS2_ABORT_UNKNOWN;
			break;
	}

	return TSG_FS2_ABORT_UNKNOWN;
}

int TLD_cancel(struct TLD_handle_t *handle)
{
	struct TLD_handle_t *_handle=handle;
	
	if(_handle!=NULL)
	{
		if(_handle->object!=NULL)
		{
			cJSON_Delete(_handle->object);
			_handle->object=NULL;
		}
	
		free(handle);
		handle=NULL;
	}
	
	return 0;
}

int TLD_delete(struct TLD_handle_t *handle, char *key)
{
	struct TLD_handle_t *_handle=handle;
	
	if(_handle!=NULL && key!=NULL)
	{
		cJSON_DeleteItemFromObject(_handle->object, key);
	}

	return 0;
}

int TLD_append(struct TLD_handle_t *handle, char *key, void *value, TLD_TYPE type)
{
	struct TLD_handle_t *_handle=handle;
	
	if(_handle==NULL || key==NULL || (value==NULL && type!=TLD_TYPE_LONG))
	{
		return -1;
	}
	
	switch(type)
	{
		case	TLD_TYPE_LONG:
			cJSON_AddNumberToObject(_handle->object, key, (long)value);
			break;
		case	TLD_TYPE_FILE:
			break;
		case	TLD_TYPE_STRING:
			if(strlen((char *)value)==0)
			{
				break;
			}
			cJSON_AddStringToObject(_handle->object, key, (char *)value);
			break;
		case	TLD_TYPE_CJSON:
			cJSON_AddItemToObject(_handle->object, key, (cJSON *)value);
			break;
		default:
			return -1;
			break;
	}
	
	return 0;	
}

struct TLD_handle_t *TLD_create(int thread_id)
{
	//struct _tld_handle *_handle=(struct _tld_handle *)dictator_malloc(thread_id, sizeof(struct _tld_handle));
	
	struct TLD_handle_t *_handle=(struct TLD_handle_t *)calloc(1, sizeof(struct TLD_handle_t));
	_handle->thread_id = thread_id;
	_handle->object = cJSON_CreateObject();
	
	return _handle;
}

static int get_gtp_ipv4v6_port(struct tsg_log_instance_t *_instance, struct streaminfo *a_stream, cJSON *object)
{
	char ip_buff[64]={0};

	if(a_stream!=NULL)
	{
		switch(a_stream->addr.addrtype)
		{
			case	ADDR_TYPE_IPV4:
					inet_ntop(AF_INET, (const void *)&(a_stream->addr.ipv4->saddr), ip_buff, sizeof(ip_buff));
					cJSON_AddStringToObject(object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_SGW_IP].name, ip_buff);	
					inet_ntop(AF_INET, (const void *)&(a_stream->addr.ipv4->daddr), ip_buff, sizeof(ip_buff));				
					cJSON_AddStringToObject(object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_PGW_IP].name, ip_buff);

					cJSON_AddNumberToObject(object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_SGW_PORT].name, (unsigned int)(a_stream->addr.ipv4->source));					
					cJSON_AddNumberToObject(object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_PGW_PORT].name, (unsigned int)(a_stream->addr.ipv4->dest));
					return 1;
				break;
			case	ADDR_TYPE_IPV6:
					inet_ntop(AF_INET6, (const void *)(a_stream->addr.ipv6->saddr), ip_buff, sizeof(ip_buff));
					cJSON_AddStringToObject(object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_SGW_IP].name, ip_buff);	
					inet_ntop(AF_INET6, (const void *)(a_stream->addr.ipv6->daddr), ip_buff, sizeof(ip_buff));				
					cJSON_AddStringToObject(object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_PGW_IP].name, ip_buff);
					
					cJSON_AddNumberToObject(object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_SGW_PORT].name, (unsigned int)(a_stream->addr.ipv6->source));					
					cJSON_AddNumberToObject(object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_PGW_PORT].name, (unsigned int)(a_stream->addr.ipv6->dest));
					return 1;
				break;
			default:
				break;
				
		}
	}

	return 0;
}

static int set_common_tunnels(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream)
{
	int ret=0;	
	char ip_buff[64]={0};
	const struct streaminfo *ptmp = a_stream;
	const struct streaminfo *pfather=NULL;
	cJSON *tunnel_object=NULL;
	cJSON *tunnel_array=cJSON_CreateArray();

	while(ptmp)
	{
		pfather = ptmp->pfather;
		switch(ptmp->addr.addrtype)
		{
			case	ADDR_TYPE_MAC:
				tunnel_object=cJSON_CreateObject();
				set_link_mac(_instance, (ptmp->addr.mac), tunnel_object);
				break;
			case	ADDR_TYPE_VLAN:
				tunnel_object=cJSON_CreateObject();
				cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "VLAN");
				set_vlan(_instance, ptmp->addr.vlan->c2s_addr_array, ptmp->addr.vlan->c2s_layer_num, tunnel_object,  LOG_COMMON_TUNNELS_VLAN_SRC_ID);
				set_vlan(_instance, ptmp->addr.vlan->s2c_addr_array, ptmp->addr.vlan->s2c_layer_num, tunnel_object, LOG_COMMON_TUNNELS_VLAN_DST_ID);
				break;
			case	ADDR_TYPE_GRE:
				tunnel_object=cJSON_CreateObject();
				cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "GRE");
				break;
			case	ADDR_TYPE_MPLS:
				if(ptmp->addr.mpls->s2c_layer_num==0 && ptmp->addr.mpls->c2s_layer_num==0)
				{
					ptmp = pfather;
					continue;
				}
				
				tunnel_object=cJSON_CreateObject();
				cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, (char *)"MPLS");
				set_mpls(_instance, ptmp->addr.mpls->c2s_addr_array, ptmp->addr.mpls->c2s_layer_num, tunnel_object, LOG_COMMON_TUNNELS_MPLS_SRC_LABEL);
				set_mpls(_instance, ptmp->addr.mpls->s2c_addr_array, ptmp->addr.mpls->s2c_layer_num, tunnel_object, LOG_COMMON_TUNNELS_MPLS_DST_LABEL);
				break;
			case	ADDR_TYPE_L2TP:
				tunnel_object=cJSON_CreateObject();
				cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "L2TP");
				break;
			case	__ADDR_TYPE_IP_PAIR_V4:
				tunnel_object=cJSON_CreateObject();				
				cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "IPv4");
				
				inet_ntop(AF_INET, (const void *)&(ptmp->addr.ipv4->saddr), ip_buff, sizeof(ip_buff));
				cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_CLIENT_IP].name, ip_buff);
				
				inet_ntop(AF_INET, (const void *)&(ptmp->addr.ipv4->daddr), ip_buff, sizeof(ip_buff));				
				cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SERVER_IP].name, ip_buff);
				break;
			case	__ADDR_TYPE_IP_PAIR_V6:
				tunnel_object=cJSON_CreateObject();				
				cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "IPv6");
				
				inet_ntop(AF_INET6, (const void *)(ptmp->addr.ipv6->saddr), ip_buff, sizeof(ip_buff));
				cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_CLIENT_IP].name, ip_buff);
				
				inet_ntop(AF_INET6, (const void *)(ptmp->addr.ipv6->daddr), ip_buff, sizeof(ip_buff));				
				cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SERVER_IP].name, ip_buff);
				break;
			case	ADDR_TYPE_PPTP:
				tunnel_object=cJSON_CreateObject();
				cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "PPTP");
				cJSON_AddNumberToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_PPTP_C2S_ID].name, ntohl(ptmp->addr.pptp->C2S_call_id));
				cJSON_AddNumberToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_PPTP_S2C_ID].name, ntohl(ptmp->addr.pptp->S2C_call_id));
				break;
			case	ADDR_TYPE_GPRS_TUNNEL:
				tunnel_object=cJSON_CreateObject();
				cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "GTP");
				cJSON_AddNumberToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_UPLINK_TEID].name, ntohl(ptmp->addr.gtp->teid_c2s));
				cJSON_AddNumberToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_DOWNLINK_TEID].name, ntohl(ptmp->addr.gtp->teid_s2c));

				ret=get_gtp_ipv4v6_port(_instance, ptmp->pfather, tunnel_object);
				if(ret==1)
				{
					ptmp=pfather->pfather;
				}
				break;
			case	ADDR_TYPE_VXLAN:
				tunnel_object=cJSON_CreateObject();
				cJSON_AddStringToObject(tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "VXLAN");
				break;
			default:
				ptmp = pfather;
				continue;
				break;
		}
		
		ptmp = pfather;
		cJSON_AddItemToArray(tunnel_array, tunnel_object);
	}

	TLD_append(_handle, _instance->id2field[LOG_COMMON_TUNNELS].name, tunnel_array, TLD_TYPE_CJSON);
	
	return 0;
}

char *log_field_id2name(struct tsg_log_instance_t *instance, tsg_log_field_id_t id)
{
	struct tsg_log_instance_t *_instance=instance;
	if(_instance!=NULL)
	{
		return _instance->id2field[id].name;
	}

	return NULL;
}

unsigned long long tsg_get_stream_id(struct streaminfo * a_stream)
{
	int ret=0;
	int device_id_size=sizeof(unsigned long long);
	unsigned long long device_id=(unsigned long long)g_tsg_para.device_id;

	ret=MESA_get_stream_opt(a_stream, MSO_GLOBAL_STREAM_ID, (void *)&device_id, &device_id_size);
	if(ret==0)
	{
		return device_id;
	}

	return -1;
}

int is_multi_hit_same_policy(struct Maat_rule_t *result, int *policy_id, int *policy_id_num)
{
	int j=0;
	
	for(j=0;j<*policy_id_num;j++)
	{
		if(policy_id[j]==result->config_id)
		{
			return 1;
		}
	}

	policy_id[(*policy_id_num)++]=result->config_id;

	return 0;
}

static int set_common_sub_action(struct TLD_handle_t *handle, char *field_name, struct Maat_rule_t *p_result)
{
	cJSON *item=NULL;
	cJSON *object=NULL;
	char *tmp_buff=NULL;
	
	if(p_result->serv_def_len<128)
	{
		object=cJSON_Parse(p_result->service_defined);
	}
	else
	{
		tmp_buff=(char *)calloc(1, p_result->serv_def_len+1);
		Maat_read_rule(g_tsg_maat_feather, p_result, MAAT_RULE_SERV_DEFINE, tmp_buff, p_result->serv_def_len);
		object=cJSON_Parse(tmp_buff);

		free(tmp_buff);
		tmp_buff=NULL;
	}

	if(object!=NULL)
	{
		item=cJSON_GetObjectItem(object, "method");
		if(item!=NULL && item->valuestring!=NULL)
		{
			TLD_append(handle, field_name, (void *)item->valuestring, TLD_TYPE_STRING);
		}
		
		cJSON_Delete(object);
		object=NULL;
	}

	return 0;
}

int set_session_attributes(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream)
{
	struct _session_attribute_label_t *attribute_label=NULL;

	attribute_label=(struct _session_attribute_label_t *)project_req_get_struct(a_stream, _instance->internal_project_id);
	if(attribute_label!=NULL)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_ESTABLISH_LATENCY_MS].name, (void *)attribute_label->establish_latency_ms, TLD_TYPE_LONG);

		set_asn(_handle, a_stream, _instance->id2field[LOG_COMMON_CLINET_ASN].name, attribute_label->client_asn);		
		set_asn(_handle, a_stream, _instance->id2field[LOG_COMMON_SERVER_ASN].name, attribute_label->server_asn);
		
		set_location(_handle, a_stream, _instance->id2field[LOG_COMMON_CLINET_LOCATION].name, attribute_label->client_location);
		set_location(_handle, a_stream, _instance->id2field[LOG_COMMON_SERVER_LOCATION].name, attribute_label->server_location);
		
		set_fqdn_category(_instance, _handle, a_stream, attribute_label->fqdn_category_id, attribute_label->fqdn_category_id_num);

		if(attribute_label->ja3_fingerprint!=NULL)
		{
			TLD_append(_handle, _instance->id2field[LOG_SSL_JA3_FINGERPRINT].name, (void *)attribute_label->ja3_fingerprint, TLD_TYPE_STRING);
		}

		set_umts_user_info(_instance, _handle, a_stream, attribute_label->user_info);
	}
	
	return 0;
}

int TLD_append_streaminfo(struct tsg_log_instance_t *instance, struct TLD_handle_t *handle, struct streaminfo *a_stream)
{
	char *addr_proto=NULL;
	char stream_id_buff[128]={0};
	unsigned long long stream_id=0;
	struct TLD_handle_t *_handle=handle;
	struct tsg_log_instance_t *_instance=instance;

	if(_instance==NULL || _handle==NULL || a_stream==NULL)
	{		
		MESA_handle_runtime_log(_instance->logger, RLOG_LV_DEBUG, "TLD_APPEND_STREAM", "instance==NULL || TLD_handle==NULL || addr==NULL");
		return -1;
	}

	set_app_id(_instance, _handle, a_stream);
	set_tcp_isn(_instance, _handle, a_stream);
	set_tuple4(_instance, _handle, a_stream);
	set_direction(_instance, _handle, a_stream);
	set_address_list(_instance, _handle, a_stream);
	set_duraction(_instance, _handle, a_stream);
	set_packet_bytes(_instance, _handle, a_stream);	
	set_session_attributes(_instance, _handle, a_stream);

	if(is_tunnels(a_stream))
	{
		set_common_tunnels(_instance, _handle, a_stream);
	}
	
	stream_id=tsg_get_stream_id(a_stream);
	snprintf(stream_id_buff, sizeof(stream_id_buff), "%llu", stream_id);
	TLD_append(_handle, _instance->id2field[LOG_COMMON_STREAM_TRACE_ID].name, (void *)stream_id_buff, TLD_TYPE_STRING);
	
	addr_proto=(char *)layer_addr_prefix_ntop(a_stream);
	TLD_append(_handle, _instance->id2field[LOG_COMMON_L4_PROTOCOL].name, (void *)addr_proto, TLD_TYPE_STRING);

	return 0;
}

int load_log_common_field(const char *filename, id2field_t *id2field, id2field_t **service2topic, int *max_service)
{
	int i=0;
	int ret=0,id=0;
	FILE *fp=NULL;
	char line[1024]={0};
	char field_name[64]={0};
	char type_name[32]={0};
	id2field_t *_service2topic=NULL;
	
	fp=fopen(filename, "r");
	if(fp==NULL)
	{
		printf("Open %s failed ...", filename);
		return -1;
	}
	
	memset(line, 0, sizeof(line));

	while((fgets(line, sizeof(line), fp))!=NULL)
	{
		if(line[0]=='#' || line[0]=='\n' || line[0]=='\r' ||line[0]=='\0')
		{
			continue;
		}
		memset(type_name, 0, sizeof(type_name));
		ret=sscanf(line, "%s %s %d", type_name, field_name, &id);
		assert(ret==3);

		for(i=0; i<TLD_TYPE_MAX; i++)
		{
			if((strncasecmp(tld_type[i].name, type_name, strlen(tld_type[i].name)))==0)
			{
				switch(tld_type[i].type)
				{
					case	TLD_TYPE_FILE:
					case	TLD_TYPE_LONG:
					case	TLD_TYPE_STRING:
						id2field[id].type = tld_type[i].type;
						id2field[id].id = id;
						memcpy(id2field[id].name, field_name, strlen(field_name));
						break;
					case	TLD_TYPE_TOPIC:
						if(_service2topic==NULL)
						{
							_service2topic=(id2field_t *)calloc(1, sizeof(id2field_t)*(id+1));
							_service2topic[id].type = TLD_TYPE_MAX;
							_service2topic[id].id = id;
							memcpy(_service2topic[id].name, field_name, strlen(field_name));

							*max_service=id+1;
						}
						else
						{
							if(*max_service<=id)
							{
								_service2topic=(id2field_t *)realloc(_service2topic, sizeof(id2field_t)*(id+1));
								memset(&_service2topic[id], 0, sizeof(id2field_t));
								_service2topic[id].type = TLD_TYPE_MAX;
								_service2topic[id].id = id;
								memcpy(_service2topic[id].name, field_name, strlen(field_name));

								*max_service=id+1;
							}
							else
							{
								memset(&_service2topic[id], 0, sizeof(id2field_t));
								_service2topic[id].type = TLD_TYPE_MAX;
								_service2topic[id].id = id;
								memcpy(_service2topic[id].name, field_name, strlen(field_name));
							}
						}
						break;
					default:
						break;
				}
			}
		}
		memset(line, 0, sizeof(line));
	}

	fclose(fp);
	fp=NULL;

	if(service2topic!=NULL)
	{
		*service2topic=_service2topic;
	}

	return 0;
}

struct tsg_log_instance_t *tsg_sendlog_init(const char *conffile)
{
	int i=0,ret=0;
	char nic_name[32]={0};
	char kafka_errstr[1024]={0};
	unsigned int local_ip_nr=0;
	rd_kafka_t *kafka_handle = NULL;
	rd_kafka_conf_t *rdkafka_conf = NULL;
	rd_kafka_topic_conf_t *topic_conf;
	struct tsg_log_instance_t *_instance=NULL;
	
	_instance=(struct tsg_log_instance_t *)calloc(1, sizeof(struct tsg_log_instance_t));
	
	int thread_num=get_thread_count();
	_instance->drop_start=(struct timespec *)calloc(1, sizeof(struct timespec)*thread_num);
	_instance->fs_status_ids=(int *)calloc(1, sizeof(int)*thread_num);
	_instance->send_log_percent=(int *)calloc(1, sizeof(int)*thread_num);

	for(i=0;i<thread_num; i++)
	{
		_instance->send_log_percent[i]=100;
	}

	MESA_load_profile_int_def(conffile, "TSG_LOG", "LOG_LEVEL",&(_instance->level), 30);	
	MESA_load_profile_string_def(conffile, "TSG_LOG", "LOG_PATH", _instance->log_path, sizeof(_instance->log_path), "./tsglog/tsglog");
	MESA_load_profile_int_def(conffile, "TSG_LOG", "SEND_USER_REGION",&(_instance->send_user_region), 0);	

	MESA_load_profile_int_def(conffile, "TSG_LOG", "APP_ID_TYPE", &(_instance->app_id_type), 1);	//0: int, 1: string	
	MESA_load_profile_string_def(conffile, "TSG_LOG", "L7_UNKNOWN_NAME", _instance->l7_unknown_name, sizeof(_instance->l7_unknown_name), "UNCATEGORIZED");

	_instance->logger=MESA_create_runtime_log_handle(_instance->log_path, _instance->level);
	if(_instance->logger==NULL)
	{
		printf("MESA_create_runtime_log_handle failed ..., path: %s level: %d", _instance->log_path, _instance->level);
		return NULL;
	}
	
	MESA_load_profile_int_def(conffile, "TSG_LOG", "MODE",&(_instance->mode), 0);
	if(_instance->mode==CLOSE)
	{
		MESA_handle_runtime_log(_instance->logger, RLOG_LV_FATAL, "TSG_LOG", "Disable tsg_send_log");
		return _instance;
	}
	
	MESA_load_profile_int_def(conffile, "TSG_LOG", "RECOVERY_INTERVEL_S", &(_instance->recovery_interval), 30);	

	MESA_load_profile_string_def(conffile, "TSG_LOG", "COMMON_FIELD_FILE", _instance->common_field_file, sizeof(_instance->common_field_file), NULL);
	MESA_load_profile_string_def(conffile, "TSG_LOG", "BROKER_LIST", _instance->broker_list, sizeof(_instance->broker_list), NULL);

	MESA_load_profile_string_def(conffile, "TSG_LOG", "SEND_QUEUE_MAX_MESSAGE", _instance->send_queue_max_msg, sizeof(_instance->send_queue_max_msg), "1000000");
	MESA_load_profile_string_def(conffile, "TSG_LOG", "REFRESH_INTERVAL_MS", _instance->refresh_interval_ms, sizeof(_instance->refresh_interval_ms), "600000");
	MESA_load_profile_string_def(conffile, "TSG_LOG", "REQUIRE_ACK", _instance->require_ack, sizeof(_instance->require_ack), "1");

	MESA_load_profile_string_def(conffile, "TSG_LOG", "TCP_LABEL", _instance->tcp_label, sizeof(_instance->tcp_label), "tcp_flow_stat");
	MESA_load_profile_string_def(conffile, "TSG_LOG", "UDP_LABEL", _instance->udp_label, sizeof(_instance->udp_label), "udp_flow_stat");

	_instance->tcp_flow_project_id=project_customer_register(_instance->tcp_label, "struct");
	_instance->udp_flow_project_id=project_customer_register(_instance->udp_label, "struct");
	if(_instance->tcp_flow_project_id<0 || _instance->udp_flow_project_id<0)
	{
		MESA_handle_runtime_log(_instance->logger,
									RLOG_LV_FATAL,
									"TCP_OR_UDP_LABEL",
									"project_customer_register is error, tcp_label: %s udp_label: %s, please check etc/project.conf",
									_instance->tcp_label,
									_instance->udp_label
								);
	}
	
	MESA_load_profile_string_def(conffile, "TSG_LOG", "NIC_NAME", nic_name, sizeof(nic_name), "eth0");	
	ret=MESA_get_dev_ipv4(nic_name, (int *)&local_ip_nr);
	if(ret<0)
	{
		MESA_handle_runtime_log(_instance->logger,
									RLOG_LV_FATAL,
									"GET_LOCAL_IP",
									"MESA_get_dev_ipv4 is error, nic_name: %s, please check tsgconf/main.conf",
									nic_name
								);
		return NULL;
	}
	inet_ntop(AF_INET,&(local_ip_nr),_instance->local_ip_str,sizeof(_instance->local_ip_str));
	
	rdkafka_conf = rd_kafka_conf_new();	
	rd_kafka_conf_set(rdkafka_conf, "queue.buffering.max.messages", _instance->send_queue_max_msg, kafka_errstr, sizeof(kafka_errstr));
	rd_kafka_conf_set(rdkafka_conf, "topic.metadata.refresh.interval.ms", _instance->refresh_interval_ms, kafka_errstr, sizeof(kafka_errstr));
	rd_kafka_conf_set(rdkafka_conf, "request.required.acks", _instance->require_ack, kafka_errstr, sizeof(kafka_errstr));	
	rd_kafka_conf_set(rdkafka_conf, "socket.keepalive.enable", "true", kafka_errstr, sizeof(kafka_errstr));
	
	if(!(kafka_handle=rd_kafka_new(RD_KAFKA_PRODUCER, rdkafka_conf, kafka_errstr, sizeof(kafka_errstr))))
	{
		MESA_handle_runtime_log(_instance->logger, RLOG_LV_FATAL, "KAFKA_INIT", "rd_kafka_new is error");
		return NULL;
	}

	if(rd_kafka_brokers_add(kafka_handle, _instance->broker_list) == 0)
	{
		MESA_handle_runtime_log(_instance->logger,
									RLOG_LV_FATAL,
									"KAFKA_INIT",
									"rd_kafka_brokers_add is error, broker_list: %s, please check tsgconf/main.conf",
									_instance->broker_list
								);
		return NULL;
	}
	
	load_log_common_field(_instance->common_field_file, _instance->id2field, &(_instance->service2topic), &(_instance->max_service));

	if(_instance->service2topic!=NULL)
	{
		_instance->topic_rkt=(rd_kafka_topic_t **)calloc(1, (_instance->max_service)*sizeof(rd_kafka_topic_t*));

		for(i=0; i<_instance->max_service; i++)
		{
			if(_instance->service2topic[i].type==TLD_TYPE_MAX)
			{
				topic_conf=rd_kafka_topic_conf_new();
				_instance->topic_rkt[_instance->service2topic[i].id]=rd_kafka_topic_new(kafka_handle, _instance->service2topic[i].name, topic_conf);
			}
		}
	}
	else
	{
		MESA_handle_runtime_log(_instance->logger,
									RLOG_LV_FATAL,
									"KAFKA_INIT",
									"load_log_common_field is error, please check %s",
									_instance->common_field_file
								);		
	}
	
	return _instance;
}


int tsg_send_log(struct tsg_log_instance_t *instance, struct TLD_handle_t *handle, tsg_log_t *log_msg, int thread_id)
{
	int ret=0,fs_id=0;
	int i=0,status=0;
	char *payload=NULL;
	char *user_agent=NULL;
	int repeat_cnt=0;
	struct timespec cur_time;
	int policy_id[MAX_RESULT_NUM]={0};
	struct TLD_handle_t *_handle=handle;
	struct tsg_log_instance_t *_instance=instance;
	
	if(_instance==NULL || _handle==NULL || log_msg==NULL)
	{
		TLD_cancel(handle);
		MESA_handle_runtime_log(_instance->logger, RLOG_LV_FATAL, "TSG_SEND_LOG", " instance==NULL || TLD_handle==NULL || log_msg==NULL ");
		return -1;
	}

	if(_instance->mode==CLOSE)
	{
		TLD_cancel(handle);		
		FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_DROP_LOG], 0, FS_OP_ADD, 1);
		MESA_handle_runtime_log(_instance->logger, RLOG_LV_INFO, "TSG_SEND_LOG", "Disable tsg_send_log.");
		return 0;
	}
	
	TLD_append_streaminfo(instance, handle, log_msg->a_stream);
	TLD_append(_handle, _instance->id2field[LOG_COMMON_SLED_IP].name, (void *)(_instance->local_ip_str), TLD_TYPE_STRING);
	if(strlen(g_tsg_para.device_sn)>0)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_DEVICE_ID].name, (void *)(g_tsg_para.device_sn), TLD_TYPE_STRING);
	}

	if(strlen(g_tsg_para.data_center)>0)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_DATA_CENTER].name, (void *)(g_tsg_para.data_center), TLD_TYPE_STRING);
	}
	
	for(i=0;i<log_msg->result_num; i++)
	{
		if(is_multi_hit_same_policy(&(log_msg->result[i]), policy_id, &repeat_cnt))
		{
			MESA_handle_runtime_log(_instance->logger, RLOG_LV_DEBUG,
										"TSG_SEND_LOG",
										"tsg same log:cfg_id=%d service=%d addr=%s",
										log_msg->result[i].config_id,
										log_msg->result[i].service_id,
										(log_msg->a_stream==NULL ? "" : PRINTADDR(log_msg->a_stream,_instance->level))
									);
			continue;
		}

		clock_gettime(CLOCK_REALTIME, &cur_time);
		if((cur_time.tv_nsec%100)>_instance->send_log_percent[thread_id])
		{			
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_DROP_LOG], 0, FS_OP_ADD, 1);
			MESA_handle_runtime_log(_instance->logger, RLOG_LV_INFO,
										"TSG_SEND_LOG",
										"tsg drop log:cfg_id=%d service=%d send_log_percent: %d addr=%s",
										log_msg->result[i].config_id,
										log_msg->result[i].service_id,
										_instance->send_log_percent[thread_id],
										(log_msg->a_stream==NULL ? "" : PRINTADDR(log_msg->a_stream,_instance->level))
									);
			continue;
		}
		
		switch(log_msg->result[i].do_log)
		{
			case	LOG_ABORT:
				MESA_handle_runtime_log(_instance->logger, RLOG_LV_INFO,
											"TSG_SEND_LOG",
											"tsg abort log:cfg_id=%d service=%d addr=%s",
											log_msg->result[i].config_id,
											log_msg->result[i].service_id,
											(log_msg->a_stream==NULL ? "" : PRINTADDR(log_msg->a_stream,_instance->level))
										);

				fs_id=action2fs_id((int)log_msg->result[i].action);
				FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[fs_id], 0, FS_OP_ADD, 1);
				continue;
				break;
			case	LOG_ALL:
				break;
			case	LOG_NOFILE:
				break;
			default:
				break;
		}

		TLD_append(_handle, _instance->id2field[LOG_COMMON_POLICY_ID].name, (void *)(long)(log_msg->result[i].config_id), TLD_TYPE_LONG);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_SERVICE].name, (void *)(long)(log_msg->result[i].service_id), TLD_TYPE_LONG);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_ACTION].name, (void *)(long)((unsigned char)log_msg->result[i].action), TLD_TYPE_LONG);

		if(_instance->send_user_region==1 && log_msg->result[i].action!=TSG_ACTION_NONE && log_msg->result[i].serv_def_len>0)
		{
			user_agent=(char *)dictator_malloc(thread_id, log_msg->result[i].serv_def_len+1);
			ret=Maat_read_rule(g_tsg_maat_feather, &(log_msg->result[i]), MAAT_RULE_SERV_DEFINE, user_agent, log_msg->result[i].serv_def_len+1);
			if(ret==log_msg->result[i].serv_def_len)
			{
				user_agent[log_msg->result[i].serv_def_len]='\0';
				TLD_append(_handle, _instance->id2field[LOG_COMMON_USER_REGION].name, (void *)user_agent, TLD_TYPE_STRING);
			}

			dictator_free(thread_id, user_agent);
			user_agent=NULL;
		}
		
		if(log_msg->result[i].action==TSG_ACTION_DENY)
		{
			set_common_sub_action(_handle, _instance->id2field[LOG_COMMON_SUB_ACTION].name, &(log_msg->result[i]));
		}
		
		payload=cJSON_PrintUnformatted(_handle->object);

		status=rd_kafka_produce(_instance->topic_rkt[log_msg->result[i].service_id], RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY, payload, strlen(payload), NULL, 0, NULL);
		if(status<0)
		{
			clock_gettime(CLOCK_REALTIME, &cur_time);
			if(cur_time.tv_sec - _instance->drop_start[thread_id].tv_sec>=1)
			{	
				_instance->send_log_percent[thread_id]/=2;
				clock_gettime(CLOCK_REALTIME, &_instance->drop_start[thread_id]);
				FS_operate(g_tsg_para.fs2_handle, _instance->fs_status_ids[thread_id], 0, FS_OP_SET, _instance->send_log_percent[thread_id]);
			}
			
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_FAILED_LOG], 0, FS_OP_ADD, 1);
			
			MESA_handle_runtime_log(_instance->logger, 
										RLOG_LV_INFO, 
										"TSG_SEND_LOG",
										"tsg_send_log to kafka is error of %s(%s), status: %d, topic: %s payload: %s",
										rd_kafka_err2name(rd_kafka_last_error()),
										rd_kafka_err2str(rd_kafka_last_error()),
										status,
										_instance->service2topic[log_msg->result[i].service_id].name,
										payload
									);
		}
		else
		{
			MESA_handle_runtime_log(_instance->logger,
										RLOG_LV_DEBUG,
										"TSG_SEND_LOG", 
										"log send successfully %s: %s",
										_instance->service2topic[log_msg->result[i].service_id].name,
										payload
									);
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_SUCCESS_LOG], 0, FS_OP_ADD, 1);		
			FS_operate(g_tsg_para.fs2_handle, _instance->fs_status_ids[thread_id], 0, FS_OP_SET, _instance->send_log_percent[thread_id]);
		}

		cJSON_free(payload);
		payload=NULL;

		TLD_delete(_handle, _instance->id2field[LOG_COMMON_POLICY_ID].name);
		TLD_delete(_handle, _instance->id2field[LOG_COMMON_SERVICE].name);
		TLD_delete(_handle, _instance->id2field[LOG_COMMON_ACTION].name);
		TLD_delete(_handle, _instance->id2field[LOG_COMMON_USER_REGION].name);
		TLD_delete(_handle, _instance->id2field[LOG_COMMON_SUB_ACTION].name);
	}

	TLD_cancel(handle);

	if(_instance->send_log_percent[thread_id]<100)
	{
		clock_gettime(CLOCK_REALTIME, &cur_time);
		if(cur_time.tv_sec - _instance->drop_start[thread_id].tv_sec>=_instance->recovery_interval)
		{
			_instance->send_log_percent[thread_id]++;
			_instance->drop_start[thread_id].tv_sec=cur_time.tv_sec;						
			FS_operate(g_tsg_para.fs2_handle, _instance->fs_status_ids[thread_id], 0, FS_OP_SET, _instance->send_log_percent[thread_id]);
		}
	}

	return 0;
}

