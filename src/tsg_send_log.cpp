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

#include "tsg_log.h"
#include "tsg_stat.h"
#include "app_label.h"
#include "tsg_entry.h"
#include "tsg_bridge.h"
#include "tsg_send_log.h"
#include "tsg_sync_state.h"
#include "tsg_rule_internal.h"
#include "tsg_send_log_internal.h"

#include "rapidjson/document.h"     // rapidjson's DOM-style API
#include "rapidjson/prettywriter.h" // for stringify JSON
#include "rapidjson/stringbuffer.h"

#ifndef MIN
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
#endif

using namespace rapidjson;
using namespace std;

struct tsg_log_instance_t *g_tsg_log_instance;

struct TLD_handle_t
{
	int thread_id;
	MemoryPoolAllocator<> *valueAllocator;
	Document *document;
};

const id2field_t tld_type[TLD_TYPE_MAX]={{TLD_TYPE_UNKNOWN,	TLD_TYPE_UNKNOWN, 	"UNKOWN"},
								 			{TLD_TYPE_LONG, 	TLD_TYPE_LONG,		"LONG"},
								 			{TLD_TYPE_STRING, 	TLD_TYPE_STRING, 	"STRING"},
											{TLD_TYPE_FILE,		TLD_TYPE_FILE,		"FILE"},
											{TLD_TYPE_TOPIC,	TLD_TYPE_TOPIC,		"TOPIC"}
										   };

extern "C" int MESA_get_dev_ipv4(const char *device, int *ip_add);

static int string_cat(char *dst, int dst_len, char *src)
{
	if(dst==NULL || dst_len<=0 || src==NULL)
	{
		return 0;
	}

	return snprintf(dst, dst_len, "%s", src);
}

#define add_number_member   add_member
#define add_object_member   add_member

#define add_member(handle, object, key, val)                                      \
    {                                                                             \
        Value temp_key;                                                           \
        temp_key.SetString((key), (handle)->document->GetAllocator());            \
        (object)->AddMember(temp_key, (val), (handle)->document->GetAllocator()); \
    }

static int copy_rapidjson(struct TLD_handle_t *_handle, char *field_name, const char *json_string)
{
	Document nest_document;
	nest_document.Parse(json_string);

	Value p_object(kObjectType);
	p_object.CopyFrom(nest_document, _handle->document->GetAllocator());

	TLD_append(_handle, field_name, (void *)&p_object, TLD_TYPE_OBJECT);

	return 0;
}

static void add_str_member(struct TLD_handle_t *_handle, Value *object, const char *key, const char *val)
{
	Value temp_key;
	Value temp_val;
	temp_key.SetString(key, _handle->document->GetAllocator());
	temp_val.SetString(val, _handle->document->GetAllocator());
	object->AddMember(temp_key, temp_val, _handle->document->GetAllocator());
}


static int register_topic(struct tsg_log_instance_t *instance, struct topic_stat *topic)
{
	rd_kafka_topic_conf_t *topic_conf;
	struct tsg_log_instance_t *_instance=(struct tsg_log_instance_t *)instance;

	topic_conf=rd_kafka_topic_conf_new();
	topic->status=1;
	//topic->topic_rkt=(rd_kafka_topic_t *)calloc(1, sizeof(rd_kafka_topic_t*));
	topic->topic_rkt=rd_kafka_topic_new(_instance->kafka_handle, topic->name, topic_conf);

	int thread_num=get_thread_count();
	topic->drop_start=(long long *)calloc(thread_num, sizeof(long long));
	topic->send_log_percent=(int *)calloc(thread_num, sizeof(int));
	
	for(int i=0; i<thread_num; i++)
	{
		topic->send_log_percent[i]=100;
		topic->drop_start[i]=tsg_get_current_time_ms();
	}
	
	topic->row_idx=tsg_stat_sendlog_row_init((const char *)(topic->name));

	return 1;
}


static int update_percent(struct tsg_log_instance_t *_instance, int service_id, enum LOG_STATUS column, int thread_id)
{
	long long current_time_ms=tsg_get_current_time_ms();
	struct topic_stat *topic=(struct topic_stat *)&(_instance->service2topic[service_id]);

	switch(column)
	{
		case	LOG_STATUS_SUCCESS:
			tsg_stat_sendlog_update(topic->row_idx, column, 1);
			//tsg_stat_sendlog_update(topic->row_idx, column+1, 1);

			tsg_stat_sendlog_update(_instance->sum_stat_row_id, column, 1);
			//tsg_stat_sendlog_update(_instance->sum_stat_row_id, column+1, 1);
			break;
		case	LOG_STATUS_FAIL:
			tsg_stat_sendlog_update(topic->row_idx, column, 1);
			//tsg_stat_sendlog_update(topic->row_idx, column+1, 1);

			tsg_stat_sendlog_update(_instance->sum_stat_row_id, column, 1);
			//tsg_stat_sendlog_update(_instance->sum_stat_row_id, column+1, 1);

			if(current_time_ms - topic->drop_start[thread_id]>=1000)
			{	
				topic->send_log_percent[thread_id]/=2;
				topic->drop_start[thread_id]=current_time_ms;
			}
			break;
		case	LOG_STATUS_DROP:
			if((current_time_ms%100) > topic->send_log_percent[thread_id])
			{
				tsg_stat_sendlog_update(topic->row_idx, column, 1);
				//tsg_stat_sendlog_update(topic->row_idx, column+1, 1);

				tsg_stat_sendlog_update(_instance->sum_stat_row_id, column, 1);
				//tsg_stat_sendlog_update(_instance->sum_stat_row_id, column+1, 1);

				return 1;
			}
			break;
		case	LOG_STATUS_MAX:
			if(topic->send_log_percent[thread_id]>=100)
			{
				break;
			}
			
			if((current_time_ms - topic->drop_start[thread_id]) >= _instance->recovery_interval*1000)
			{
				topic->send_log_percent[thread_id]++;
				topic->drop_start[thread_id]=current_time_ms;
			}
			break;
		default:
			break;
	}

	return 0;
}

static int is_tunnels(const struct streaminfo *a_stream)
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

static int set_isn(const struct streaminfo *a_stream, struct TLD_handle_t *_handle, char *field_name, enum MESA_stream_opt type)
{
	unsigned int isn=0;
	int size=sizeof(isn);
	int ret=MESA_get_stream_opt(a_stream, type, &isn, &size);
	if(ret==0)
	{		
		TLD_append(_handle, field_name, (void *)(long)isn, TLD_TYPE_LONG);
	}

	return 1;
}

static int set_tcp_isn(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
{
	if(a_stream->type==STREAM_TYPE_TCP)
	{
		switch(a_stream->dir)
		{
			case	DIR_C2S:
				set_isn(a_stream, _handle, _instance->id2field[LOG_COMMON_TCP_CLIENT_ISN].name, MSO_TCP_ISN_C2S);
				break;
			case	DIR_S2C:
				set_isn(a_stream, _handle, _instance->id2field[LOG_COMMON_TCP_SERVER_ISN].name, MSO_TCP_ISN_S2C);
				break;
			case	DIR_DOUBLE:
				set_isn(a_stream, _handle, _instance->id2field[LOG_COMMON_TCP_CLIENT_ISN].name, MSO_TCP_ISN_C2S);
				set_isn(a_stream, _handle, _instance->id2field[LOG_COMMON_TCP_SERVER_ISN].name, MSO_TCP_ISN_S2C);
				break;
			default:
				break;
		}
	}
	
	return 1;
}

static int set_linkinfo(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
{
	const char *linkinfo=(const char *)session_mac_linkinfo_get(a_stream);
	if(linkinfo==NULL)
	{
		return 0;
	}

	cJSON *item=NULL;
	cJSON *object=cJSON_Parse(linkinfo);
	if(object)
	{
		item=cJSON_GetObjectItem(object, "common_direction");
		if(item!=NULL)
		{			
			TLD_append(_handle, (char *)"common_direction", (void *)(long)(item->valueint), TLD_TYPE_LONG);
		}
		
		item=cJSON_GetObjectItem(object, "common_egress_link_id");
		if(item!=NULL)
		{			
			TLD_append(_handle, (char *)"common_egress_link_id", (void *)(long)(item->valueint), TLD_TYPE_LONG);
		}
		
		item=cJSON_GetObjectItem(object, "common_ingress_link_id");
		if(item!=NULL)
		{			
			TLD_append(_handle, (char *)"common_ingress_link_id", (void *)(long)(item->valueint), TLD_TYPE_LONG);
		}

		cJSON_Delete(object);
		object=NULL;
		
		return 1;
	}
	
	return 0;
}

static int set_asn(struct TLD_handle_t *_handle, const struct streaminfo *a_stream, char *field_name, struct asn_info *asn_info)
{	
	if(asn_info!=NULL)
	{
		int len=0;
		char buff[1024]={0};
		int buff_len=sizeof(buff);

		len+=string_cat(buff+len, buff_len-len, asn_info->asn_id);
		buff[len++]='(';
		len+=string_cat(buff+len, buff_len-len, asn_info->organization);
		buff[len++]=')';
		TLD_append(_handle, field_name, (void *)buff, TLD_TYPE_STRING);
	}

	return 1;
}

static int set_location(struct TLD_handle_t *_handle,  const struct streaminfo *a_stream, char *field_name, struct location_info *location_info)
{
	if(location_info==NULL || location_info->full_location==NULL || location_info->full_location_len<=0)
	{
		return 0;
	}
	
	char location[1024]={0};

	memcpy(location, location_info->full_location, MIN((int)sizeof(location), location_info->full_location_len-1));
	TLD_append(_handle, field_name, (void *)location, TLD_TYPE_STRING);

	return 1;
}

static int set_direction(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle,  const struct streaminfo *a_stream)
{
	const struct session_runtime_action_context *srt_action_context=session_runtime_action_context_get(a_stream);
	if(srt_action_context==NULL)
	{
		return 0;
	}
	
	char direction=srt_action_context_get_direction(srt_action_context);
	if(direction>0)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_DIRECTION].name, (void *)(long)direction, TLD_TYPE_LONG);	
		return 1;
	}
	
	return 0;
}

static int set_address_list(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
{
	unsigned short tunnel_type=0;
	char nest_addr_buf[1024]={0};
	int tunnel_type_size=sizeof(tunnel_type);
	
	MESA_get_stream_opt(a_stream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &tunnel_type_size);
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

static int set_tuple4(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
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

static int set_duraction(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
{
	long common_con_duration_ms=0;
	int size=sizeof(unsigned long long);
	unsigned long long create_time=0,last_time=0;

	if(a_stream->ptcpdetail!=NULL)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_START_TIME].name, (void *)(a_stream->ptcpdetail->createtime), TLD_TYPE_LONG);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_END_TIME].name, (void *)(a_stream->ptcpdetail->lastmtime), TLD_TYPE_LONG);

		int ret=MESA_get_stream_opt(a_stream, MSO_STREAM_CREATE_TIMESTAMP_MS, (void *)&create_time, &size);
		if(ret>=0)
		{
			ret=MESA_get_stream_opt(a_stream, MSO_STREAM_LASTUPDATE_TIMESTAMP_MS, (void *)&last_time, &size);
			if(ret>=0 && last_time>create_time)
			{
				common_con_duration_ms=last_time-create_time;			
				TLD_append(_handle, _instance->id2field[LOG_COMMON_CON_DURATION_MS].name, (void *)(common_con_duration_ms), TLD_TYPE_LONG);
			}
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

static int set_subscriber_id(struct TLD_handle_t *_handle, char *field_name, struct subscribe_id_info *subscriber)
{
	if(subscriber!=NULL && subscriber->subscribe_id!=NULL)
	{		
		TLD_append(_handle, field_name, (void *)subscriber->subscribe_id, TLD_TYPE_STRING);
		return 1;
	}
	
	return 0;
}

static int set_fqdn_category(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream, unsigned int *category_id, int category_id_num)
{
	int i=0;
	if(category_id_num<=0 || category_id==NULL)
	{
		return 0;
	}
	
	Value array(kArrayType);
	for(i=0; i<category_id_num; i++)
	{
		array.PushBack(category_id[i], _handle->document->GetAllocator());
	}

	TLD_append(_handle, _instance->id2field[LOG_COMMON_FQDN_CATEGORY].name, &array, TLD_TYPE_OBJECT);

	return 1;
}

static int set_umts_user_info(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream, struct umts_user_info *user_info)
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

static int set_packet_bytes(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
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

int set_app_identify_info_array(Value *array, struct TLD_handle_t *_handle, struct app_attributes *result, char result_num)
{
	for(int i=0; i<result_num; i++)
	{
		char app_name[512]={0};
		Value object(kObjectType);
		int ret=tsg_get_app_name_by_id(g_tsg_maat_feather, result[i].app_id, app_name, sizeof(app_name), 0);
		if(ret>0)
		{
			add_str_member(_handle, &object, "app_name", app_name);
		}
		else
		{
			object.AddMember("app_name", result[i].app_id, _handle->document->GetAllocator());
		}
		object.AddMember("packet_sequence",result[i].packet_sequence, _handle->document->GetAllocator());
		array->PushBack(object, _handle->document->GetAllocator());
	}

	return result_num;
}

static int set_app_identify_info(struct TLD_handle_t *_handle, char *field_name, struct gather_app_result * gather_result)
{
	if(gather_result->user_define_num<=0 && gather_result->built_in_num<=0 && gather_result->unknown_flag==0)
	{
		return 0;
	}
	
	Value array(kArrayType);
	set_app_identify_info_array(&array, _handle, gather_result->user_define, gather_result->user_define_num);
	set_app_identify_info_array(&array, _handle, gather_result->built_in, gather_result->built_in_num);

	if(gather_result->unknown_flag==1)
	{
		set_app_identify_info_array(&array, _handle, &gather_result->unknown, 1);
	}
	
	TLD_append(_handle, field_name, &array, TLD_TYPE_OBJECT);
	
	return 1;
}

static int get_app_id_list(Value *app_id_object, struct TLD_handle_t *_handle, const char *field_name, struct app_attributes *result, char result_num)
{
	if(result_num==0)
	{
		return 0;
	}
	
	Value array(kArrayType);
	for(int i=0; i<result_num; i++)
	{	
		char app_name[512]={0};
		Value object(kObjectType);
		int ret=tsg_get_app_name_by_id(g_tsg_maat_feather, result[i].app_id, app_name, sizeof(app_name), 1);
		if(ret>0)
		{		
			add_str_member(_handle, &object, "app_name", app_name);
		}
		object.AddMember("app_id", result[i].app_id, _handle->document->GetAllocator());
		object.AddMember("surrogate_id", result[i].surrogate_id, _handle->document->GetAllocator());
		object.AddMember("packet_sequence",result[i].packet_sequence, _handle->document->GetAllocator());
		array.PushBack(object, _handle->document->GetAllocator());
	}
	add_object_member(_handle, app_id_object, field_name, array);

	return 1;
}


static int set_userdefine_app(struct TLD_handle_t *_handle, char *field_name, struct app_attributes *result, char result_num)
{
	if(result==NULL || result_num<=0)
	{
		return 0;
	}
	
	int i=0;
	char app_name[256]={0};
	
	Value array(kArrayType);
	for(i=0; i<result_num; i++)
	{
		memset(app_name, 0, sizeof(app_name));
		tsg_get_app_name_by_id(g_tsg_maat_feather, result[i].app_id, app_name, sizeof(app_name), 1);
		if(strnlen(app_name, sizeof(app_name)) > 0)
		{
			Value app_name_str;
			app_name_str.SetString(app_name, _handle->document->GetAllocator());
			array.PushBack(app_name_str, _handle->document->GetAllocator());
		}
	}

	TLD_append(_handle, field_name, &array, TLD_TYPE_OBJECT);

	return 1;
}

int set_app_id(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
{
	struct gather_app_result *gather_result=(struct gather_app_result *)session_gather_app_results_get(a_stream);
	if(gather_result==NULL)
	{	
		char app_name[512]={0};
		if(tsg_get_app_name_by_id(g_tsg_maat_feather, _instance->unknown_app_id, app_name, sizeof(app_name), 0))
		{
			TLD_append(_handle, _instance->id2field[LOG_COMMON_APP_FULL_PATH].name, (void *)app_name, TLD_TYPE_STRING);
			TLD_append(_handle, _instance->id2field[LOG_COMMON_APP_LABEL].name, (void *)app_name, TLD_TYPE_STRING);
		}
		
		return 0;
	}

	set_userdefine_app(_handle, _instance->id2field[LOG_COMMON_USERDEFINE_APP].name, gather_result->user_define, gather_result->user_define_num);

	char app_full_path[256]={0};
	session_application_full_path_update(a_stream, app_full_path, sizeof(app_full_path));

	TLD_append(_handle, _instance->id2field[LOG_COMMON_APP_FULL_PATH].name, (void *)app_full_path, TLD_TYPE_STRING);
	char *app_label=rindex(app_full_path, '.');
	if(app_label!=NULL)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_APP_LABEL].name, (void *)(app_label+1), TLD_TYPE_STRING);
	}
	else
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_APP_LABEL].name, (void *)app_full_path, TLD_TYPE_STRING);
	}
	
	set_app_identify_info(_handle, _instance->id2field[LOG_COMMON_APP_IDENTIFY_INFO].name, gather_result);

	if(_instance->send_app_id)
	{
		Value app_id_object(kObjectType);
		get_app_id_list(&app_id_object, _handle, "LPI_L7", gather_result->l7_protocol,  gather_result->l7_protocol_num);
		get_app_id_list(&app_id_object, _handle, "USER_DEFINE", gather_result->user_define,  gather_result->user_define_num);
		get_app_id_list(&app_id_object, _handle, "BUILT_IN", gather_result->built_in,  gather_result->built_in_num);

		get_app_id_list(&app_id_object, _handle, "QM_L7", gather_result->qm_engine, gather_result->l7_qm_engine_num);
		get_app_id_list(&app_id_object, _handle, "THIRD", gather_result->qm_engine+gather_result->l7_qm_engine_num,  gather_result->qm_engine_num-gather_result->l7_qm_engine_num);
			
		if(gather_result->matched_app_flag==1)
		{
			get_app_id_list(&app_id_object, _handle, "HITED_APP", &(gather_result->matched_app), 1);
		}
		if(gather_result->unknown_flag==1)
		{
			get_app_id_list(&app_id_object, _handle, "UNKNOWN", &(gather_result->unknown), 1);
		}
		
		TLD_append(_handle, _instance->id2field[LOG_COMMON_APP_ID].name, &app_id_object, TLD_TYPE_OBJECT);
	}
	
	return 1;
}

int set_vlan(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct single_layer_vlan_addr *vlan_addr, int layer_num, Value *tunnel_object, enum LOG_FIELD_ID id)
{
	if(layer_num==0)
	{
		return 0;
	}
	
	int i=0;
	Value vlan_array(kArrayType);
	for(i=0; i<layer_num; i++)
	{
		vlan_array.PushBack(ntohs(vlan_addr[i].VID), _handle->document->GetAllocator());
	}
	add_object_member(_handle, tunnel_object, _instance->id2field[id].name, vlan_array);

	return 1;
}

static int set_mpls(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct single_layer_mpls_addr *mpls_addr, int layer_num, Value *tunnel_object, enum LOG_FIELD_ID id)
{
	if(layer_num==0)
	{
		return 0;
	}

	int i=0;
	Value mpls_array(kArrayType);
	for(i=0; i<layer_num; i++)
	{
		mpls_array.PushBack(ntohl(mpls_addr[i].label), _handle->document->GetAllocator());
	}
	add_object_member(_handle, tunnel_object, _instance->id2field[id].name, mpls_array);

	return 1;
}

static int set_l2tp(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct layer_addr_l2tp *l2tp_addr, Value *object)
{
	if(l2tp_addr==NULL || object==NULL)
	{
		return 0;
	}

	struct layer_addr_l2tp_v2_t *l2tp_v2=NULL;
	
	switch(l2tp_addr->version)
	{
		case	2:
			l2tp_v2=&(l2tp_addr->l2tpun.l2tp_addr_v2);			
			add_str_member(_handle, object, _instance->id2field[LOG_COMMON_L2TP_VERSION].name, "v2");
			add_number_member(_handle, object, _instance->id2field[LOG_COMMON_L2TP_LAC2LNS_TUNNEL_ID].name, ntohs(l2tp_v2->tunnelid_C2S));			
			add_number_member(_handle, object, _instance->id2field[LOG_COMMON_L2TP_LNS2LAC_TUNNEL_ID].name, ntohs(l2tp_v2->tunnelid_S2C));
			add_number_member(_handle, object, _instance->id2field[LOG_COMMON_L2TP_LAC2LNS_SESSION_ID].name, ntohs(l2tp_v2->sessionid_C2S));			
			add_number_member(_handle, object, _instance->id2field[LOG_COMMON_L2TP_LNS2LAC_SESSION_ID].name, ntohs(l2tp_v2->sessionid_S2C));
			break;
		case	3:
			add_str_member(_handle, object, _instance->id2field[LOG_COMMON_L2TP_VERSION].name, "v3");
			break;
		default:
			return 0;	
	}
	
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

static int set_link_mac(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct layer_addr_mac *mac, Value *tunnel_object)
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
			add_str_member(_handle, tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "ETHERNET");
			add_str_member(_handle, tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_MAC_SOURCE].name, c2s_source_mac);
			add_str_member(_handle, tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_MAC_DEST].name, c2s_dest_mac);
			break;
		case	2:
			add_str_member(_handle, tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "ETHERNET");
			add_str_member(_handle, tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_MAC_SOURCE].name, s2c_source_mac);
			add_str_member(_handle, tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_MAC_DEST].name, s2c_dest_mac);
			break;
		case	3:
			add_str_member(_handle, tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "MULTIPATH_ETHERNET");
			add_str_member(_handle, tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_C2S_MAC_SOURCE].name, c2s_source_mac);
			add_str_member(_handle, tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_C2S_MAC_DEST].name, c2s_dest_mac);
			add_str_member(_handle, tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_S2C_MAC_SOURCE].name, s2c_source_mac);
			add_str_member(_handle, tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_S2C_MAC_DEST].name, s2c_dest_mac);
			break;
		default:
			break;
	}
	
	return 1;
}

enum RULE_STAT
{
	RULE_STAT_ABORT=0,
	RULE_STAT_SEND
};

static void fs3_rule_stat_update(enum RULE_STAT stat_type, int action, long long increase)
{
	enum RULE_TYPE rule_type=RULE_TYPE_UNKNOW;
	
	switch(action)
	{
		case	TSG_ACTION_DENY:
			rule_type=RULE_TYPE_DENY; break;
		case	TSG_ACTION_BYPASS:
			rule_type=RULE_TYPE_ALLOW; break;
		case	TSG_ACTION_MONITOR:
			rule_type=RULE_TYPE_MONITOR; break;
		case	TSG_ACTION_INTERCEPT:
			rule_type=RULE_TYPE_INTERCEPT; break;
		case	TSG_ACTION_NO_INTERCEPT:
			rule_type=RULE_TYPE_NO_INTERCEPT; break;
		case	TSG_ACTION_S_CHAINING:
			rule_type=RULE_TYPE_SERVICE_CHAINING; break;
		case	TSG_ACTION_SHAPING:
			rule_type=RULE_TYPE_SHAPING; break;
		case	TSG_ACTION_SHUNT:
			rule_type=RULE_TYPE_SHUNT; break;
		default:
			rule_type=RULE_TYPE_UNKNOW; break;
	}

	switch(stat_type)
	{
		case	RULE_STAT_ABORT:
			tsg_stat_abort_rule_update(rule_type, increase);
			break;
		case	RULE_STAT_SEND:
			tsg_stat_send_rule_update(rule_type, increase);
			break;
		default:
			break;
	}
}

int TLD_cancel(struct TLD_handle_t *handle)
{
	if (handle != NULL)
	{
		if (handle->document != NULL)
		{		
			long long length=0;
			
			length=handle->document->GetAllocator().Size();
			tsg_stat_log_handle_update(LOG_HANDLE_FREE_SIZE, length);

			length=handle->document->GetAllocator().Capacity();
			tsg_stat_log_handle_update(LOG_HANDLE_FREE_CAPACITY, length);
			
			delete handle->document;
			handle->document = NULL;

			delete handle->valueAllocator;
			handle->valueAllocator=NULL;

			tsg_stat_log_handle_update(LOG_HANDLE_FREE_CNT, 1);
		}
		
		free(handle);
		handle = NULL;
	}
	
	return 0;
}

int TLD_search(struct TLD_handle_t *handle, char *key)
{
	if (handle != NULL && handle->document != NULL && key != NULL)
	{
		Value::ConstMemberIterator itr = handle->document->FindMember(key);
		if (itr!=handle->document->MemberEnd())
		{
			return 1;
		}
	}

	return 0;
}

static void TLD_delete(struct TLD_handle_t *handle, char *key)
{
	if (handle != NULL && handle->document != NULL && key != NULL)
	{
		handle->document->RemoveMember(key);
	}
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
			add_number_member(_handle, _handle->document, key, (long)value);
			break;
		case	TLD_TYPE_FILE:
			break;
		case	TLD_TYPE_STRING:
			if(strlen((char *)value)==0)
			{
				break;
			}
			add_str_member(_handle, _handle->document, key, (const char *)value);
			break;
		case	TLD_TYPE_OBJECT:
			add_object_member(handle, handle->document, key, ((Value &)(*(Value *)value)));
			break;
		case	TLD_TYPE_CJSON:
			printf("TLD_TYPE_CJSON is obsolete, please use TLD_TYPE_OBJECT !!!\n");
			abort();
		default:
			return -1;
			break;
	}

	tsg_stat_log_handle_update(LOG_HANDLE_APPEND_CNT, 1);

	return 0;
}

int TLD_array_append(struct TLD_handle_t *handle, char *key, void **array, int array_num, TLD_TYPE type)
{
	if(handle==NULL || key==NULL ||  array_num<=0 || array==NULL || (type!=TLD_TYPE_LONG && type!=TLD_TYPE_STRING))
	{
		return -1;
	}

	int i=0;
	Value obj_array(kArrayType);

	switch(type)
	{
	case    TLD_TYPE_LONG:
		for(i=0; i<array_num; i++)
		{
			obj_array.PushBack((long)(array[i]), handle->document->GetAllocator());
		}
		break;
	case    TLD_TYPE_STRING:
		for(i=0; i<array_num; i++)
		{
			Value str_value((const char *)(array[i]), handle->document->GetAllocator());
			obj_array.PushBack(str_value, handle->document->GetAllocator());
		}
		break;
	default:
		return -1;
	}

	add_object_member(handle, handle->document, key, obj_array);

	return 1;
}

struct TLD_handle_t *TLD_duplicate(struct TLD_handle_t *handle)
{
	if (handle == NULL)
	{
		return NULL;
	}
	struct TLD_handle_t *_handle=(struct TLD_handle_t *)calloc(1, sizeof(struct TLD_handle_t));
	_handle->thread_id = handle->thread_id;
	_handle->document = new Document();
	//_handle->document->SetObject();

	_handle->document->CopyFrom(*handle->document, _handle->document->GetAllocator());

	tsg_stat_log_handle_update(LOG_HANDLE_DUP_CNT, 1);

	return _handle;
}

struct TLD_handle_t *TLD_create(int thread_id)
{
	if(g_tsg_log_instance->mode==CLOSE)
	{
		return NULL;
	}
	
	struct TLD_handle_t *_handle=(struct TLD_handle_t *)calloc(1, sizeof(struct TLD_handle_t));
	_handle->thread_id = thread_id;
	
	_handle->valueAllocator =new MemoryPoolAllocator<>(g_tsg_log_instance->rapidjson_chunk_capacity);
	_handle->document = new Document(_handle->valueAllocator);
	_handle->document->SetObject();

	

	return _handle;
}

int TLD_convert_json(struct TLD_handle_t *_handle, char *buff, unsigned int buff_len)
{
	StringBuffer sb(0, 2048);
	Writer<StringBuffer> writer(sb);
	_handle->document->Accept(writer);

	memcpy(buff, sb.GetString(), MIN(sb.GetSize(), buff_len));
	
	return 1;
}

static int set_mail_eml(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
{
	struct tsg_conn_sketch_notify_data *notify_mail=(struct tsg_conn_sketch_notify_data *)session_conn_sketch_notify_data_get(a_stream);
	if(notify_mail!=NULL && notify_mail->pdata.mail_eml_filename!=NULL && notify_mail->protocol==PROTO_MAIL)
	{
		TLD_delete(_handle, _instance->id2field[LOG_COMMON_MAIL_EML_FILE].name);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_MAIL_EML_FILE].name, (void *)notify_mail->pdata.mail_eml_filename, TLD_TYPE_STRING);
		return 1;
	}

	return 0;
}

static int set_s3_filename(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
{
	struct business_notify_data *bnd_label=(struct business_notify_data *)session_business_data_get(a_stream);
	if(bnd_label==NULL || bnd_label->pdata==NULL)
	{
		return 0;
	}
	
	switch(bnd_label->proto)
	{
		case	PROTO_HTTP:
			TLD_delete(_handle, _instance->id2field[LOG_COMMON_HTTP_REQUEST_S3_FILE].name);
			TLD_delete(_handle, _instance->id2field[LOG_COMMON_HTTP_RESPONSE_S3_FILE].name);

			if(bnd_label->s3_http==NULL)
			{
				break;
			}

			TLD_append(_handle, _instance->id2field[LOG_COMMON_HTTP_REQUEST_S3_FILE].name, bnd_label->s3_http->request_filename, TLD_TYPE_STRING);
			TLD_append(_handle, _instance->id2field[LOG_COMMON_HTTP_RESPONSE_S3_FILE].name, bnd_label->s3_http->response_filename, TLD_TYPE_STRING);
			break;
		default:
			break;
	}

	return 1;
}

int set_nat_linkinfo(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
{
	if(_instance->send_nat_linkinfo==0 || a_stream==NULL)
	{
		return 0;
	}

	char *c2s_linkinfo=(char *)session_nat_c2s_linkinfo_get(a_stream);
	if(c2s_linkinfo!=NULL)
	{
		copy_rapidjson(_handle, _instance->id2field[LOG_COMMON_LINK_INFO_C2S].name, c2s_linkinfo);
	}
		
	char *s2c_linkinfo=(char *)session_nat_s2c_linkinfo_get(a_stream);
	if(s2c_linkinfo!=NULL)
	{
		copy_rapidjson(_handle, _instance->id2field[LOG_COMMON_LINK_INFO_S2C].name, s2c_linkinfo);
	}

	return 1;
}

static int set_tunnel_ipv4v6_port(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream, Value *object, enum addr_type_t up_layer_type)
{
	char ip_buff[64]={0};
	if(a_stream==NULL)
	{		
		return 0;
	}

	enum LOG_FIELD_ID s_ip_idx, d_ip_idx, s_port_idx, d_port_idx;

	switch(up_layer_type)
	{
		case	ADDR_TYPE_L2TP:
			s_ip_idx=LOG_COMMON_L2TP_ACCESS_CONCENTRATOR_IP;
			d_ip_idx=LOG_COMMON_L2TP_NETWORK_SERVER_IP;
			s_port_idx=LOG_COMMON_L2TP_ACCESS_CONCENTRATOR_PORT;
			d_port_idx=LOG_COMMON_L2TP_NETWORK_SERVER_PORT;
			break;
		case	ADDR_TYPE_GPRS_TUNNEL:
			s_ip_idx=LOG_COMMON_TUNNELS_GTP_SGW_IP;
			d_ip_idx=LOG_COMMON_TUNNELS_GTP_PGW_IP;
			s_port_idx=LOG_COMMON_TUNNELS_GTP_SGW_PORT;
			d_port_idx=LOG_COMMON_TUNNELS_GTP_PGW_PORT;			
			break;
		default:
			return 0;
			break;
	}
		
	switch(a_stream->addr.addrtype)
	{
		case	ADDR_TYPE_IPV4:
				inet_ntop(AF_INET, (const void *)&(a_stream->addr.ipv4->saddr), ip_buff, sizeof(ip_buff));
				add_str_member(_handle, object, _instance->id2field[s_ip_idx].name, ip_buff);

				inet_ntop(AF_INET, (const void *)&(a_stream->addr.ipv4->daddr), ip_buff, sizeof(ip_buff));	
				add_str_member(_handle, object, _instance->id2field[d_ip_idx].name, ip_buff);
				
				add_number_member(_handle, object, _instance->id2field[s_port_idx].name, ntohs(a_stream->addr.ipv4->source));
				add_number_member(_handle, object, _instance->id2field[d_port_idx].name, ntohs(a_stream->addr.ipv4->dest));
				return 1;
			break;
		case	ADDR_TYPE_IPV6:
				inet_ntop(AF_INET6, (const void *)(a_stream->addr.ipv6->saddr), ip_buff, sizeof(ip_buff));
				add_str_member(_handle, object, _instance->id2field[s_ip_idx].name, ip_buff);

				inet_ntop(AF_INET6, (const void *)(a_stream->addr.ipv6->daddr), ip_buff, sizeof(ip_buff));
				add_str_member(_handle, object, _instance->id2field[d_ip_idx].name, ip_buff);
				
				add_number_member(_handle, object, _instance->id2field[s_port_idx].name, ntohs(a_stream->addr.ipv6->source));
				add_number_member(_handle, object, _instance->id2field[d_port_idx].name, ntohs(a_stream->addr.ipv6->dest));
				return 1;
			break;
		default:
			break;
			
	}
	
	return 0;
}

struct session_marker_notify_ctx 
{
	uint64_t flags;
	char *identify_str;
};

int set_session_flags(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
{
	struct session_marker_notify_ctx *sm_notify=(struct session_marker_notify_ctx *)session_session_flags_get(a_stream);
	if(sm_notify==NULL)
	{
		return 0;
	}

	if(!TLD_search(_handle, _instance->id2field[LOG_COMMON_FLAGS].name))
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_FLAGS].name, (void *)(long)(sm_notify->flags), TLD_TYPE_LONG);
	}

	if(!TLD_search(_handle, _instance->id2field[LOG_COMMON_FLAGS_IDENTIFY_INFO].name))
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_FLAGS_IDENTIFY_INFO].name, (void *)(long)(sm_notify->identify_str), TLD_TYPE_STRING);
	}

	return 0;
}

int set_sce_profile_ids(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
{
	struct sce_log_update *sce = (struct sce_log_update *)session_log_update_data_get(a_stream, TSG_SERVICE_CHAINING);
	if(sce==NULL)
	{
		return 0;
	}

	Value sce_profile_ids_array(kArrayType);
	for(size_t i=0; i<sce->n_profile_ids; i++)
	{
		sce_profile_ids_array.PushBack((unsigned int)(sce->profile_ids[i]), _handle->document->GetAllocator());
	}

	TLD_append(_handle, _instance->id2field[LOG_COMMON_SCE_PROFILE_IDS].name, (void *) &sce_profile_ids_array, TLD_TYPE_OBJECT);

	fs3_rule_stat_update(RULE_STAT_SEND, TSG_ACTION_S_CHAINING, sce->n_profile_ids);

	return 0;
}

int set_shaping_profile_ids(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
{
	struct shaper_log_update *shaping = (struct shaper_log_update *)session_log_update_data_get(a_stream, TSG_SERVICE_SHAPING);
	if(shaping==NULL)
	{
		return 0;
	}

	Value shaping_object(kObjectType);

	Value shaping_array(kArrayType);
	for(size_t i=0; i<shaping->n_shaper_rule; i++)
	{
		Value object(kObjectType);
		object.AddMember("rule_id", (unsigned int)shaping->shaper_rules[i].rule_id, _handle->document->GetAllocator());

		Value shaping_profile_ids_array(kArrayType);
		for(size_t j=0; j<shaping->shaper_rules[i].n_profile_ids; j++)
		{
			shaping_profile_ids_array.PushBack((unsigned long)(shaping->shaper_rules[i].profile_ids[j]), _handle->document->GetAllocator());
		}

		add_object_member(_handle, &object, "profile_ids", shaping_profile_ids_array)
		shaping_array.PushBack(object, _handle->document->GetAllocator());
	}

	TLD_append(_handle, _instance->id2field[LOG_COMMON_SHAPING_PROFILE_IDS].name, &shaping_array, TLD_TYPE_OBJECT);

	fs3_rule_stat_update(RULE_STAT_SEND, TSG_ACTION_SHAPING, shaping->n_shaper_rule);

	return 0;
}

int set_shaping_rule_ids(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
{
	if(a_stream==NULL)
	{
		return 0;
	}
	
	struct matched_policy_rules *hited_shaping=(struct matched_policy_rules *)session_matched_rules_get(a_stream, TSG_SERVICE_SHAPING);
	if(hited_shaping==NULL)
	{
		return 0;
	}

	Value shaping_rule_ids_array(kArrayType);
	for(size_t i=0; i<hited_shaping->n_rules; i++)
	{
		shaping_rule_ids_array.PushBack((unsigned long)(hited_shaping->rules[i].rule_id), _handle->document->GetAllocator());
	}

	TLD_append(_handle, _instance->id2field[LOG_COMMON_SHAPING_RULE_IDS].name, (void *) &shaping_rule_ids_array, TLD_TYPE_OBJECT);

	return 0;
}

static int set_common_tunnels(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
{
	int ret=0;	
	char ip_buff[64]={0};
	const struct streaminfo *ptmp = a_stream;
	const struct streaminfo *pfather=NULL;
	Value tunnel_array(kArrayType);

	while(ptmp)
	{
		Value tunnel_object(kObjectType);
		pfather = ptmp->pfather;
		switch(ptmp->addr.addrtype)
		{
			case	ADDR_TYPE_MAC:
				set_link_mac(_instance, _handle, (ptmp->addr.mac), &tunnel_object);
				break;
			case	ADDR_TYPE_VLAN:
				add_str_member(_handle, &tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "VLAN");
				set_vlan(_instance, _handle, ptmp->addr.vlan->c2s_addr_array, ptmp->addr.vlan->c2s_layer_num, &tunnel_object,  LOG_COMMON_TUNNELS_VLAN_SRC_ID);
				set_vlan(_instance, _handle, ptmp->addr.vlan->s2c_addr_array, ptmp->addr.vlan->s2c_layer_num, &tunnel_object, LOG_COMMON_TUNNELS_VLAN_DST_ID);
				break;
			case	ADDR_TYPE_GRE:
				add_str_member(_handle, &tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "GRE");
				break;
			case	ADDR_TYPE_MPLS:
				if(ptmp->addr.mpls->s2c_layer_num==0 && ptmp->addr.mpls->c2s_layer_num==0)
				{
					ptmp = pfather;
					continue;
				}
				add_str_member(_handle, &tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "MPLS");
				set_mpls(_instance, _handle, ptmp->addr.mpls->c2s_addr_array, ptmp->addr.mpls->c2s_layer_num, &tunnel_object, LOG_COMMON_TUNNELS_MPLS_SRC_LABEL);
				set_mpls(_instance, _handle, ptmp->addr.mpls->s2c_addr_array, ptmp->addr.mpls->s2c_layer_num, &tunnel_object, LOG_COMMON_TUNNELS_MPLS_DST_LABEL);
				break;
			case	ADDR_TYPE_L2TP:
				add_str_member(_handle, &tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "L2TP");
				set_l2tp(_instance, _handle, ptmp->addr.l2tp, &tunnel_object);

				ret=set_tunnel_ipv4v6_port(_instance, _handle, ptmp->pfather, &tunnel_object, ADDR_TYPE_L2TP);
				if(ret==1)
				{
					ptmp=pfather->pfather;
				}
				break;
			case	__ADDR_TYPE_IP_PAIR_V4:
				add_str_member(_handle, &tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "IPv4");

				inet_ntop(AF_INET, (const void *)&(ptmp->addr.ipv4->saddr), ip_buff, sizeof(ip_buff));
				add_str_member(_handle, &tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_CLIENT_IP].name, ip_buff);

				inet_ntop(AF_INET, (const void *)&(ptmp->addr.ipv4->daddr), ip_buff, sizeof(ip_buff));
				add_str_member(_handle, &tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SERVER_IP].name, ip_buff);
				break;
			case	__ADDR_TYPE_IP_PAIR_V6:			
				add_str_member(_handle, &tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "IPv6");

				inet_ntop(AF_INET6, (const void *)(ptmp->addr.ipv6->saddr), ip_buff, sizeof(ip_buff));
				add_str_member(_handle, &tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_CLIENT_IP].name, ip_buff);

				inet_ntop(AF_INET6, (const void *)(ptmp->addr.ipv6->daddr), ip_buff, sizeof(ip_buff));
				add_str_member(_handle, &tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SERVER_IP].name, ip_buff);
				break;
			case	ADDR_TYPE_PPTP:
				add_str_member(_handle, &tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "PPTP");
				add_number_member(_handle, &tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_PPTP_C2S_ID].name, ntohs(ptmp->addr.pptp->C2S_call_id));
				add_number_member(_handle, &tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_PPTP_S2C_ID].name, ntohs(ptmp->addr.pptp->S2C_call_id));
				break;
			case	ADDR_TYPE_GPRS_TUNNEL:
				add_str_member(_handle, &tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "GTP");
				add_number_member(_handle, &tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_UPLINK_TEID].name, ntohl(ptmp->addr.gtp->teid_c2s));
				add_number_member(_handle, &tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_DOWNLINK_TEID].name, ntohl(ptmp->addr.gtp->teid_s2c));

				ret=set_tunnel_ipv4v6_port(_instance, _handle, ptmp->pfather, &tunnel_object, ADDR_TYPE_GPRS_TUNNEL);
				if(ret==1)
				{
					ptmp=pfather->pfather;
				}
				break;
			case	ADDR_TYPE_VXLAN:
				add_str_member(_handle, &tunnel_object, _instance->id2field[LOG_COMMON_TUNNELS_SCHEMA_TYPE].name, "VXLAN");
				break;
			default:
				ptmp = pfather;
				continue;
				break;
		}
		
		ptmp=pfather;
		tunnel_array.PushBack(tunnel_object, _handle->document->GetAllocator());
	}

	TLD_append(_handle, _instance->id2field[LOG_COMMON_TUNNELS].name, &tunnel_array, TLD_TYPE_OBJECT);

	return 0;
}

char *log_field_id2name(struct tsg_log_instance_t *instance, enum LOG_FIELD_ID id)
{
	struct tsg_log_instance_t *_instance=instance;
	if(_instance!=NULL)
	{
		return _instance->id2field[id].name;
	}

	return NULL;
}

int is_multi_hit_same_policy(struct maat_rule *result, int *policy_id, int *policy_id_num)
{
	int j=0;
	
	for(j=0;j<*policy_id_num;j++)
	{
		if(policy_id[j]==result->rule_id)
		{
			return 1;
		}
	}

	policy_id[(*policy_id_num)++]=result->rule_id;

	return 0;
}

static int is_hitted_shunt(const struct streaminfo *a_stream)
{
	if(a_stream==NULL)
	{
		return 0;
	}
	
	const struct session_runtime_action_context *srt_action_context=session_runtime_action_context_get(a_stream);
	enum TSG_METHOD_TYPE method_type=srt_action_context_get_method_type(srt_action_context);
	if(method_type==TSG_METHOD_TYPE_SHUNT)
	{
		return 1;
	}

	return 0;
}

static int set_xxxx_from_user_region(struct TLD_handle_t *_handle, struct tsg_log_instance_t *_instance, struct maat_rule *p_result, int thread_seq)
{
	cJSON *item=NULL;
	cJSON *object=NULL;

	TLD_delete(_handle, _instance->id2field[LOG_COMMON_USER_REGION].name);
	TLD_delete(_handle, _instance->id2field[LOG_COMMON_SUB_ACTION].name);

	if(p_result->action!=TSG_ACTION_NONE)
	{
		struct maat_compile *compile=(struct maat_compile *)matched_rule_cites_security_compile(g_tsg_maat_feather, p_result->rule_id);
		if(compile!=NULL && compile->p_user_region!=NULL)
		{
			object=cJSON_Parse(compile->p_user_region);
			if(_instance->send_user_region==1)
			{
				TLD_append(_handle, _instance->id2field[LOG_COMMON_USER_REGION].name, (void *)(compile->p_user_region), TLD_TYPE_STRING);
			}

			plugin_ex_data_security_compile_free(compile);
		}
	}

	if(object==NULL)
	{
		return 0;
	}

	if(p_result->action==TSG_ACTION_DENY)
	{
		item=cJSON_GetObjectItem(object, "method");
		if(item!=NULL && item->valuestring!=NULL)
		{
			TLD_append(_handle, _instance->id2field[LOG_COMMON_SUB_ACTION].name, (void *)item->valuestring, TLD_TYPE_STRING);
		}
	}
	
	cJSON_Delete(object);
	object=NULL;

	return 0;
}

int set_application_behavior(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
{
	struct application_behavior *behavior_result=(struct application_behavior *)session_application_behavior_get(a_stream);
	if(behavior_result!=NULL)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_APPLICATION_BEHAVIOR].name, (void *)(behavior_result->stream_behavior), TLD_TYPE_STRING);
	}

	return 1;
}

int set_policy_action_para_exec_result(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream, struct maat_rule *p_result)
{
	struct tsg_notify_execution_result *execution_result=(struct tsg_notify_execution_result *)session_mirrored_and_capture_packets_exec_result_get(a_stream);
	if(execution_result==NULL)
	{
		return 0;
	}

	TLD_delete(_handle, _instance->id2field[LOG_COMMON_MIRRORED_PKTS].name);
	TLD_delete(_handle, _instance->id2field[LOG_COMMON_MIRRORED_BYTES].name);
	TLD_delete(_handle, _instance->id2field[LOG_COMMON_PACKET_CAPTURE_FILE].name);
	
	for(int i=0; i<execution_result->stat_mirrored_cnt; i++)
	{
		if(execution_result->stat_mirrored[i].compile_id==p_result->rule_id)
		{
			TLD_append(_handle, _instance->id2field[LOG_COMMON_MIRRORED_PKTS].name, (void *)(execution_result->stat_mirrored[i].packets), TLD_TYPE_LONG);
			TLD_append(_handle, _instance->id2field[LOG_COMMON_MIRRORED_BYTES].name, (void *)(execution_result->stat_mirrored[i].bytes), TLD_TYPE_LONG);
			break;
		}
	}

	for(int i=0; i<execution_result->capture_result_cnt; i++)
	{		
		if(execution_result->capture_result[i].compile_id==p_result->rule_id)
		{	
			TLD_append(_handle, _instance->id2field[LOG_COMMON_PACKET_CAPTURE_FILE].name, (void *)(execution_result->capture_result[i].packet_path), TLD_TYPE_STRING);
			break;
		}
	}
	
	return 1;
}

int set_session_attributes(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
{
	struct session_runtime_attribute *srt_attribute=(struct session_runtime_attribute *)session_runtime_attribute_get(a_stream);
	if(srt_attribute==NULL)
	{
		return 0;
	}

	if(srt_attribute->establish_latency_ms>0)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_ESTABLISH_LATENCY_MS].name, (void *)srt_attribute->establish_latency_ms, TLD_TYPE_LONG);
	}

	if(srt_attribute->http_action_file_size>0)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_HTTP_ACTION_FILESIZE].name, (void *)(long)srt_attribute->http_action_file_size, TLD_TYPE_LONG);
	}
	
	set_asn(_handle, a_stream, _instance->id2field[LOG_COMMON_CLINET_ASN].name, srt_attribute->client_asn);
	set_asn(_handle, a_stream, _instance->id2field[LOG_COMMON_SERVER_ASN].name, srt_attribute->server_asn);
	
	set_location(_handle, a_stream, _instance->id2field[LOG_COMMON_CLINET_LOCATION].name, srt_attribute->client_location);
	set_location(_handle, a_stream, _instance->id2field[LOG_COMMON_SERVER_LOCATION].name, srt_attribute->server_location);

	int ret=set_subscriber_id(_handle, _instance->id2field[LOG_COMMON_SUBSCRIBER_ID].name, srt_attribute->client_subscribe_id);
	if(ret==0)
	{
		set_subscriber_id(_handle, _instance->id2field[LOG_COMMON_SUBSCRIBER_ID].name, srt_attribute->server_subscribe_id);
	}
	
	set_fqdn_category(_instance, _handle, a_stream, srt_attribute->fqdn_category_ids, srt_attribute->n_fqdn_category_ids);

	if(srt_attribute->ja3_fingerprint!=NULL)
	{
		TLD_append(_handle, _instance->id2field[LOG_SSL_JA3_FINGERPRINT].name, (void *)srt_attribute->ja3_fingerprint, TLD_TYPE_STRING);
	}

	set_umts_user_info(_instance, _handle, a_stream, srt_attribute->user_info);

	if(srt_attribute->client_endpoint!=NULL)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_TUNNELS_ENDPOINT_A_DESC].name, (void *)srt_attribute->client_endpoint->description, TLD_TYPE_STRING);
	}

	if(srt_attribute->server_endpoint!=NULL)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_TUNNELS_ENDPOINT_B_DESC].name, (void *)srt_attribute->server_endpoint->description, TLD_TYPE_STRING);
	}

	if(srt_attribute->session_flags>0 && !(TLD_search(_handle, _instance->id2field[LOG_COMMON_FLAGS].name)))
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_FLAGS].name, (void *)srt_attribute->session_flags, TLD_TYPE_LONG);
	}

	return 1;
}

int set_lua_scripts_result(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
{
	struct user_defined_attribute *uda_label=(struct user_defined_attribute *)session_lua_user_defined_attribute_get(a_stream);
	if(uda_label!=NULL)
	{
		Value array(kArrayType);

		for(int i=0; i<uda_label->n_akv; i++)
		{
			Value object(kObjectType);
			switch(uda_label->akv[i].type)
			{
				case	LUA_ATTRIBUTE_TYPE_BOOL:
				case	LUA_ATTRIBUTE_TYPE_NUMERIC:
					add_number_member(_handle, &object, uda_label->akv[i].name, uda_label->akv[i].number);
					break;
				case	LUA_ATTRIBUTE_TYPE_IP:
				case	LUA_ATTRIBUTE_TYPE_STRING:	
					add_str_member(_handle, &object, uda_label->akv[i].name, uda_label->akv[i].string);
					break;
				default:
					continue;
			}

			array.PushBack(object, _handle->document->GetAllocator());
		}

		TLD_append(_handle, _instance->id2field[LOG_COMMON_APP_EXTRACT_INFO].name, &array, TLD_TYPE_OBJECT);
	}

	return 0;
}

int set_intercept_info(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
{
	struct proxy_log_update *proxy = (struct proxy_log_update *)session_log_update_data_get(a_stream, TSG_SERVICE_INTERCEPT);
	if(proxy!=NULL)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_SSL_PINNING_STATE].name, (void *)(long)proxy->ssl_pinning_state, TLD_TYPE_LONG);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_SSL_CERT_VERIFY].name, (void *)(long)proxy->ssl_cert_verify, TLD_TYPE_LONG);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_SSL_INTERCEPT_STATE].name, (void *)(long)proxy->ssl_intercept_state, TLD_TYPE_LONG);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_SSL_UPSTREAM_LATENCY].name, (void *)(long)proxy->ssl_upstream_latency, TLD_TYPE_LONG);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_SSL_DOWNSTREAM_LATENCY].name, (void *)(long)proxy->ssl_downstream_latency, TLD_TYPE_LONG);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_SSL_UPSTREAM_VERSION].name, proxy->ssl_upstream_version, TLD_TYPE_STRING);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_SSL_DOWNSTREAM_VERSION].name, proxy->ssl_downstream_version, TLD_TYPE_STRING);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_SSL_ERROR].name, proxy->ssl_error, TLD_TYPE_STRING);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_SSL_PASSTHROUGHT_REASON].name, proxy->ssl_passthrough_reason, TLD_TYPE_STRING);
	}

	return 0;
}

int TLD_append_streaminfo(struct tsg_log_instance_t *instance, struct TLD_handle_t *handle, const struct streaminfo *a_stream)
{
	struct TLD_handle_t *_handle=handle;
	struct tsg_log_instance_t *_instance=instance;

	if(_instance==NULL || _handle==NULL || a_stream==NULL)
	{
		if(_instance)
		{
			MASTER_LOG(_instance->logger, RLOG_LV_DEBUG, LOG_MODULE_SENDLOG, "TLD_APPEND_STREAM TLD_handle==NULL || addr==NULL");
		}
		return -1;
	}

	int ret=set_linkinfo(_instance, _handle, a_stream);
	if(ret==0)
	{
		set_direction(_instance, _handle, a_stream);
	}

	set_app_id(_instance, _handle, a_stream);
	set_tcp_isn(_instance, _handle, a_stream);
	set_tuple4(_instance, _handle, a_stream);
	set_address_list(_instance, _handle, a_stream);
	set_duraction(_instance, _handle, a_stream);
	set_packet_bytes(_instance, _handle, a_stream);	
	set_session_attributes(_instance, _handle, a_stream);
	set_lua_scripts_result(_instance, _handle, a_stream);
	
	set_session_flags(_instance, _handle, a_stream);
	
	if(is_tunnels(a_stream))
	{
		set_common_tunnels(_instance, _handle, a_stream);
	}
	
	unsigned long long stream_id=tsg_get_stream_trace_id(a_stream);
	char stream_id_buff[128]={0};
	snprintf(stream_id_buff, sizeof(stream_id_buff), "%llu", stream_id);
	TLD_append(_handle, _instance->id2field[LOG_COMMON_STREAM_TRACE_ID].name, (void *)stream_id_buff, TLD_TYPE_STRING);
	
	char *addr_proto=(char *)layer_addr_prefix_ntop(a_stream);
	TLD_append(_handle, _instance->id2field[LOG_COMMON_L4_PROTOCOL].name, (void *)addr_proto, TLD_TYPE_STRING);

	return 0;
}

static int session_record_limit(struct tsg_log_instance_t *_instance, const struct streaminfo *a_stream, enum LOG_TYPE log_type)
{
	if(tsg_session_record_switch_get()==0)
	{
		return 1;
	}
	
	if(log_type==LOG_TYPE_SESSION_RECORD)
	{
		if(a_stream==NULL || a_stream->pdetail==NULL)
		{
			return 0;
		}

		switch(a_stream->type)
		{
			case	STREAM_TYPE_TCP:
				if((a_stream->ptcpdetail->clientbytes + a_stream->ptcpdetail->serverbytes < (unsigned int)_instance->tcp_min_log_bytes) ||
					(a_stream->ptcpdetail->clientpktnum + a_stream->ptcpdetail->serverpktnum < (unsigned int)_instance->tcp_min_log_pkts))
				{
					return 1;
				}
				break;
			case	STREAM_TYPE_UDP:
				if((a_stream->pudpdetail->clientbytes + a_stream->pudpdetail->serverbytes < (unsigned int)_instance->udp_min_log_bytes) ||
					(a_stream->pudpdetail->clientpktnum + a_stream->pudpdetail->serverpktnum < (unsigned int)_instance->udp_min_log_pkts))
				{
					return 1;
				}
				break;
			default:
				break;
		}
		
		return 0;
	}
	
	if(log_type==LOG_TYPE_INTERIM_SESSION_RECORD && _instance->send_interim_log==0)
	{
		return 1;
	}
	
	if(log_type==LOG_TYPE_TRANSACTION_RECORD && _instance->send_transcation_log==0)
	{
		return 1;
	}

	return 0;
}

int append_common_field(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream)
{
	TLD_append_streaminfo(_instance, _handle, a_stream);
	TLD_append(_handle, _instance->id2field[LOG_COMMON_SLED_IP].name, (void *)(_instance->local_ip_str), TLD_TYPE_STRING);
	if(strlen(g_tsg_para.device_sn)>0)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_DEVICE_ID].name, (void *)(g_tsg_para.device_sn), TLD_TYPE_STRING);
	}

	TLD_append(_handle, _instance->id2field[LOG_COMMON_DATA_CENTER].name, (void *)tsg_data_center_get(), TLD_TYPE_STRING);
	TLD_append(_handle, _instance->id2field[LOG_COMMON_DEVICE_TAG].name, (void *)tsg_device_tag_get(), TLD_TYPE_STRING);
	TLD_append(_handle, _instance->id2field[LOG_COMMON_TRAFFIC_VSYSTEM_ID].name, (void *)(long)_instance->vsystem_id, TLD_TYPE_LONG);

	set_application_behavior(_instance, _handle, a_stream);

	return 1;
}

int log_common_fields_new(const char *filename, id2field_t *id2field, struct topic_stat **service2topic, int *max_service)
{
	int i=0,flag=0;
	FILE *fp=NULL;
	char line[1024]={0};
	char field_name[64]={0};
	char type_name[32]={0};
	struct topic_stat *_service2topic=NULL;
	
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
		int id=0;
		memset(type_name, 0, sizeof(type_name));
		sscanf(line, "%31s %63s %d", type_name, field_name, &id);

		for(i=0; i<TLD_TYPE_MAX; i++)
		{
			if((strncasecmp(tld_type[i].name, type_name, strlen(tld_type[i].name)))==0)
			{
				switch(tld_type[i].type)
				{
					case	TLD_TYPE_FILE:
					case	TLD_TYPE_LONG:
					case	TLD_TYPE_STRING:
						if(id<LOG_COMMON_MAX)
						{
							id2field[id].type = tld_type[i].type;
							id2field[id].id = id;
							memcpy(id2field[id].name, field_name, strlen(field_name));
						}
						flag=1;
						break;
					case	TLD_TYPE_TOPIC:
						if(_service2topic==NULL)
						{
							_service2topic=(struct topic_stat *)calloc(1, sizeof(struct topic_stat)*(id+1));
							_service2topic[id].type = TLD_TYPE_MAX;
							//_service2topic[id].id = id;
							memcpy(_service2topic[id].name, field_name, strlen(field_name));

							*max_service=id+1;
						}
						else
						{
							if(*max_service<=id)
							{
								_service2topic=(struct topic_stat *)realloc(_service2topic, sizeof(struct topic_stat)*(id+1));
								memset(&_service2topic[id], 0, sizeof(struct topic_stat));
								_service2topic[id].type = TLD_TYPE_MAX;
								//_service2topic[id].id = id;
								memcpy(_service2topic[id].name, field_name, strlen(field_name));

								*max_service=id+1;
							}
							else
							{
								memset(&_service2topic[id], 0, sizeof(struct topic_stat));
								_service2topic[id].type = TLD_TYPE_MAX;
								//_service2topic[id].id = id;
								memcpy(_service2topic[id].name, field_name, strlen(field_name));
							}
						}
						flag=1;
						break;
					default:
						break;
				}

				if(flag==1)
				{
					flag=0;
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
		(*service2topic)=_service2topic;
	}

	return 0;
}

struct tsg_log_instance_t *tsg_sendlog_init(const char *conffile)
{
	char override_sled_ip[32]={0};
	char kafka_errstr[1024]={0};
	unsigned int local_ip_nr=0;
	rd_kafka_conf_t *rdkafka_conf = NULL;
	char broker_list[1024]={0};
	struct tsg_log_instance_t *_instance=NULL;
	char common_field_file[128]={0};
	char log_path[128]={0};

	_instance=(struct tsg_log_instance_t *)calloc(1, sizeof(struct tsg_log_instance_t));

	MESA_load_profile_int_def(conffile, "TSG_LOG", "LOG_LEVEL",&(_instance->level), 30);
	MESA_load_profile_string_def(conffile, "TSG_LOG", "LOG_PATH", log_path, sizeof(log_path), "./log/tsglog");
	MESA_load_profile_int_def(conffile, "TSG_LOG", "SEND_USER_REGION", &(_instance->send_user_region), 0);
	MESA_load_profile_int_def(conffile, "TSG_LOG", "SEND_DATA_CENTER_SWITCH", &(_instance->send_data_center), 0);
	MESA_load_profile_int_def(conffile, "TSG_LOG", "SEND_APP_ID_SWITCH", &(_instance->send_app_id), 0);
	MESA_load_profile_int_def(conffile, "TSG_LOG", "SEND_INTERCEPT_LOG", &(_instance->send_intercept_log), 0);
	MESA_load_profile_int_def(conffile, "TSG_LOG", "SEND_NAT_LINKINFO_SWITCH", &(_instance->send_nat_linkinfo), 0);
	MESA_load_profile_int_def(conffile, "TSG_LOG", "RAPIDJSON_CHUNK_CAPACITY", &(_instance->rapidjson_chunk_capacity), 8192);

	MESA_load_profile_int_def(conffile, "TSG_LOG", "VSYSTEM_ID", &(_instance->vsystem_id), 1);
	MESA_load_profile_int_def(conffile, "SYSTEM","UNKNOWN_APP_ID", &_instance->unknown_app_id, 4);

	MESA_load_profile_int_def(conffile, "TSG_LOG", "SEND_INTERIM_RECORD", &(_instance->send_interim_log), 1);
	MESA_load_profile_int_def(conffile, "TSG_LOG", "SEND_TRANSCATION_RECORD", &(_instance->send_transcation_log), 1);
	MESA_load_profile_int_def(conffile, "TSG_LOG","TCP_MIN_PKTS", &_instance->tcp_min_log_pkts, 3);
	MESA_load_profile_int_def(conffile, "TSG_LOG","TCP_MIN_BYTES", &_instance->tcp_min_log_bytes, 5);
	MESA_load_profile_int_def(conffile, "TSG_LOG","UDP_MIN_PKTS", &_instance->udp_min_log_pkts, 3);
	MESA_load_profile_int_def(conffile, "TSG_LOG","UDP_MIN_BYTES", &_instance->udp_min_log_bytes, 5);
	
	_instance->logger=MESA_create_runtime_log_handle(log_path, _instance->level);
	if(_instance->logger==NULL)
	{
		printf("MESA_create_runtime_log_handle failed ..., path: %s level: %d", log_path, _instance->level);
		free(_instance);
		_instance=NULL;
		return NULL;
	}
	
	MESA_load_profile_int_def(conffile, "TSG_LOG", "MODE",&(_instance->mode), 0);
	if(_instance->mode==CLOSE)
	{
		MASTER_LOG(_instance->logger, RLOG_LV_FATAL, LOG_MODULE_SENDLOG, "Disable tsg_send_log");
		return _instance;
	}
	
	MESA_load_profile_int_def(conffile, "TSG_LOG", "RECOVERY_INTERVEL_S", &(_instance->recovery_interval), 30);	

	MESA_load_profile_string_def(conffile, "TSG_LOG", "COMMON_FIELD_FILE", common_field_file, sizeof(common_field_file), NULL);
	MESA_load_profile_string_def(conffile, "TSG_LOG", "BROKER_LIST", broker_list, sizeof(broker_list), NULL);
	MESA_load_profile_string_def(conffile, "TSG_LOG", "SASL_USERNAME", _instance->sasl_username, sizeof(_instance->sasl_username), ""); //admin
	MESA_load_profile_string_def(conffile, "TSG_LOG", "SASL_PASSWD", _instance->sasl_passwd, sizeof(_instance->sasl_passwd), "");

	MESA_load_profile_string_def(conffile, "TSG_LOG", "SEND_QUEUE_MAX_MESSAGE", _instance->send_queue_max_msg, sizeof(_instance->send_queue_max_msg), "1000000");
	MESA_load_profile_string_def(conffile, "TSG_LOG", "REFRESH_INTERVAL_MS", _instance->refresh_interval_ms, sizeof(_instance->refresh_interval_ms), "600000");
	MESA_load_profile_string_def(conffile, "TSG_LOG", "REQUIRE_ACK", _instance->require_ack, sizeof(_instance->require_ack), "1");

	MESA_load_profile_string_def(conffile, "SYSTEM", "TCP_LABEL", _instance->tcp_label, sizeof(_instance->tcp_label), "tcp_flow_stat");
	MESA_load_profile_string_def(conffile, "SYSTEM", "UDP_LABEL", _instance->udp_label, sizeof(_instance->udp_label), "udp_flow_stat");

	_instance->tcp_flow_project_id=project_customer_register(_instance->tcp_label, "struct");
	_instance->udp_flow_project_id=project_customer_register(_instance->udp_label, "struct");
	if(_instance->tcp_flow_project_id<0 || _instance->udp_flow_project_id<0)
	{
		MASTER_LOG(_instance->logger, RLOG_LV_FATAL, LOG_MODULE_SENDLOG, 
									"project_customer_register is error, tcp_label: %s udp_label: %s, please check etc/project.conf",
									_instance->tcp_label,
									_instance->udp_label
								);
	}

	MESA_load_profile_string_def(conffile, "SYSTEM", "OVERRIDE_SLED_IP", override_sled_ip, sizeof(override_sled_ip), "OVERRIDE_SLED_IP");
	char *sled_ip=getenv(override_sled_ip);
	if(sled_ip==NULL)
	{
		char nic_name[32]={0};
		MESA_load_profile_string_def(conffile, "SYSTEM", "NIC_NAME", nic_name, sizeof(nic_name), "lo");	
		int ret=MESA_get_dev_ipv4(nic_name, (int *)&local_ip_nr);
		if(ret<0)
		{
			MASTER_LOG(_instance->logger, RLOG_LV_FATAL, LOG_MODULE_SENDLOG, 
										"GET_LOCAL_IP MESA_get_dev_ipv4 is error, nic_name: %s, please check tsgconf/main.conf",
										nic_name
									);
			return NULL;
		}
		inet_ntop(AF_INET,&(local_ip_nr),_instance->local_ip_str,sizeof(_instance->local_ip_str));
	}
	else
	{
		memcpy(_instance->local_ip_str, sled_ip, MIN(sizeof(_instance->local_ip_str)-1, strlen(sled_ip)));
	}
	
	rdkafka_conf = rd_kafka_conf_new();	
	rd_kafka_conf_set(rdkafka_conf, "queue.buffering.max.messages", _instance->send_queue_max_msg, kafka_errstr, sizeof(kafka_errstr));
	rd_kafka_conf_set(rdkafka_conf, "topic.metadata.refresh.interval.ms", _instance->refresh_interval_ms, kafka_errstr, sizeof(kafka_errstr));
	rd_kafka_conf_set(rdkafka_conf, "request.required.acks", _instance->require_ack, kafka_errstr, sizeof(kafka_errstr));	
	rd_kafka_conf_set(rdkafka_conf, "socket.keepalive.enable", "true", kafka_errstr, sizeof(kafka_errstr));	
	rd_kafka_conf_set(rdkafka_conf, "bootstrap.servers", broker_list, kafka_errstr, sizeof(kafka_errstr));
	
	if(strlen(_instance->sasl_username)> 0 && strlen(_instance->sasl_passwd)>0)
	{
		rd_kafka_conf_set(rdkafka_conf, "security.protocol", "sasl_plaintext", kafka_errstr, sizeof(kafka_errstr));
		rd_kafka_conf_set(rdkafka_conf, "sasl.mechanisms", "PLAIN", kafka_errstr, sizeof(kafka_errstr));
		rd_kafka_conf_set(rdkafka_conf, "sasl.username", _instance->sasl_username, kafka_errstr, sizeof(kafka_errstr));
		rd_kafka_conf_set(rdkafka_conf, "sasl.password", _instance->sasl_passwd, kafka_errstr, sizeof(kafka_errstr));
	}
	
	if(!(_instance->kafka_handle=rd_kafka_new(RD_KAFKA_PRODUCER, rdkafka_conf, kafka_errstr, sizeof(kafka_errstr))))
	{
		MASTER_LOG(_instance->logger, RLOG_LV_FATAL, LOG_MODULE_SENDLOG, "KAFKA_INIT rd_kafka_new is error");
		return NULL;
	}

	log_common_fields_new(common_field_file, _instance->id2field, &(_instance->service2topic), &(_instance->max_service));

	if(_instance->service2topic!=NULL)
	{
		_instance->sum_stat_row_id=tsg_stat_sendlog_row_init("sum");
		for(int i=0; i<_instance->max_service; i++)
		{
			if(_instance->service2topic[i].type==TLD_TYPE_MAX && strlen(_instance->service2topic[i].name)>0)
			{
				register_topic(_instance, &( _instance->service2topic[i]));
			}
		}
	}
	else
	{
		MASTER_LOG(_instance->logger, RLOG_LV_FATAL, LOG_MODULE_SENDLOG, "KAFKA_INIT log_common_fields_new is error, please check %s", common_field_file);
	}
	
	return _instance;
}
void tsg_sendlog_destroy(struct tsg_log_instance_t * instance)
{
	if(instance==NULL)
	{
		return ;
	}
	
	if(instance->mode!=CLOSE)
	{
		for(int i=0; i<instance->max_service; i++)
		{
			if(instance->service2topic[i].type!=TLD_TYPE_MAX || i==1)  //i=1 equal i=0, service id of security event is 0 and 1
 			{
				continue;
			}
			
			if(instance->service2topic[i].topic_rkt!=NULL)
			{
				rd_kafka_topic_destroy(instance->service2topic[i].topic_rkt);
			}

			if(instance->service2topic[i].drop_start!=NULL)
			{
				free(instance->service2topic[i].drop_start);
				instance->service2topic[i].drop_start=NULL;
			}

			if(instance->service2topic[i].send_log_percent!=NULL)
			{
				free(instance->service2topic[i].send_log_percent);
				instance->service2topic[i].send_log_percent=NULL;
			}
		}
		
		//rd_kafka_destroy_flags(instance->kafka_handle, 4);
		rd_kafka_destroy(instance->kafka_handle);

		free(instance->service2topic);
		instance->service2topic=NULL;
	}

	
	MESA_destroy_runtime_log_handle(instance->logger);
	instance->logger=NULL;

	free(instance);
	instance=NULL;
	return ;
}

int send_log_by_type(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream, LOG_TYPE log_type, int thread_id)
{
	int ret=update_percent(_instance, log_type, LOG_STATUS_DROP, thread_id);
	if(ret==1)
	{
		MASTER_LOG(_instance->logger, RLOG_LV_DEBUG, LOG_MODULE_SENDLOG, 
									"drop log: log_type=%d send_log_percent: %d addr=%s",
									log_type,
									_instance->service2topic[log_type].send_log_percent[thread_id],
									(a_stream==NULL ? "" : printaddr(&(a_stream->addr), thread_id))
								);
	}
		
	StringBuffer sb(0, 2048);
	Writer<StringBuffer> writer(sb);
	_handle->document->Accept(writer);

	tsg_send_payload(_instance, log_type, (char *)sb.GetString(), sb.GetSize(), thread_id);
	
	return 0;
}

int send_event_log(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream, LOG_TYPE log_type, struct maat_rule *rules, size_t n_rules, int thread_id)
{
	int repeat_cnt=0;
	int policy_id[MAX_RESULT_NUM]={0};

	for(size_t i=0;i<n_rules; i++)
	{
		if(is_multi_hit_same_policy(&(rules[i]), policy_id, &repeat_cnt))
		{
			MASTER_LOG(_instance->logger, RLOG_LV_DEBUG, LOG_MODULE_SENDLOG, 
										"tsg same log:cfg_id=%d service=%d addr=%s",
										rules[i].rule_id,
										rules[i].service_id,
										(a_stream==NULL ? "" : printaddr(&(a_stream->addr), thread_id))
									);
			continue;
		}

		if(a_stream!=NULL && rules[i].service_id!=TSG_SERVICE_INTERCEPT)
		{
			tsg_set_policy_flow(a_stream, &(rules[i]), thread_id);
		}

		switch(rules[i].do_log)
		{
			case	LOG_ABORT:
				MASTER_LOG(_instance->logger, RLOG_LV_DEBUG, LOG_MODULE_SENDLOG, 
											"tsg abort log:cfg_id=%d service=%d addr=%s",
											rules[i].rule_id,
											rules[i].service_id,
											(a_stream==NULL ? "" : printaddr(&(a_stream->addr), thread_id))
										);

				fs3_rule_stat_update(RULE_STAT_ABORT, (int)rules[i].action, 1);
				continue;
				break;
			case	LOG_ALL:
				if(rules[i].action==TSG_ACTION_MONITOR)
				{
					set_s3_filename(_instance, _handle, a_stream);
					set_mail_eml(_instance, _handle, a_stream);
				}
				break;
			case	LOG_NOFILE:
				if(rules[i].action==TSG_ACTION_MONITOR)
				{
					TLD_delete(_handle, _instance->id2field[LOG_COMMON_MAIL_EML_FILE].name);
					TLD_delete(_handle, _instance->id2field[LOG_COMMON_HTTP_REQUEST_S3_FILE].name);
					TLD_delete(_handle, _instance->id2field[LOG_COMMON_HTTP_RESPONSE_S3_FILE].name);
				}
				break;
			default:
				break;
		}
		
		TLD_append(_handle, _instance->id2field[LOG_COMMON_POLICY_ID].name, (void *)(long)(rules[i].rule_id), TLD_TYPE_LONG);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_SERVICE].name, (void *)(long)(rules[i].service_id), TLD_TYPE_LONG);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_VSYSTEM_ID].name, (void *)(long)rules[i].vsys_id, TLD_TYPE_LONG);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_ACTION].name, (void *)(long)(rules[i].action), TLD_TYPE_LONG);

		set_policy_action_para_exec_result(_instance, _handle, a_stream, &(rules[i]));
		
		set_xxxx_from_user_region(_handle, _instance, &(rules[i]), thread_id);

		send_log_by_type(_instance, _handle, a_stream, log_type, thread_id);

		TLD_delete(_handle, _instance->id2field[LOG_COMMON_POLICY_ID].name);
		TLD_delete(_handle, _instance->id2field[LOG_COMMON_SERVICE].name);
		TLD_delete(_handle, _instance->id2field[LOG_COMMON_ACTION].name);
		TLD_delete(_handle, _instance->id2field[LOG_COMMON_USER_REGION].name);
		TLD_delete(_handle, _instance->id2field[LOG_COMMON_VSYSTEM_ID].name);

		fs3_rule_stat_update(RULE_STAT_SEND, (int)rules[i].action, 1);
	}

	return 0;
}

int deal_event_rules(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream, LOG_TYPE log_type, TSG_SERVICE service, int *is_append_common_field, int thread_id)
{
	struct matched_policy_rules *matched_rules=(struct matched_policy_rules *)session_matched_rules_get(a_stream, service);
	if(matched_rules==NULL || matched_rules->n_rules==0)
	{
		return 0;
	}

	if((*is_append_common_field)==0)
	{
		(*is_append_common_field)=1;
		append_common_field(_instance, _handle, a_stream);
	}
	
	if(service==TSG_SERVICE_INTERCEPT)
	{
		set_intercept_info(_instance, _handle, a_stream);
	}
	
	send_event_log(_instance, _handle, a_stream, log_type, matched_rules->rules, matched_rules->n_rules, thread_id);
	session_matched_rules_free(a_stream, service, (void *)matched_rules);
	session_matched_rules_async(a_stream, service, NULL);

	return 1;
}

int tsg_send_log(struct tsg_log_instance_t *instance, struct TLD_handle_t *handle, const struct streaminfo *a_stream, enum LOG_TYPE log_type, struct maat_rule *rules, size_t n_rules, int thread_id)
{	
	struct TLD_handle_t *_handle=handle;
	struct tsg_log_instance_t *_instance=instance;

	if(_instance==NULL || _handle==NULL || rules==NULL || n_rules==0)
	{
		TLD_cancel(_handle);
		if(_instance!=NULL)
		{
			MASTER_LOG(_instance->logger, RLOG_LV_DEBUG, LOG_MODULE_SENDLOG, " instance==NULL || TLD_handle==NULL || log_msg==NULL ");
		}
		return -1;
	}

	if(_instance->mode==CLOSE)
	{
		TLD_cancel(_handle);
		tsg_stat_sendlog_update(_instance->sum_stat_row_id, LOG_STATUS_DROP, 1);
		tsg_stat_sendlog_update(_instance->sum_stat_row_id, LOG_STATUS_DROP_S, 1);
		MASTER_LOG(_instance->logger, RLOG_LV_INFO, LOG_MODULE_SENDLOG, "Disable tsg_send_log.");
		return 0;
	}

	if(is_hitted_shunt(a_stream))
	{
		TLD_cancel(_handle);
		fs3_rule_stat_update(RULE_STAT_ABORT, TSG_ACTION_SHUNT, 1);
		return 0;
	}

	int is_append_common_field=0;

	switch(log_type)
	{
		case	LOG_TYPE_SECURITY_EVENT:
			append_common_field(instance, handle, a_stream);
			send_event_log(_instance, _handle, a_stream, LOG_TYPE_SECURITY_EVENT, rules, n_rules, thread_id);
			break;
		case	LOG_TYPE_INTERCEPT_EVENT:
			append_common_field(instance, handle, a_stream);
			send_event_log(_instance, _handle, a_stream, LOG_TYPE_INTERCEPT_EVENT, rules, n_rules, thread_id);
			break;
		case	LOG_TYPE_SESSION_RECORD:
		case	LOG_TYPE_TRANSACTION_RECORD:
			deal_event_rules(_instance, _handle, a_stream, LOG_TYPE_SECURITY_EVENT, TSG_SERVICE_SECURITY, &is_append_common_field, thread_id);

			if(_instance->send_intercept_log==1)
			{
				deal_event_rules(_instance, _handle, a_stream, LOG_TYPE_INTERCEPT_EVENT, TSG_SERVICE_INTERCEPT, &is_append_common_field, thread_id);
			}
			// no break;
		case	LOG_TYPE_INTERIM_SESSION_RECORD:
			if(session_record_limit(_instance, a_stream, log_type))
			{
				break;
			}

			if(is_append_common_field==0)
			{
				append_common_field(_instance, _handle, a_stream);
			}

			TLD_append(_handle, _instance->id2field[LOG_COMMON_VSYSTEM_ID].name, (void *)(long)_instance->vsystem_id, TLD_TYPE_LONG);
			
			set_sce_profile_ids(_instance, _handle, a_stream);
			set_shaping_profile_ids(_instance, _handle, a_stream);
			set_shaping_rule_ids(_instance, _handle, a_stream);
			set_nat_linkinfo(_instance, _handle, a_stream);
			send_log_by_type(_instance, _handle, a_stream, log_type, thread_id);
			break;
		case	LOG_TYPE_BGP_RECORD:
		case	LOG_TYPE_VOIP_RECORD:
		case	LOG_TYPE_GTPC_RECORD:
		case	LOG_TYPE_INTERNAL_RTP_RECORD:
			append_common_field(_instance, _handle, a_stream);
			TLD_append(_handle, _instance->id2field[LOG_COMMON_VSYSTEM_ID].name, (void *)(long)_instance->vsystem_id, TLD_TYPE_LONG);
			send_log_by_type(_instance, _handle, a_stream, log_type, thread_id);
			break;
		default:
			return 0;
	}
	
	TLD_cancel(handle);

	return 0;
}

int tsg_register_topic(struct tsg_log_instance_t *instance, char *topic_name)
{
	struct tsg_log_instance_t *_instance=(struct tsg_log_instance_t *)instance;
	if(_instance==NULL || _instance->mode==CLOSE || topic_name==NULL || _instance->kafka_handle==NULL)
	{
		return -1;
	}
	
	_instance->service2topic=(struct topic_stat *)realloc(_instance->service2topic, (_instance->max_service+1)*sizeof(struct topic_stat));
	_instance->service2topic[_instance->max_service].type=TLD_TYPE_MAX;
	memset(_instance->service2topic[_instance->max_service].name, 0, MAX_STRING_LEN32);
	memcpy(_instance->service2topic[_instance->max_service].name, topic_name, MIN(MAX_STRING_LEN32-1, strlen(topic_name)));

	register_topic(_instance, &(_instance->service2topic[_instance->max_service]));
	_instance->max_service++;
	
	return (_instance->max_service-1);
}

int tsg_send_payload(struct tsg_log_instance_t *instance, int topic_id, char *payload, int payload_len, int thread_id)
{
	int status=0;	
	struct tsg_log_instance_t *_instance=instance;
	
	if(_instance==NULL || _instance->mode==CLOSE)
	{
		return 0;
	}

	if(payload==NULL || payload_len<=0 || topic_id<0 || _instance->service2topic[topic_id].topic_rkt==NULL)
	{
		MASTER_LOG(_instance->logger, RLOG_LV_INFO, LOG_MODULE_SENDLOG,
									"tsg_send_log to kafka is error (payload==NULL || payload_len<=0 || topic_id<0 || _instance->service2topic[topic_id].topic_rkt==NULL), topic: %s",
									_instance->service2topic[topic_id].name
								);
		return -1;
	}

	status=rd_kafka_produce(_instance->service2topic[topic_id].topic_rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY, payload, payload_len, NULL, 0, NULL);
	if(status<0)
	{
		update_percent(_instance, topic_id, LOG_STATUS_FAIL, thread_id);
		
		MASTER_LOG(_instance->logger, RLOG_LV_INFO, LOG_MODULE_SENDLOG,
									"tsg_send_log to kafka is error of code: %d %s(%s), status: %d, topic: %s %s",
									rd_kafka_last_error(),
									rd_kafka_err2name(rd_kafka_last_error()),
									rd_kafka_err2str(rd_kafka_last_error()),
									status,
									_instance->service2topic[topic_id].name,
									payload
								);
		return -1;
	}
	else
	{
		update_percent(_instance, topic_id, LOG_STATUS_SUCCESS, thread_id);
		MASTER_LOG(_instance->logger, RLOG_LV_INFO, LOG_MODULE_SENDLOG, "log send successfully %s: %s", _instance->service2topic[topic_id].name, payload);
	}

	update_percent(_instance, topic_id, LOG_STATUS_MAX, thread_id); 

	return 0;
}

int tsg_unknown_app_id_get(struct tsg_log_instance_t *instance)
{
	if(instance!=NULL)
	{
		return instance->unknown_app_id;
	}

	return 0;
}

