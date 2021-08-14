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

#include "rapidjson/document.h"     // rapidjson's DOM-style API
#include "rapidjson/prettywriter.h" // for stringify JSON
#include "rapidjson/stringbuffer.h"


using namespace rapidjson;
using namespace std;


char TSG_SEND_LOG_VERSION_20200729=0;
struct tsg_log_instance_t *g_tsg_log_instance;

struct TLD_handle_t
{
	int thread_id;
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

static int set_linkinfo(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream)
{
	const char *linkinfo=(const char *)project_req_get_struct(a_stream, _instance->mac_linkinfo_project_id);
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

static int set_asn(struct TLD_handle_t *_handle, struct streaminfo *a_stream, char *field_name, struct asn_info *asn_info)
{
	int len=0;
	char buff[1024]={0};
	int buff_len=sizeof(buff);
	
	if(asn_info!=NULL)
	{
		len+=string_cat(buff, buff_len-len, asn_info->asn_id);
		buff[len++]='(';
		len+=string_cat(buff, buff_len-len, asn_info->organization);
		buff[len++]=')';
		TLD_append(_handle, field_name, (void *)buff, TLD_TYPE_STRING);
	}

	return 1;
}

static int set_location(struct TLD_handle_t *_handle, struct streaminfo *a_stream, char *field_name, struct location_info *location_info)
{
	int len=0;
	char buff[1024]={0};
	int buff_len=sizeof(buff);
	
	if(location_info!=NULL)
	{
		len+=string_cat(buff, buff_len-len, location_info->city_full);
		buff[len++]=',';
		len+=string_cat(buff, buff_len-len, location_info->province_full);
		buff[len++]=',';
		len+=string_cat(buff, buff_len-len, location_info->country_full);
		buff[len++]=',';
		
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

static int set_subscriber_id(struct TLD_handle_t *_handle, char *field_name, struct subscribe_id_info *subscriber)
{
	if(subscriber!=NULL && subscriber->subscribe_id!=NULL)
	{		
		TLD_append(_handle, field_name, (void *)subscriber->subscribe_id, TLD_TYPE_STRING);
		return 1;
	}
	
	return 0;
}

static int set_fqdn_category(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream, unsigned int *category_id, int category_id_num)
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

static int set_userdefine_app(struct TLD_handle_t *_handle, char *field_name, struct app_identify_result *result, TLD_TYPE type)
{
	if(result==NULL || result->app_id_num<=0)
	{
		return 0;
	}
	
	int i=0;
	char app_name[256]={0};
	
	Value array(kArrayType);
	for(i=0; i<result->app_id_num; i++)
	{
		memset(app_name, 0, sizeof(app_name));
		tsg_app_id2name(result->app_id[i], app_name, sizeof(app_name), 1);
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

static unsigned int get_max_app_id(unsigned int *app_id_array, int app_id_num)
{
	if(app_id_num<=0)
	{
		return 0;
	}
	
	int i=0;
	unsigned int max_app_id=app_id_array[0]; 

	for(i=1; i< app_id_num; i++)
	{
		if(max_app_id<app_id_array[i])
		{
			max_app_id=app_id_array[i];
		}
	}


	return max_app_id;
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

static int get_app_id_list(Value *app_id_object, struct TLD_handle_t *_handle, const char *field_name, struct app_identify_result *result)
{
	int i=0;

	if(result->app_id_num==0)
	{
		return 0;
	}
	
	Value array(kArrayType);
	for(i=0; i<result->app_id_num; i++)
	{
		Value object(kObjectType);
		object.AddMember("app_id", result->app_id[i], _handle->document->GetAllocator());
		object.AddMember("surrogate_id", result->surrogate_id[i], _handle->document->GetAllocator());
		array.PushBack(object, _handle->document->GetAllocator());
	}
	add_object_member(_handle, app_id_object, field_name, array);

	return 1;
}

static int get_app_name_list(unsigned int *app_id_array, int app_id_num, char *app_name, int app_name_len, int *flag, int is_joint_parent)
{
	int i=0;
	int offset=0;

	if((*flag)==1 || app_id_num<=0)
	{
		return 0;
	}
	
	//for(i=0; i<app_id_num; i++)
	for(i=app_id_num-1; i<app_id_num; i++)
	{
		(*flag)=1;

		if(i>0 && offset>0 && (app_name_len-offset)>0)
		{
			app_name[offset]='.';
			offset++;
		}
		
		offset+=tsg_app_id2name(app_id_array[i], app_name+offset, app_name_len-offset, is_joint_parent);
	}

	return 1;
}

static int set_app_id(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream)
{
	int app_id_flag=0;
	int l7_protocol_flag=0;
	char app_name[512]={0};
	unsigned int max_app_id=0;
	char protocol_list[256]={0};

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
		Value app_id_object(kObjectType);
		get_app_id_list(&app_id_object, _handle, "USER_DEFINE", &(label->result[ORIGIN_USER_DEFINE]));
		get_app_id_list(&app_id_object, _handle, "BUILT_IN", &(label->result[ORIGIN_BUILT_IN]));
		get_app_id_list(&app_id_object, _handle, "DKPT", &(label->result[ORIGIN_DKPT]));
		get_app_id_list(&app_id_object, _handle, "THIRD", &(label->result[ORIGIN_QM_ENGINE]));
		TLD_append(_handle, _instance->id2field[LOG_COMMON_APP_ID].name, &app_id_object, TLD_TYPE_OBJECT);

		set_userdefine_app(_handle, _instance->id2field[LOG_COMMON_USERDEFINE_APP].name, &(label->result[ORIGIN_USER_DEFINE]), TLD_TYPE_LONG);
		
		max_app_id=get_max_app_id(label->result[ORIGIN_USER_DEFINE].app_id, label->result[ORIGIN_USER_DEFINE].app_id_num);
		if(max_app_id>0)
		{
			get_app_name_list(&max_app_id, 1, app_name, sizeof(app_name), &app_id_flag, 0);
		}
		
		if(app_id_flag!=1)
		{
			get_app_name_list(label->result[ORIGIN_BUILT_IN].app_id, label->result[ORIGIN_BUILT_IN].app_id_num, app_name, sizeof(app_name), &app_id_flag, 0);
		}

		if(app_id_flag!=1)
		{
			get_app_name_list(label->result[ORIGIN_DKPT].app_id, label->result[ORIGIN_DKPT].app_id_num, app_name, sizeof(app_name), &app_id_flag, 0);
		}

		if(app_id_flag!=1)
		{
			get_app_name_list(label->result[ORIGIN_QM_ENGINE].app_id, label->result[ORIGIN_QM_ENGINE].app_id_num, app_name, sizeof(app_name), &app_id_flag, 0);
		}
		
		if(app_id_flag==1)
		{
			TLD_append(_handle, _instance->id2field[LOG_COMMON_APP_LABEL].name, (void *)app_name, TLD_TYPE_STRING);
		}
	}

	return 1;
}

static int set_vlan(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct single_layer_vlan_addr *vlan_addr, int layer_num, Value *tunnel_object, tsg_log_field_id_t id)
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

static int set_mpls(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct single_layer_mpls_addr *mpls_addr, int layer_num, Value *tunnel_object, tsg_log_field_id_t id)
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
	if (handle != NULL)
	{
		if (handle->document != NULL)
		{
			delete handle->document;
			handle->document = NULL;
		}
		free(handle);
		handle = NULL;
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
	
	return 0;	
}

struct TLD_handle_t *TLD_create(int thread_id)
{
	//struct _tld_handle *_handle=(struct _tld_handle *)dictator_malloc(thread_id, sizeof(struct _tld_handle));
	
	struct TLD_handle_t *_handle=(struct TLD_handle_t *)calloc(1, sizeof(struct TLD_handle_t));
	_handle->thread_id = thread_id;
	_handle->document = new Document();
	_handle->document->SetObject();

	return _handle;
}

static int set_user_region(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct Maat_rule_t *p_result, int thread_seq)
{
	int ret=0;
	char *user_region=NULL;

	if(p_result->action!=TSG_ACTION_NONE && p_result->serv_def_len>0)
	{
		user_region=(char *)dictator_malloc(thread_seq, p_result->serv_def_len+1);
		ret=Maat_read_rule(g_tsg_maat_feather, p_result, MAAT_RULE_SERV_DEFINE, user_region, p_result->serv_def_len+1);
		if(ret==p_result->serv_def_len)
		{
			user_region[p_result->serv_def_len]='\0';
			TLD_append(_handle, _instance->id2field[LOG_COMMON_USER_REGION].name, (void *)user_region, TLD_TYPE_STRING);
		}

		dictator_free(thread_seq, user_region);
		user_region=NULL;	
	}
	
	return 0;
}

int set_nat_linkinfo(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream, char *field_name, int project_id)
{
	const char *nat_linkinfo=(const char *)project_req_get_struct(a_stream, project_id);
	if(nat_linkinfo==NULL)
	{
		return 0;
	}

	copy_rapidjson(_handle, field_name, nat_linkinfo);

	return 0;
}

static int get_gtp_ipv4v6_port(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream, Value *object)
{
	char ip_buff[64]={0};
	if(a_stream!=NULL)
	{
		switch(a_stream->addr.addrtype)
		{
			case	ADDR_TYPE_IPV4:
					inet_ntop(AF_INET, (const void *)&(a_stream->addr.ipv4->saddr), ip_buff, sizeof(ip_buff));
					add_str_member(_handle, object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_SGW_IP].name, ip_buff);

					inet_ntop(AF_INET, (const void *)&(a_stream->addr.ipv4->daddr), ip_buff, sizeof(ip_buff));	
					add_str_member(_handle, object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_PGW_IP].name, ip_buff);
					
					add_number_member(_handle, object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_SGW_PORT].name, (unsigned int)(a_stream->addr.ipv4->source));
					add_number_member(_handle, object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_PGW_PORT].name, (unsigned int)(a_stream->addr.ipv4->dest));
					return 1;
				break;
			case	ADDR_TYPE_IPV6:
					inet_ntop(AF_INET6, (const void *)(a_stream->addr.ipv6->saddr), ip_buff, sizeof(ip_buff));
					add_str_member(_handle, object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_SGW_IP].name, ip_buff);
	
					inet_ntop(AF_INET6, (const void *)(a_stream->addr.ipv6->daddr), ip_buff, sizeof(ip_buff));
					add_str_member(_handle, object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_PGW_IP].name, ip_buff);
					
					add_number_member(_handle, object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_SGW_PORT].name, (unsigned int)(a_stream->addr.ipv6->source));
					add_number_member(_handle, object, _instance->id2field[LOG_COMMON_TUNNELS_GTP_PGW_PORT].name, (unsigned int)(a_stream->addr.ipv6->dest));
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

				ret=get_gtp_ipv4v6_port(_instance, _handle, ptmp->pfather, &tunnel_object);
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
		
		ptmp = pfather;;
		tunnel_array.PushBack(tunnel_object, _handle->document->GetAllocator());
	}

	TLD_append(_handle, _instance->id2field[LOG_COMMON_TUNNELS].name, &tunnel_array, TLD_TYPE_OBJECT);

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
	unsigned long long device_id=(unsigned long long)g_tsg_para.device_seq_in_dc;

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

int set_mirrored_pkt_bytes(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct mirrored_vlan *vlan, int compile_id)
{
	int i=0;
	for(i=0; i<vlan->compile_id_num; i++)
	{
		if(vlan->compile_id[i]==compile_id)
		{
			TLD_append(_handle, _instance->id2field[LOG_COMMON_MIRRORED_PKTS].name, (void *)(long)(vlan->mirrored_pkts), TLD_TYPE_LONG);			
			TLD_append(_handle, _instance->id2field[LOG_COMMON_MIRRORED_BYTES].name, (void *)(long)(vlan->mirrored_bytes), TLD_TYPE_LONG);
			return 1;
		}
	}

	return 0;
}

int set_mirrored_session(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream, struct Maat_rule_t *p_result)
{
	int i=0,ret=0;
	struct tcpall_context *context=(struct tcpall_context *)project_req_get_struct(a_stream, g_tsg_para.tcpall_project_id);
	if(context!=NULL && context->method_type==TSG_METHOD_TYPE_MIRRORED)
	{
		for(i=0; i<context->vlan_num; i++)
		{
			ret=set_mirrored_pkt_bytes(_instance, _handle, &(context->vlan[i]), p_result->config_id);
			if(ret==1)
			{
				return 1;
			}
		}
	}

	return 0;
}

int set_session_attributes(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream)
{
	int ret=0;
	struct session_attribute_label *attribute_label=NULL;

	attribute_label=(struct session_attribute_label *)project_req_get_struct(a_stream, _instance->session_attribute_project_id);
	if(attribute_label!=NULL)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_ESTABLISH_LATENCY_MS].name, (void *)attribute_label->establish_latency_ms, TLD_TYPE_LONG);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_HTTP_ACTION_FILESIZE].name, (void *)(long)attribute_label->http_action_file_size, TLD_TYPE_LONG);

		set_asn(_handle, a_stream, _instance->id2field[LOG_COMMON_CLINET_ASN].name, attribute_label->client_asn);		
		set_asn(_handle, a_stream, _instance->id2field[LOG_COMMON_SERVER_ASN].name, attribute_label->server_asn);
		
		set_location(_handle, a_stream, _instance->id2field[LOG_COMMON_CLINET_LOCATION].name, attribute_label->client_location);
		set_location(_handle, a_stream, _instance->id2field[LOG_COMMON_SERVER_LOCATION].name, attribute_label->server_location);

		ret=set_subscriber_id(_handle, _instance->id2field[LOG_COMMON_SUBSCRIBER_ID].name, attribute_label->client_subscribe_id);
		if(ret==0)
		{
			set_subscriber_id(_handle, _instance->id2field[LOG_COMMON_SUBSCRIBER_ID].name, attribute_label->server_subscribe_id);
		}
		
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
	int ret=0;
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

	ret=set_linkinfo(_instance, _handle, a_stream);
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
	char label_buff[128]={0};
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

	MESA_load_profile_string_def(conffile, "TSG_LOG", "LINKINFO_FROM_MAC", label_buff, sizeof(label_buff), "mirror_linkinfo_from_mac");
	_instance->mac_linkinfo_project_id=project_customer_register(label_buff, PROJECT_VAL_TYPE_STRUCT);
	if(_instance->mac_linkinfo_project_id<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "PROJECT_REGISTER", "Register %s failed.", label_buff);
	}

	MESA_load_profile_string_def(conffile, "TSG_LOG", "NAT_C2S_LINKINFO", label_buff, sizeof(label_buff), "common_link_info_c2s");
	_instance->nat_c2s_linkinfo_project_id=project_customer_register(label_buff, PROJECT_VAL_TYPE_STRUCT);
	if(_instance->nat_c2s_linkinfo_project_id<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "PROJECT_REGISTER", "Register %s failed.", label_buff);
	}

	MESA_load_profile_string_def(conffile, "TSG_LOG", "NAT_S2C_LINKINFO", label_buff, sizeof(label_buff), "common_link_info_s2c");
	_instance->nat_s2c_linkinfo_project_id=project_customer_register(label_buff, PROJECT_VAL_TYPE_STRUCT);
	if(_instance->nat_s2c_linkinfo_project_id<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "PROJECT_REGISTER", "Register %s failed.", label_buff);
	}

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

	MESA_load_profile_string_def(conffile, "SYSTEM", "TCP_LABEL", _instance->tcp_label, sizeof(_instance->tcp_label), "tcp_flow_stat");
	MESA_load_profile_string_def(conffile, "SYSTEM", "UDP_LABEL", _instance->udp_label, sizeof(_instance->udp_label), "udp_flow_stat");

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
	
	MESA_load_profile_string_def(conffile, "SYSTEM", "NIC_NAME", nic_name, sizeof(nic_name), "lo");	
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
	rd_kafka_conf_set(rdkafka_conf, "bootstrap.servers", _instance->broker_list, kafka_errstr, sizeof(kafka_errstr));
	
	if(!(kafka_handle=rd_kafka_new(RD_KAFKA_PRODUCER, rdkafka_conf, kafka_errstr, sizeof(kafka_errstr))))
	{
		MESA_handle_runtime_log(_instance->logger, RLOG_LV_FATAL, "KAFKA_INIT", "rd_kafka_new is error");
		return NULL;
	}
#if 0
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
#endif
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
	int fs_id=0;
	int i=0,status=0;
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

		if(log_msg->result[i].action==TSG_ACTION_MONITOR)
		{
			set_mirrored_session(_instance, _handle, log_msg->a_stream, &(log_msg->result[i]));
		}
		
		if(_instance->send_user_region==1)
		{
			set_user_region(_instance, _handle, &log_msg->result[i], thread_id);
		}

		if(log_msg->result[i].config_id==0 && log_msg->a_stream!=NULL)
		{			
			set_nat_linkinfo(_instance, _handle, log_msg->a_stream, _instance->id2field[LOG_COMMON_LINK_INFO_C2S].name, _instance->nat_c2s_linkinfo_project_id);
			set_nat_linkinfo(_instance, _handle, log_msg->a_stream, _instance->id2field[LOG_COMMON_LINK_INFO_S2C].name, _instance->nat_s2c_linkinfo_project_id);
		}
		
		if(log_msg->result[i].action==TSG_ACTION_DENY)
		{
			set_common_sub_action(_handle, _instance->id2field[LOG_COMMON_SUB_ACTION].name, &(log_msg->result[i]));
		}
		
		StringBuffer sb(0, 2048);
		Writer<StringBuffer> writer(sb);
		_handle->document->Accept(writer);

		status=rd_kafka_produce(_instance->topic_rkt[log_msg->result[i].service_id], RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY, (void *)sb.GetString(), sb.GetSize(), NULL, 0, NULL);
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
										sb.GetString()
									);
		}
		else
		{
			MESA_handle_runtime_log(_instance->logger,
										RLOG_LV_DEBUG,
										"TSG_SEND_LOG", 
										"log send successfully %s: %s",
										_instance->service2topic[log_msg->result[i].service_id].name,
										sb.GetString()
									);
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_SUCCESS_LOG], 0, FS_OP_ADD, 1);		
			FS_operate(g_tsg_para.fs2_handle, _instance->fs_status_ids[thread_id], 0, FS_OP_SET, _instance->send_log_percent[thread_id]);
		}

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

