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

int is_multi_hit_same_policy(struct Maat_rule_t *result, int *policy_id, int *policy_id_num)
{
	return 0;
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


char *log_field_id2name(struct tsg_log_instance_t *instance, tsg_log_field_id_t id)
{
	struct tsg_log_instance_t *_instance=instance;
	if(_instance!=NULL)
	{
		return _instance->id2field[id].name;
	}

	return NULL;
}

char *tsg_l7_protocol_id2name(struct tsg_log_instance_t *instance, unsigned short id)
{
	struct tsg_log_instance_t *_instance=instance;
	
	if(_instance!=NULL && id>=MIN_L7_PROTO_ID && id<=MAX_L7_PROTO_ID)
	{
		return _instance->l7_proto_id2field[id].name;
	}

	return NULL;
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

int set_common_field_from_label(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct streaminfo *a_stream)
{
	char buff[1024]={0};
	char *l7_protocol=NULL;
	struct _basic_proto_label *l7_proto_label=NULL;
	struct _location_info_t *location=NULL;
	struct _session_attribute_label_t *internal_label=NULL;

	internal_label=(struct _session_attribute_label_t *)project_req_get_struct(a_stream, _instance->internal_project_id);
	if(internal_label!=NULL)
	{		
		l7_proto_label=(struct _basic_proto_label *)project_req_get_struct(a_stream, _instance->l7_proto_project_id);
		if(l7_proto_label!=NULL)
		{
			l7_protocol=tsg_l7_protocol_id2name(_instance, l7_proto_label->proto_id);
			if(l7_protocol!=NULL)
			{
				TLD_append(_handle, _instance->id2field[LOG_COMMON_L7_PROTOCOL].name, (void *)l7_protocol, TLD_TYPE_STRING);
			}
		}
		else
		{
			l7_protocol=tsg_schema_index2string(internal_label->proto);
			if(l7_protocol!=NULL)
			{			
				TLD_append(_handle, _instance->id2field[LOG_COMMON_L7_PROTOCOL].name, (void *)l7_protocol, TLD_TYPE_STRING);
			}
			else
			{
				TLD_append(_handle, _instance->id2field[LOG_COMMON_L7_PROTOCOL].name, (void *)"UNCATEGORIZED", TLD_TYPE_STRING);
			}
		}
		
		TLD_append(_handle, _instance->id2field[LOG_COMMON_ESTABLISH_LATENCY_MS].name, (void *)internal_label->establish_latency_ms, TLD_TYPE_LONG);

		if(internal_label->client_asn!=NULL)
		{
			snprintf(buff, sizeof(buff), "%s(%s)", internal_label->client_asn->asn, internal_label->client_asn->organization);
			TLD_append(_handle, _instance->id2field[LOG_COMMON_CLINET_ASN].name, (void *)buff, TLD_TYPE_STRING);
		}
		
		if(internal_label->server_asn!=NULL)
		{
			snprintf(buff, sizeof(buff), "%s(%s)", internal_label->server_asn->asn, internal_label->server_asn->organization);
			TLD_append(_handle, _instance->id2field[LOG_COMMON_CLINET_ASN].name, (void *)buff, TLD_TYPE_STRING);
		}

		if(internal_label->client_location!=NULL)
		{
			location=internal_label->client_location;
			snprintf(buff, sizeof(buff), "%s,%s,%s", location->city_full, location->province_full, location->country_full);
			TLD_append(_handle, _instance->id2field[LOG_COMMON_CLINET_LOCATION].name, (void *)buff, TLD_TYPE_STRING);
		}

		if(internal_label->server_location!=NULL)
		{
			location=internal_label->server_location;
			snprintf(buff, sizeof(buff), "%s,%s,%s", location->city_full, location->province_full, location->country_full);
			TLD_append(_handle, _instance->id2field[LOG_COMMON_SERVER_LOCATION].name, (void *)buff, TLD_TYPE_STRING);
		}

		if(internal_label->ja3_fingerprint!=NULL)
		{
			TLD_append(_handle, _instance->id2field[LOG_SSL_JA3_FINGERPRINT].name, (void *)internal_label->ja3_fingerprint, TLD_TYPE_STRING);
		}
	}
	else
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_L7_PROTOCOL].name, (void *)"UNCATEGORIZED", TLD_TYPE_STRING);
	}

	return 0;
}

int TLD_append_streaminfo(struct tsg_log_instance_t *instance, struct TLD_handle_t *handle, struct streaminfo *a_stream)
{
	int i_or_e=0,direction=0;
	int ret=0,addr_type=0;
	unsigned short tunnel_type=0;
	char nest_addr_buf[1024];
	char *addr_proto=NULL;
	time_t cur_time;
	long common_con_duration_ms=0;
	unsigned long long stream_id=0;
	unsigned short c_port=0, s_port=0;
	int tunnel_type_size=sizeof(tunnel_type);
	struct layer_addr_ipv4 *ipv4=NULL;
	struct layer_addr_ipv6 *ipv6=NULL;
	char server_ip[MAX_IPV4_LEN*8]={0};
	char client_ip[MAX_IPV4_LEN*8]={0};
	struct tcp_flow_stat *tflow_project=NULL;
    struct udp_flow_stat *uflow_project=NULL;
	
	struct TLD_handle_t *_handle=handle;
	struct tsg_log_instance_t *_instance=instance;

	if(_instance==NULL || _handle==NULL || a_stream==NULL)
	{		
		MESA_handle_runtime_log(_instance->logger,
								RLOG_LV_DEBUG,
								"TLD_APPEND_STREAM",
								"instance==NULL || TLD_handle==NULL || addr==NULL"
								);
		return -1;
	}

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

	switch(a_stream->type)
	{
		case	STREAM_TYPE_TCP:
			tflow_project=(struct tcp_flow_stat *)project_req_get_struct(a_stream, _instance->tcp_flow_project_id);
			if(tflow_project!=NULL)
			{
				TLD_append(_handle, _instance->id2field[LOG_COMMON_S2C_PKT_NUM].name, (void *)(long)tflow_project->S2C_all_pkt, TLD_TYPE_LONG);
				TLD_append(_handle, _instance->id2field[LOG_COMMON_S2C_BYTE_NUM].name, (void *)(long)tflow_project->S2C_all_byte, TLD_TYPE_LONG);
				TLD_append(_handle, _instance->id2field[LOG_COMMON_C2S_PKT_NUM].name, (void *)(long)tflow_project->C2S_all_pkt, TLD_TYPE_LONG);
				TLD_append(_handle, _instance->id2field[LOG_COMMON_C2S_BYTE_NUM].name, (void *)(long)tflow_project->C2S_all_byte, TLD_TYPE_LONG);
			}
			break;
		case	STREAM_TYPE_UDP:
			uflow_project=(struct udp_flow_stat *)project_req_get_struct(a_stream, _instance->udp_flow_project_id);
			if(uflow_project!=NULL)
			{
				TLD_append(_handle, _instance->id2field[LOG_COMMON_S2C_PKT_NUM].name, (void *)(long)uflow_project->S2C_pkt, TLD_TYPE_LONG);
				TLD_append(_handle, _instance->id2field[LOG_COMMON_S2C_BYTE_NUM].name, (void *)(long)uflow_project->S2C_byte, TLD_TYPE_LONG);
				TLD_append(_handle, _instance->id2field[LOG_COMMON_C2S_PKT_NUM].name, (void *)(long)uflow_project->C2S_pkt, TLD_TYPE_LONG);
				TLD_append(_handle, _instance->id2field[LOG_COMMON_C2S_BYTE_NUM].name, (void *)(long)uflow_project->C2S_byte, TLD_TYPE_LONG);
			}
			break;
		default:
			break;
	}

	if(a_stream!=NULL && a_stream->ptcpdetail!=NULL)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_START_TIME].name, (void *)(a_stream->ptcpdetail->createtime), TLD_TYPE_LONG);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_END_TIME].name, (void *)(a_stream->ptcpdetail->lastmtime), TLD_TYPE_LONG);
		
		common_con_duration_ms=(a_stream->ptcpdetail->lastmtime-a_stream->ptcpdetail->createtime)*1000;
		TLD_append(_handle, _instance->id2field[LOG_COMMON_CON_DURATION_MS].name, (void *)(common_con_duration_ms), TLD_TYPE_LONG);
	}
	else
	{
		cur_time=time(NULL);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_START_TIME].name, (void *)cur_time, TLD_TYPE_LONG);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_END_TIME].name, (void *)cur_time, TLD_TYPE_LONG);		
		TLD_append(_handle, _instance->id2field[LOG_COMMON_CON_DURATION_MS].name, (void *)(common_con_duration_ms), TLD_TYPE_LONG);
	}

	stream_id=tsg_get_stream_id(a_stream);
	char stream_id_buff[128]="";
	snprintf(stream_id_buff, sizeof(stream_id_buff), "%llu", stream_id);
	TLD_append(_handle, _instance->id2field[LOG_COMMON_STREAM_TRACE_ID].name, (void *)stream_id_buff, TLD_TYPE_STRING);
	
	addr_proto=(char *)layer_addr_prefix_ntop(a_stream);
	TLD_append(_handle, _instance->id2field[LOG_COMMON_L4_PROTOCOL].name, (void *)addr_proto, TLD_TYPE_STRING);
	

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

	set_common_field_from_label(_instance, _handle, a_stream);

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
	int tmp_value=0;
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
	MESA_load_profile_string_def(conffile, "TSG_LOG", "L7_PROTO_LABEL", _instance->l7_proto_label, sizeof(_instance->l7_proto_label), "BASIC_PROTO_LABEL");

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
	
	_instance->l7_proto_project_id=project_customer_register(_instance->l7_proto_label, "struct");
	if(_instance->l7_proto_project_id<0)
	{
		MESA_handle_runtime_log(_instance->logger,
									RLOG_LV_FATAL,
									"L7_PROTO_LABEL",
									"project_customer_register is error, l7_proto_label: %s, please check etc/project.conf",
									_instance->l7_proto_label
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
	
	MESA_load_profile_string_def(conffile, "TSG_LOG", "L7_PROTO_ID_FILE", _instance->l7_proto_id_file, sizeof(_instance->l7_proto_id_file), "./tsgconf/app_l7_proto_id.conf");
	load_log_common_field(_instance->l7_proto_id_file, _instance->l7_proto_id2field, NULL, &tmp_value);

	rdkafka_conf = rd_kafka_conf_new();	
	rd_kafka_conf_set(rdkafka_conf, "queue.buffering.max.messages", _instance->send_queue_max_msg, kafka_errstr, sizeof(kafka_errstr));
	rd_kafka_conf_set(rdkafka_conf, "topic.metadata.refresh.interval.ms", _instance->refresh_interval_ms, kafka_errstr, sizeof(kafka_errstr));
	rd_kafka_conf_set(rdkafka_conf, "request.required.acks", _instance->require_ack, kafka_errstr, sizeof(kafka_errstr));
	
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
	int i=0,status=0;
	char *payload=NULL;
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
										(_instance->level<RLOG_LV_FATAL ? (log_msg->a_stream==NULL ? "" : printaddr(&(log_msg->a_stream->addr), thread_id)) : "")
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
										(_instance->level<RLOG_LV_FATAL ? (log_msg->a_stream==NULL ? "" : printaddr(&(log_msg->a_stream->addr), thread_id)) : "")
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
											(_instance->level<RLOG_LV_FATAL ? (log_msg->a_stream==NULL ? "" : printaddr(&(log_msg->a_stream->addr), thread_id)) : "")
										);
				
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
		
		if(log_msg->result[i].action==TSG_ACTION_DENY)
		{
			set_common_sub_action(_handle, _instance->id2field[LOG_COMMON_SUB_ACTION].name, &(log_msg->result[i]));
		}
		
		payload = cJSON_PrintUnformatted(_handle->object);

		status = rd_kafka_produce(_instance->topic_rkt[log_msg->result[i].service_id], RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY, payload, strlen(payload), NULL, 0, NULL);			

		if(status < 0)
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
										"tsg_send_log to kafka is error, status: %d, topic: %s payload: %s",
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

		free(payload);
		payload=NULL;

		TLD_delete(_handle, _instance->id2field[LOG_COMMON_POLICY_ID].name);
		TLD_delete(_handle, _instance->id2field[LOG_COMMON_SERVICE].name);
		TLD_delete(_handle, _instance->id2field[LOG_COMMON_ACTION].name);
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

