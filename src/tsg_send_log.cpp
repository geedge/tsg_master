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

#include <MESA/stream.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_entry.h"
#include "tsg_send_log.h"
#include "tsg_send_log_internal.h"

char TSG_SEND_LOG_VERSION_20191121=0;
struct tsg_log_instance_t *g_tsg_log_instance;


const id2field_t tld_type[TLD_TYPE_MAX]={{TLD_TYPE_UNKNOWN,	TLD_TYPE_UNKNOWN, 	"UNKOWN"},
								 			{TLD_TYPE_LONG, 	TLD_TYPE_LONG,		"LONG"},
								 			{TLD_TYPE_STRING, 	TLD_TYPE_STRING, 	"STRING"},
											{TLD_TYPE_FILE,		TLD_TYPE_FILE,		"FILE"}
										   };

extern "C" int MESA_get_dev_ipv4(const char *device, int *ip_add);


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

int TLD_append_streaminfo(struct tsg_log_instance_t *instance, struct TLD_handle_t *handle, struct streaminfo *a_stream)
{
	int ret=0,addr_type=0;
	unsigned short tunnel_type=0;
	char nest_addr_buf[1024];
	char *addr_proto=NULL;
	unsigned long long stream_id=0;
	unsigned short c_port=0, s_port=0;
	int tunnel_type_size=sizeof(tunnel_type);
	struct layer_addr_ipv4 *ipv4=NULL;
	struct layer_addr_ipv6 *ipv6=NULL;
	char server_ip[MAX_IPV4_LEN*8]={0};
	char client_ip[MAX_IPV4_LEN*8]={0};
	
	struct TLD_handle_t *_handle=handle;
	struct tsg_log_instance_t *_instance=instance;

	if(_instance==NULL || _handle==NULL || a_stream==NULL)
	{		
		MESA_handle_runtime_log(_instance->logger,
								((a_stream==NULL) ? RLOG_LV_DEBUG: RLOG_LV_FATAL),
								"TLD_APPEND_STREAM",
								"instance==NULL || TLD_handle==NULL || addr: %s", 
								((a_stream==NULL) ? "NULL": (printaddr(&a_stream->addr, a_stream->threadnum)))
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
	
	TLD_append(_handle, _instance->id2field[LOG_COMMON_S2C_PKT_NUM].name, (void *)(long)a_stream->ptcpdetail->clientpktnum, TLD_TYPE_LONG);
	TLD_append(_handle, _instance->id2field[LOG_COMMON_S2C_BYTE_NUM].name, (void *)(long)a_stream->ptcpdetail->clientbytes, TLD_TYPE_LONG);
	TLD_append(_handle, _instance->id2field[LOG_COMMON_C2S_PKT_NUM].name, (void *)(long)a_stream->ptcpdetail->serverpktnum, TLD_TYPE_LONG);
	TLD_append(_handle, _instance->id2field[LOG_COMMON_C2S_BYTE_NUM].name, (void *)(long)a_stream->ptcpdetail->serverbytes, TLD_TYPE_LONG);

	stream_id=tsg_get_stream_id(a_stream);
	TLD_append(_handle, _instance->id2field[LOG_COMMON_STREAM_TRACE_ID].name, (void *)(long)stream_id, TLD_TYPE_LONG);
	
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
	
	return 0;
}

static int load_log_common_field(const char *filename, id2field_t *id2field, id2field_t *service2topic)
{
	int i=0;
	int ret=0,id=0;
	FILE *fp=NULL;
	char line[1024]={0};
	char field_name[64]={0};
	char type_name[32]={0};
		
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
		assert(ret==3 && id<LOG_COMMON_MAX);

		for(i=0; i<LOG_COMMON_MAX; i++)
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
					default:
						if((strncasecmp("TOPIC", type_name, strlen("TOPIC")))==0)
						{
							service2topic[id].type = TLD_TYPE_MAX;
							service2topic[id].id = id;
							memcpy(service2topic[id].name, field_name, strlen(field_name));
						}
						break;
				}
			}
		}
		memset(line, 0, sizeof(line));
	}

	fclose(fp);
	fp=NULL;

	return 0;
}

struct tsg_log_instance_t *tsg_sendlog_init(const char *conffile)
{
	int i=0,ret=0,level=30;
	char nic_name[32]={0};
	char kafka_errstr[1024]={0};
	unsigned int local_ip_nr=0;
	char log_path[MAX_STRING_LEN*4]={0};
	rd_kafka_t *kafka_handle = NULL;
	rd_kafka_conf_t *rdkafka_conf = NULL;
	rd_kafka_topic_conf_t *topic_conf;
	struct tsg_log_instance_t *_instance=NULL;
	
	_instance=(struct tsg_log_instance_t *)calloc(1, sizeof(struct tsg_log_instance_t));
	
	MESA_load_profile_int_def(conffile, "TSG_LOG", "MODE",&(_instance->mode), 0);	
	MESA_load_profile_string_def(conffile, "TSG_LOG", "COMMON_FIELD_FILE", _instance->common_field_file, sizeof(_instance->common_field_file), NULL);
	MESA_load_profile_string_def(conffile, "TSG_LOG", "BROKER_LIST", _instance->broker_list, sizeof(_instance->broker_list), NULL);

	MESA_load_profile_int_def(conffile, "TSG_LOG", "LOG_LEVEL",&(level), 30);	
	MESA_load_profile_string_def(conffile, "TSG_LOG", "LOG_PATH", log_path, sizeof(log_path), NULL);

	_instance->logger=MESA_create_runtime_log_handle(log_path, level);
	if(_instance->logger==NULL)
	{
		printf("MESA_create_runtime_log_handle failed ..., path: %s level: %d", log_path, level);
		return NULL;
	}

	MESA_load_profile_string_def(conffile, "TSG_LOG", "NIC_NAME", nic_name, sizeof(nic_name), "eth0");	
	ret=MESA_get_dev_ipv4(nic_name, (int *)&local_ip_nr);
	if(ret<0)
	{
		MESA_handle_runtime_log(_instance->logger, RLOG_LV_FATAL, "GET_LOCAL_IP", "MESA_get_dev_ipv4 is error, nic_name: %s", nic_name);
		return NULL;
	}
	inet_ntop(AF_INET,&(local_ip_nr),_instance->local_ip_str,sizeof(_instance->local_ip_str));


	rdkafka_conf = rd_kafka_conf_new();
	rd_kafka_conf_set(rdkafka_conf, "queue.buffering.max.messages", "1000000", kafka_errstr, sizeof(kafka_errstr));
	rd_kafka_conf_set(rdkafka_conf, "topic.metadata.refresh.interval.ms", "600000",kafka_errstr, sizeof(kafka_errstr));
	rd_kafka_conf_set(rdkafka_conf, "request.required.acks", "1", kafka_errstr, sizeof(kafka_errstr));
	
	if(!(kafka_handle=rd_kafka_new(RD_KAFKA_PRODUCER, rdkafka_conf, kafka_errstr, sizeof(kafka_errstr))))
	{
		MESA_handle_runtime_log(_instance->logger, RLOG_LV_FATAL, "KAFKA_INIT", "rd_kafka_new is error");
		return NULL;
	}

	if(rd_kafka_brokers_add(kafka_handle, _instance->broker_list) == 0)
	{
		MESA_handle_runtime_log(_instance->logger, RLOG_LV_FATAL, "KAFKA_INIT", "rd_kafka_brokers_add is error, broker_list: %s", _instance->broker_list);
		return NULL;
	}

	MESA_load_profile_int_def(conffile, "TSG_LOG", "MAX_SERVICE",&(_instance->max_service), 0);
	(_instance->topic_rkt)=(rd_kafka_topic_t **)calloc(1, sizeof(rd_kafka_topic_t*));
	*(_instance->topic_rkt)=(rd_kafka_topic_t *)calloc(1, (1+_instance->max_service)*sizeof(rd_kafka_topic_t*));
	
	_instance->service2topic=(id2field_t *)calloc(1, (1+_instance->max_service)*sizeof(id2field_t));
	
	load_log_common_field(_instance->common_field_file, _instance->id2field, _instance->service2topic);

	for(i=0; i<_instance->max_service+1; i++)
	{
		if(_instance->service2topic[i].type==TLD_TYPE_MAX)
		{
			topic_conf=rd_kafka_topic_conf_new();
			_instance->topic_rkt[_instance->service2topic[i].id]=rd_kafka_topic_new(kafka_handle, _instance->service2topic[i].name, topic_conf);
		}
	}
	
	return _instance;
}


int tsg_send_log(struct tsg_log_instance_t *instance, struct TLD_handle_t *handle, tsg_log_t *log_msg, int thread_id)
{
	int i=0,ret=0,status=0;
	char *payload=NULL;
	time_t cur_time;
	long common_con_duration_ms=0;
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
		MESA_handle_runtime_log(_instance->logger, RLOG_LV_INFO, "TSG_SEND_LOG", "Disable tsg_send_log.");
		return 0;
	}

	//TODO
	//common_user_tags
	//common_isp
	//common_app_label
	//common_app_id
	//common_protocol_id
	//common_has_dup_traffic
	//common_stream_error
	
	TLD_append_streaminfo(instance, handle, log_msg->a_stream);

	TLD_append(_handle, _instance->id2field[LOG_COMMON_SLED_IP].name, (void *)(_instance->local_ip_str), TLD_TYPE_STRING);

	if(log_msg->a_stream!=NULL && log_msg->a_stream->ptcpdetail!=NULL)
	{
		TLD_append(_handle, _instance->id2field[LOG_COMMON_START_TIME].name, (void *)(log_msg->a_stream->ptcpdetail->createtime), TLD_TYPE_LONG);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_END_TIME].name, (void *)(log_msg->a_stream->ptcpdetail->lastmtime), TLD_TYPE_LONG);
		
		common_con_duration_ms=log_msg->a_stream->ptcpdetail->lastmtime-log_msg->a_stream->ptcpdetail->createtime;
		TLD_append(_handle, _instance->id2field[LOG_COMMON_CON_DURATION_MS].name, (void *)(common_con_duration_ms), TLD_TYPE_LONG);
	}
	else
	{
		cur_time=time(NULL);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_START_TIME].name, (void *)cur_time, TLD_TYPE_LONG);
		TLD_append(_handle, _instance->id2field[LOG_COMMON_END_TIME].name, (void *)cur_time, TLD_TYPE_LONG);		
		TLD_append(_handle, _instance->id2field[LOG_COMMON_CON_DURATION_MS].name, (void *)(common_con_duration_ms), TLD_TYPE_LONG);
	}

#if 0
	struct vxlan_info vinfo;
	int opt_val_len = sizeof(vinfo);
	status=MESA_get_stream_opt(log_msg->a_stream, MSO_STREAM_VXLAN_INFO, &vinfo, &opt_val_len);
	if(status < 0)
	{
		MESA_handle_runtime_log(_instance->logger, RLOG_LV_DEBUG, "TSG_SEND_LOG", "tsg log: get vxlan info error, tuple4: %s",  printaddr(&log_msg->a_stream->addr, thread_id));
	}
	else
	{
		TLD_append((TLD_handle_t)_handle, _instance->id2field[LOG_COMMON_LINK_ID].name, (void *)(long)vinfo.link_id, TLD_TYPE_LONG);	
		TLD_append((TLD_handle_t)_handle, _instance->id2field[LOG_COMMON_DIRECTION].name, (void *)(long)vinfo.link_dir, TLD_TYPE_LONG);	
		TLD_append((TLD_handle_t)_handle, _instance->id2field[LOG_COMMON_DEVICE_ID].name, (void *)(long)vinfo.dev_id, TLD_TYPE_LONG);		
		TLD_append((TLD_handle_t)_handle, _instance->id2field[LOG_COMMON_ENTRANCE_ID].name, (void *)(long)vinfo.entrance_id, TLD_TYPE_LONG);	
		TLD_append((TLD_handle_t)_handle, _instance->id2field[LOG_COMMON_ENCAPSULATION].name, (void *)(long)vinfo.encap_type, TLD_TYPE_LONG);
	}
#endif

	for(i=0;i<log_msg->result_num; i++)
	{
		switch(log_msg->result[i].do_log)
		{
			case	LOG_ABORT:
				MESA_handle_runtime_log(_instance->logger, RLOG_LV_INFO,
										"TSG_SEND_LOG",
										"tsg abort log:cfg_id=%d service=%d addr=%s",
										log_msg->result[i].config_id,
										log_msg->result[i].service_id,
										printaddr(&(log_msg->a_stream->addr), thread_id));
				
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

		if(log_msg->result[i].serv_def_len<128)
		{
			TLD_append(_handle, _instance->id2field[LOG_COMMON_USER_REGION].name, (void *)(log_msg->result[i].service_defined), TLD_TYPE_STRING);
		}
		else
		{
			char *service_defined=(char *)calloc(1, log_msg->result[i].serv_def_len+1);
			ret=Maat_read_rule(g_tsg_maat_feather, &log_msg->result[i], MAAT_RULE_SERV_DEFINE, service_defined, log_msg->result[i].serv_def_len);
			if(ret==log_msg->result[i].serv_def_len)
			{
				TLD_append(_handle, _instance->id2field[LOG_COMMON_USER_REGION].name, (void *)service_defined, TLD_TYPE_STRING);			
			}
			else
			{
				MESA_handle_runtime_log(_instance->logger,
										RLOG_LV_FATAL, 
										"TSG_SEND_LOG",
										"Fetch service_defined failed, policy_id: %d service: %d action: %d addr: %s",
										log_msg->result[i].config_id,
										log_msg->result[i].service_id,
										log_msg->result[i].action,
										printaddr(&log_msg->a_stream->addr, thread_id));
			}
			free((void *)service_defined);
			service_defined=NULL;
		}

		payload = cJSON_PrintUnformatted(_handle->object);

		status = rd_kafka_produce(_instance->topic_rkt[log_msg->result[i].service_id], RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY, payload, strlen(payload), NULL, 0, NULL);			

		if(status < 0)
		{
			MESA_handle_runtime_log(_instance->logger, RLOG_LV_INFO, "TSG_SEND_LOG",
										"tsg_send_log to kafka is error, status: %d, topic: %s payload: %s",
										status, _instance->service2topic[log_msg->result[i].service_id].name, payload);
		}
		else
		{
			MESA_handle_runtime_log(_instance->logger,RLOG_LV_INFO, "TSG_SEND_LOG", 
										"log send successfully %s: %s", _instance->service2topic[log_msg->result[i].service_id].name, payload);
		}

		free(payload);
		payload=NULL;

		TLD_delete(_handle, _instance->id2field[LOG_COMMON_POLICY_ID].name);
		TLD_delete(_handle, _instance->id2field[LOG_COMMON_SERVICE].name);
		TLD_delete(_handle, _instance->id2field[LOG_COMMON_ACTION].name);
		TLD_delete(_handle, _instance->id2field[LOG_COMMON_USER_REGION].name);

		FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_LOG], 0, FS_OP_ADD, 1);
	}

	TLD_cancel(handle);

	return 0;
}

