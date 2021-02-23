#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <unistd.h>

#include <MESA/http.h>
#include <MESA/ftp.h>
#include <MESA/ssl.h>
#include <MESA/mail.h>
#include "MESA/gquic.h"
#include <MESA/stream.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_rule.h"
#include "tsg_entry.h"
#include "tsg_send_log.h"
#include "tsg_statistic.h"
#include "tsg_send_log_internal.h"
#include "tsg_ssl_utils.h"
#include "tsg_ssh_utils.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define GIT_VERSION_CATTER(v) __attribute__((__used__)) const char * GIT_VERSION_##v = NULL
#define GIT_VERSION_EXPEND(v) GIT_VERSION_CATTER(v)

/* VERSION TAG */
#ifdef GIT_VERSION
GIT_VERSION_EXPEND(GIT_VERSION);
#else
static __attribute__((__used__)) const char * GIT_VERSION_UNKNOWN = NULL;
#endif
#undef GIT_VERSION_CATTER
#undef GIT_VERSION_EXPEND

#ifdef __cplusplus
}
#endif


char TSG_MASTER_VERSION_20200805=0;
const char *tsg_conffile="tsgconf/main.conf";
g_tsg_para_t g_tsg_para;

id2field_t g_tsg_fs2_field[TSG_FS2_MAX]={{TLD_TYPE_UNKNOWN, TSG_FS2_TCP_LINKS, "tcp_links"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_UDP_LINKS, "udp_links"}, 
										 {TLD_TYPE_UNKNOWN, TSG_FS2_BYPASS, "bypass"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_HIT_ADDR, "hit_addr"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_HIT_SHARE, "hit_share"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_INTERCEPT, "intercept"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_SUCCESS_LOG, "success_log"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_FAILED_LOG, "failed_log"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_DROP_LOG, "drop_log"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_ABORT_ALLOW, "abort_allow"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_ABORT_DENY, "abort_deny"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_ABORT_MONITOR, "abort_monitor"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_ABORT_INTERCEPT, "abort_intercept"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_ABORT_UNKNOWN, "abort_unknown"}
										};

id2field_t g_tsg_proto_name2id[PROTO_MAX]={{TLD_TYPE_UNKNOWN, PROTO_UNKONWN, "unknown"}, 
										 {TLD_TYPE_UNKNOWN, PROTO_IPv4, "IPV4"},
										 {TLD_TYPE_UNKNOWN, PROTO_IPv6, "IPV6"},
										 {TLD_TYPE_UNKNOWN, PROTO_TCP, "TCP"},
										 {TLD_TYPE_UNKNOWN, PROTO_UDP, "UDP"},
										 {TLD_TYPE_UNKNOWN, PROTO_HTTP, "HTTP"},
										 {TLD_TYPE_UNKNOWN, PROTO_MAIL, "MAIL"},
										 {TLD_TYPE_UNKNOWN, PROTO_DNS, "DNS"},
										 {TLD_TYPE_UNKNOWN, PROTO_FTP, "FTP"},
										 {TLD_TYPE_UNKNOWN, PROTO_SSL, "SSL"},
										 {TLD_TYPE_UNKNOWN, PROTO_SIP, "SIP"},
										 {TLD_TYPE_UNKNOWN, PROTO_BGP, "BGP"},
										 {TLD_TYPE_UNKNOWN, PROTO_STREAMING_MEDIA, "STREAMING_MEDIA"},
										 {TLD_TYPE_UNKNOWN, PROTO_QUIC, "QUIC"},
										 {TLD_TYPE_UNKNOWN, PROTO_SSH, "SSH"},
										 {TLD_TYPE_UNKNOWN, PROTO_SMTP, "SMTP"},
										 {TLD_TYPE_UNKNOWN, PROTO_IMAP, "IMAP"},
										 {TLD_TYPE_UNKNOWN, PROTO_POP3, "POP3"},
										 {TLD_TYPE_UNKNOWN, PROTO_RTP, "RTP"}
										};

#define	DECCRYPTION_EXCLUSION_ALLOW_POLICY_ID	1

static int tsg_get_sn(char *filename, char *device_sn, int device_sn_len)
{
	int ret=0,flags=0;
	char buff[4096]={0};
	cJSON *object=NULL;
	
	FILE *fp=fopen(filename, "rb");
	if(fp)
	{
		ret=fread(buff, sizeof(buff), 1, fp);
		if(ret<(int)sizeof(buff))
		{
			object=cJSON_Parse(buff);
			if(object)
			{
				cJSON *item=cJSON_GetObjectItem(object, "sn");
				if(item && item->valuestring!=NULL && device_sn_len>(int)strlen(item->valuestring))
				{
					flags=1;
					memcpy(device_sn, item->valuestring, strlen(item->valuestring));
				}
				cJSON_Delete(object);
				object=NULL;
			}
		}

		fclose(fp);
		fp=NULL;
	}

	return flags;
}

static int get_device_id(char *command, int entrance_id)
{
	FILE *fp=NULL; 
	char buffer[128]={0};

	fp=popen(command, "r"); 
	if(fp)
	{
		fgets(buffer,sizeof(buffer),fp); 
    	pclose(fp);
	}
	
	return (entrance_id<<7)+(atoi(buffer)%128);
}

static int tsg_proto_name2flag(char *proto_list, int *flag)
{
	int i=0;
	char *s=NULL,*e=NULL;

	s=proto_list;
	while(s)
	{
		e=index(s, ';');
		if(!e)
		{
			break;
		}

		for(i=0; i< PROTO_MAX; i++)
		{
			if((memcmp(s, g_tsg_proto_name2id[i].name, e-s))==0)
			{
				*flag|=(1<<g_tsg_proto_name2id[i].id);
				break;
			}
		}
		
		s=e+1;	
	}

	return 0;
}

static void free_policy_label(int thread_seq, void *project_req_value)
{
	dictator_free(thread_seq, project_req_value);
	project_req_value=NULL;
}

static void free_context(void **pme, int thread_seq)
{
	struct _master_context *_context=(struct _master_context *)*pme;

	if(_context!=NULL)
	{
		if(_context->result!=NULL)
		{
			dictator_free(thread_seq, (void *)_context->result);
			_context->result=NULL;
		}

		dictator_free(thread_seq, (void *)_context);
		_context=NULL;
		*pme=NULL;
	}
}

static int init_context(void **pme, tsg_protocol_t proto, struct Maat_rule_t *p_result, int thread_seq)
{	
	struct _master_context *_context=(struct _master_context *)*pme;

	*pme=dictator_malloc(thread_seq, sizeof(struct _master_context));
	_context=(struct _master_context *)*pme;
	_context->proto=proto;
	_context->domain_len=0;
	memset(_context->domain, 0, sizeof(_context->domain));
	
	_context->hit_cnt=1;
	_context->result=(struct Maat_rule_t *)dictator_malloc(thread_seq, sizeof(struct Maat_rule_t));
	memcpy(_context->result, p_result, sizeof(struct Maat_rule_t));

	return 0;
}

char *tsg_schema_index2string(tsg_protocol_t proto)
{
	char *schema_field_value=NULL;

	switch(proto)
	{
		case	PROTO_HTTP:
			schema_field_value=(char *)"HTTP";
			break;
		case	PROTO_SSL:
			schema_field_value=(char *)"SSL";
			break;
		case	PROTO_DNS:
			schema_field_value=(char *)"DNS";
			break;
		case	PROTO_FTP:
			schema_field_value=(char *)"FTP";
			break;
		case	PROTO_BGP:
			schema_field_value=(char *)"BGP";
			break;
		case	PROTO_SIP:
			schema_field_value=(char *)"SIP";
			break;
		case	PROTO_MAIL:
			schema_field_value=(char *)"MAIL";
			break;
		case	PROTO_STREAMING_MEDIA:
			schema_field_value=(char *)"STREAMING_MEDIA";
			break;
		case	PROTO_QUIC:
			schema_field_value=(char *)"QUIC";
			break;
		case	PROTO_SSH:
			schema_field_value=(char *)"SSH";
			break;
		case	PROTO_IMAP:
			schema_field_value=(char *)"IMAP";
			break;
		case	PROTO_POP3:
			schema_field_value=(char *)"POP3";
			break;
		case	PROTO_SMTP:
			schema_field_value=(char *)"SMTP";
			break;
		case	PROTO_RTP:
			schema_field_value=(char *)"RTP";
			break;
		default:
			break;
	}

	return schema_field_value;
}

static int master_send_log(struct streaminfo *a_stream, struct Maat_rule_t *p_result, int result_num, struct _identify_info *identify_info, int thread_seq)
{
	tsg_log_t log_msg;	
	char *domain_field_name=NULL;
	char *schema_field_name=NULL;
	char *schema_field_value=NULL;
	struct TLD_handle_t *TLD_handle=NULL;

	TLD_handle=TLD_create(thread_seq);
	if(identify_info!=NULL && (identify_info->proto>PROTO_UNKONWN) && (identify_info->proto<PROTO_MAX))
	{
		schema_field_name=log_field_id2name(g_tsg_log_instance, LOG_COMMON_SCHAME_TYPE);

		if(identify_info->proto==PROTO_IMAP || identify_info->proto==PROTO_SMTP || identify_info->proto==PROTO_POP3)
		{
			schema_field_value=tsg_schema_index2string(PROTO_MAIL);
		}
		else
		{
			schema_field_value=tsg_schema_index2string(identify_info->proto);
		}
		
		if(schema_field_value!=NULL)
		{
			TLD_append(TLD_handle, schema_field_name, (void *)schema_field_value, TLD_TYPE_STRING);
		}

		switch(identify_info->proto)
		{
			case	PROTO_HTTP:
				domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_HTTP_HOST);
				TLD_append(TLD_handle, domain_field_name, (void *)identify_info->domain, TLD_TYPE_STRING);
				break;
			case	PROTO_SSL:
				domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_SSL_SNI);
				TLD_append(TLD_handle, domain_field_name, (void *)identify_info->domain, TLD_TYPE_STRING);
				break;
			case	PROTO_QUIC:
				domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_QUIC_SNI);
				TLD_append(TLD_handle, domain_field_name, (void *)identify_info->domain, TLD_TYPE_STRING);
				break;
			default:
				break;
		}
	}
	
	log_msg.a_stream=a_stream;
	log_msg.result=p_result;
	log_msg.result_num=result_num;
	tsg_send_log(g_tsg_log_instance, TLD_handle, &log_msg, thread_seq);
	
	if(p_result->config_id!=DECCRYPTION_EXCLUSION_ALLOW_POLICY_ID)
	{
		tsg_set_policy_flow(a_stream, p_result, thread_seq);
	}
	
	return 1;
}

int tsg_set_device_id_to_telegraf(char *device_sn)
{
	char buff[128]={0};
	FILE *fp=NULL;

	if(device_sn)
	{
		fp=fopen("/etc/default/telegraf", "wb");
		if(fp)
		{
			snprintf(buff, sizeof(buff), "device_id=\"%s\"\n", device_sn);
			fwrite(buff, strlen(buff), 1, fp);
			fclose(fp);
			fp=NULL;
			return 0;
		}
	}

	return -1;
}

static void free_session_attribute_label(int thread_seq, void *project_req_value)
{
	struct _session_attribute_label_t *label=(struct _session_attribute_label_t *)project_req_value;

	if(label!=NULL)
	{
		if(label->client_asn!=NULL)
		{
			ASN_free_data(label->client_asn->table_id, (MAAT_PLUGIN_EX_DATA *)&(label->client_asn), 0, g_tsg_para.logger);
			label->client_asn=NULL;
		}

		if(label->server_asn!=NULL)
		{
			ASN_free_data(label->server_asn->table_id, (MAAT_PLUGIN_EX_DATA *)&(label->server_asn), 0, g_tsg_para.logger);
			label->server_asn=NULL;
		}

		if(label->client_location!=NULL)
		{
			location_free_data(label->client_location->table_id, (MAAT_PLUGIN_EX_DATA *)&(label->client_location), 0, g_tsg_para.logger);
			label->client_location=NULL;
		}

		if(label->server_location!=NULL)
		{
			location_free_data(label->server_location->table_id, (MAAT_PLUGIN_EX_DATA *)&(label->server_location), 0, g_tsg_para.logger);
			label->server_location=NULL;
		}

		if(label->client_subscribe_id!=NULL)
		{
			subscribe_id_free_data(label->client_subscribe_id->table_id, (MAAT_PLUGIN_EX_DATA *)&label->client_subscribe_id, 0, g_tsg_para.logger);
			label->client_subscribe_id=NULL;
		}

		if(label->server_subscribe_id!=NULL)
		{
			subscribe_id_free_data(label->server_subscribe_id->table_id, (MAAT_PLUGIN_EX_DATA *)&label->server_subscribe_id, 0, g_tsg_para.logger);
			label->server_subscribe_id=NULL;
		}

		if(label->ja3_fingerprint!=NULL)
		{
			dictator_free(thread_seq, (void *)label->ja3_fingerprint);
			label->ja3_fingerprint=NULL;
		}
		
		dictator_free(thread_seq, project_req_value);
		project_req_value=NULL;
	}
}

static struct Maat_rule_t *tsg_policy_decision_criteria(struct streaminfo *a_stream, Maat_rule_t *result, int result_num, struct _identify_info *identify_info, int thread_seq)
{
	int i=0,ret=0;
	Maat_rule_t tmp_result;
	Maat_rule_t *p_result=NULL;
	Maat_rule_t *q_result=NULL;
	scan_status_t mid=NULL;
	
	if(result==NULL || result_num<=0)
	{
		return NULL;
	}
#if 0
	ret=Maat_rule_sort_by_evaluation_order(g_tsg_maat_feather, result, result_num);
	if(ret!=result_num)
	{
		return NULL;
	}

	p_result=&result[0];
	
	if(p_result->action==TSG_ACTION_INTERCEPT && domain!=NULL && domain_len>0)
	{
		ret=Maat_full_scan_string(g_tsg_maat_feather,
									g_tsg_para.table_id[TABLE_EXCLUSION_SSL_SNI],
									CHARSET_UTF8,
									domain,
									domain_len,
									&tmp_result,
									NULL,
									1,
									&mid,
									thread_seq);
		if(ret>0)
		{
			p_result=NULL;
			for(i=1; i<result_num; i++)
			{
				if(p_result->action==TSG_ACTION_INTERCEPT)
				{
					continue;
				}
				p_result=&result[i];
			}
		}
	}
	
	return 	p_result;
#endif

	for(i=0; i<result_num; i++)
	{
		if(p_result==NULL)
		{
			p_result=&result[i];
			continue;
		}
		
		if((unsigned char)result[i].action>(unsigned char)p_result->action)
		{
			if(p_result->action!=TSG_ACTION_INTERCEPT)
			{
				q_result=p_result;
			}
			p_result=&result[i];
			continue;
		}

		if((unsigned char)result[i].action<(unsigned char)p_result->action && (unsigned char)result[i].action!=TSG_ACTION_INTERCEPT)
		{		
			q_result=&result[i];
		}
		
		if(result[i].action==p_result->action)
		{
			if(result[i].config_id>p_result->config_id)
			{
				p_result=&result[i];
			}
		}	
	}

	if(p_result->action==TSG_ACTION_INTERCEPT && identify_info!=NULL && identify_info->domain_len>0)
	{
		ret=Maat_full_scan_string(g_tsg_maat_feather,
									g_tsg_para.table_id[TABLE_EXCLUSION_SSL_SNI],
									CHARSET_UTF8,
									identify_info->domain,
									identify_info->domain_len,
									&tmp_result,
									NULL,
									1,
									&mid,
									thread_seq);

		if(mid!=NULL)
		{
			Maat_clean_status(&mid);
			mid=NULL;
		}

		if(ret>0)
		{	
			MESA_handle_runtime_log(g_tsg_para.logger,
										RLOG_LV_DEBUG,
										"EXCLUSION_SSL_SNI",
										"Hit %s policy_id: %d service: %d action: %d Decryption Exclusion: [ policy_id: %d service: %d action: %d ] addr: %s",
										identify_info->domain,
										tmp_result.config_id,
										tmp_result.service_id,
										(unsigned char)tmp_result.action,
										p_result->config_id,
										p_result->service_id,
										(unsigned char)p_result->action,
										(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_stream->addr, thread_seq) : "")
									);
			
			p_result=q_result;
			master_send_log(a_stream, &tmp_result, 1, identify_info, thread_seq);
		}
		else
		{
			MESA_handle_runtime_log(g_tsg_para.logger,
										RLOG_LV_DEBUG,
										"EXCLUSION_SSL_SNI",
										"Not hit %s stream_dir: %d addr: %s  scan ret: %d",
										identify_info->domain,
										a_stream->dir,
										(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_stream->addr, thread_seq) : ""),
										ret
									);
		}
	}

	return p_result;
}

static int identify_application_protocol(struct streaminfo *a_stream, struct _identify_info *identify_info, struct _session_attribute_label_t *attribute_label, void *a_packet)
{
	int ret=0;                            
	identify_info->proto = PROTO_UNKONWN;

	switch(a_stream->type)
	{
		case	STREAM_TYPE_TCP:
			if(g_tsg_para.proto_flag&(1<<PROTO_HTTP))  //http
			{
				char *host=NULL;
				ret=http_host_parser((char *)a_stream->ptcpdetail->pdata, (unsigned int)a_stream->ptcpdetail->datalen, a_stream->curdir, &host);
				if(ret>=0)
				{
					identify_info->proto=PROTO_HTTP;
					if(ret>0 && host!=NULL)
					{
						identify_info->domain_len=MIN(ret, (int)sizeof(identify_info->domain) - 1);
						strncpy(identify_info->domain, host, identify_info->domain_len);
					}
					else
					{
						identify_info->domain_len=0;
					}
					return 1;
				}
			}

			if(g_tsg_para.proto_flag&(1<<PROTO_SSL))  //ssl
			{
				enum chello_parse_result chello_status = CHELLO_PARSE_INVALID_FORMAT;
				struct ssl_chello *chello = NULL;

				chello=ssl_chello_parse((unsigned char *)a_stream->ptcpdetail->pdata, (unsigned int)a_stream->ptcpdetail->datalen, &chello_status);
				if(chello_status==CHELLO_PARSE_SUCCESS)
				{
					identify_info->proto=PROTO_SSL;
					if(chello->sni==NULL)
					{
						identify_info->domain_len = 0;
					}
					else
					{
						identify_info->domain_len = strnlen(chello->sni, sizeof(identify_info->domain) - 1);
						strncpy(identify_info->domain, chello->sni, identify_info->domain_len);
					}
					
					ssl_chello_free(chello);

					struct _ssl_ja3_info_t *ja3_info=NULL;
					ja3_info=ssl_get_ja3_fingerprint(a_stream, (unsigned char *)a_stream->ptcpdetail->pdata, (unsigned int)a_stream->ptcpdetail->datalen, a_stream->threadnum);
					if(ja3_info!=NULL)
					{
						if(ja3_info->sni==NULL || ja3_info->sni_len<=0)
						{
							identify_info->domain_len = 0;
						}
						else
						{
							identify_info->domain_len = strnlen(ja3_info->sni, sizeof(identify_info->domain) - 1);
							strncpy(identify_info->domain, ja3_info->sni, identify_info->domain_len);
						}

						if(attribute_label!=NULL && ja3_info->fp!=NULL && ja3_info->fp_len>0)
						{
							attribute_label->ja3_fingerprint=(char *)dictator_malloc(a_stream->threadnum, ja3_info->fp_len+1);
							memcpy(attribute_label->ja3_fingerprint, ja3_info->fp, ja3_info->fp_len);
							attribute_label->ja3_fingerprint[ja3_info->fp_len]='\0';
						}

						return 1;
					}
					
					return 1;
				}
				
			    ssl_chello_free(chello);
			}
	
			if(g_tsg_para.proto_flag&(1<<PROTO_FTP))  //ftp
			{
				ret=ftp_control_identify(a_stream);
				if(ret>0)
				{
					identify_info->proto=PROTO_FTP;
					return 1;
				}
			}
			
			if(g_tsg_para.proto_flag&(1<<PROTO_MAIL))  //mail
			{
				ret=mail_protocol_identify_by_first_payload(a_stream,(char *)a_stream->ptcpdetail->pdata, a_stream->ptcpdetail->datalen, a_stream->threadnum);
				if(ret>0)
				{
					switch(ret)
					{
						case	SMTP_PROTOCOL:
							identify_info->proto=PROTO_SMTP;
							return 1;
							break;
						case	POP3_PROTOCOL:
							identify_info->proto=PROTO_POP3;
							return 1;
							break;
						case	IMAP_PROTOCOL:
							identify_info->proto=PROTO_IMAP;
							return 1;
							break;
						default:
							break;
					}
				}
			}

			break;
		case	STREAM_TYPE_UDP:
			if(g_tsg_para.proto_flag&(1<<PROTO_DNS))  //dns
			{
				struct stream_tuple4_v4 *tpl4 = NULL;
				struct stream_tuple4_v6 *tpl6 = NULL;

				switch(a_stream->addr.addrtype)
				{
					case ADDR_TYPE_IPV4:
						tpl4=a_stream->addr.tuple4_v4;
						if((ntohs(tpl4->source)==53) || (ntohs(tpl4->dest)==53))
						{
							identify_info->proto=PROTO_DNS;
							return 1;
						}
						break;
					case ADDR_TYPE_IPV6:
						tpl6=a_stream->addr.tuple4_v6;
						if((ntohs(tpl6->source)==53) || (ntohs(tpl6->dest)==53))
						{
							identify_info->proto=PROTO_DNS;
							return 1;
						}
						break;
					default:
						break;
				}
			}
				
			if(g_tsg_para.proto_flag&(1<<PROTO_SSH))  //ssh
			{
				ret = ssh_protocol_identify((unsigned char *)a_stream->ptcpdetail->pdata, (unsigned int)a_stream->ptcpdetail->datalen,g_tsg_para.logger);
				if(ret > 0)
				{
					identify_info->proto=PROTO_SSH;
					return 1;
				}
			}
			
			if(g_tsg_para.proto_flag&(1<<PROTO_QUIC))  //quic
			{
				ret=quic_protocol_identify(a_stream, a_packet, identify_info->domain, sizeof(identify_info->domain));
				if(ret>=0)
				{
					identify_info->proto=PROTO_QUIC;
					identify_info->domain_len=ret;
					return 1;
				}
			}
			break;
		default:
			break;
	}
	
	return ret;
}

extern "C" char TSG_MASTER_TCP_ENTRY(struct streaminfo *a_tcp, void **pme, int thread_seq,void *a_packet)
{
	int i=0,ret=0,hit_num=0;
	struct timespec tv;
	int state=APP_STATE_GIVEME;
	scan_status_t mid=NULL;
	Maat_rule_t *p_result=NULL;
	//Maat_rule_t *q_result=NULL;
	struct _identify_info identify_info;
	Maat_rule_t all_result[MAX_RESULT_NUM];
	policy_priority_label_t *priority_label=NULL;	
	struct _master_context *_context=(struct _master_context *)*pme;
	struct _session_attribute_label_t *internal_label=NULL;
	unsigned long long create_time=0;
	int size=sizeof(create_time);
	switch(a_tcp->opstate)
	{
		case	OP_STATE_PENDING:
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_TCP_LINKS], 0, FS_OP_ADD, 1);

			internal_label=(struct _session_attribute_label_t *)dictator_malloc(thread_seq, sizeof(struct _session_attribute_label_t));
			memset(internal_label, 0, sizeof(struct _session_attribute_label_t));
			
			memset(&identify_info, 0, sizeof(identify_info));
			identify_application_protocol(a_tcp, &identify_info, internal_label, a_packet);
			internal_label->proto=identify_info.proto;

			ret=MESA_get_stream_opt(a_tcp, MSO_STREAM_CREATE_TIMESTAMP_MS, (void *)&create_time, &size);
			if(ret>=0)
			{
				clock_gettime(CLOCK_REALTIME, &tv);
				internal_label->establish_latency_ms=tv.tv_sec*1000+tv.tv_nsec/1000/1000 - create_time;
			}

			ret=project_req_add_struct(a_tcp, g_tsg_para.internal_project_id, (const void *)internal_label);
			if(ret<0)
			{
				MESA_handle_runtime_log(g_tsg_para.logger,
										RLOG_LV_FATAL,
										"PROJECT_ADD",
										"Add internal_label failed, establish latency ms: %llu proto: %d addr: %s",
										internal_label->establish_latency_ms,
										internal_label->proto,
										(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_tcp->addr, thread_seq) : "")
										);
			}
			else
			{
				MESA_handle_runtime_log(g_tsg_para.logger,
										RLOG_LV_DEBUG,
										"PROJECT_ADD",
										"Add internal_label successfully, establish latency ms: %llu proto: %d addr: %s",
										internal_label->establish_latency_ms,
										internal_label->proto,
										(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_tcp->addr, thread_seq) : "")
										);	
			}
			
			ret=tsg_scan_nesting_addr(g_tsg_maat_feather, a_tcp, identify_info.proto, &mid, all_result+hit_num, MAX_RESULT_NUM-hit_num);
			if(ret>0)
			{
				hit_num+=ret;
				FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_HIT_ADDR], 0, FS_OP_ADD, 1);		
			}

			if(identify_info.proto==PROTO_HTTP || identify_info.proto==PROTO_SSL)
			{
				ret=tsg_scan_shared_policy(g_tsg_maat_feather, &identify_info, all_result+hit_num, MAX_RESULT_NUM-hit_num, &mid, thread_seq);
				if(ret>0)
				{
					FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_HIT_SHARE], 0, FS_OP_ADD, 1);
					MESA_handle_runtime_log(g_tsg_para.logger,
												RLOG_LV_DEBUG,
												"SCAN_FQDN",
												"Hit %s: %s policy_id: %d service: %d action: %d addr: %s",
												(identify_info.proto==PROTO_HTTP) ? "host" : "sni",
												identify_info.domain,
												all_result[hit_num].config_id,
												all_result[hit_num].service_id,
												(unsigned char)all_result[hit_num].action,
												(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_tcp->addr, thread_seq) : "")
											);

					hit_num+=ret;
				}
				else
				{
					MESA_handle_runtime_log(g_tsg_para.logger,
												RLOG_LV_DEBUG,
												"SCAN_FQDN",
												"Not hit %s: %s ret: %d stream_dir: %d addr: %s",
												(ret==-1) ?  "NULL" : ((identify_info.proto==PROTO_HTTP) ? "host" : "sni"),
												(ret==-1) ? "NULL" : identify_info.domain,
												ret,
												a_tcp->dir,
												(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_tcp->addr, thread_seq) : "")
											);
				}

				if(strlen(identify_info.domain)>0 && identify_info.domain_len>0)
				{
					internal_label->fqdn_category_id_num=tsg_get_fqdn_category_id(g_tsg_maat_feather, 
																					identify_info.domain,
																					internal_label->fqdn_category_id,
																					MAX_CATEGORY_ID_NUM,
																					g_tsg_para.logger,
																					thread_seq
																				);
				}

				for(i=0; i<internal_label->fqdn_category_id_num; i++)
				{
					int idx=identify_info.proto==PROTO_HTTP ? TABLE_HTTP_HOST : TABLE_SSL_SNI;
					ret=Maat_scan_intval(g_tsg_maat_feather,
											g_tsg_para.table_id[idx],
											(unsigned int)internal_label->fqdn_category_id[i],
											all_result+hit_num,
											MAX_RESULT_NUM-hit_num,
											&mid,
											thread_seq
										);
					if(ret>0)
					{
						MESA_handle_runtime_log(g_tsg_para.logger,
												RLOG_LV_DEBUG,
												"SCAN_FQDN_CAT",
												"Hit %s: %s category_id: %d policy_id: %d service: %d action: %d addr: %s",
												(identify_info.proto==PROTO_HTTP) ? "host" : "sni",
												identify_info.domain,
												internal_label->fqdn_category_id[i],
												all_result[hit_num].config_id,
												all_result[hit_num].service_id,
												(unsigned char)all_result[hit_num].action,
												(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_tcp->addr, thread_seq) : "")
											);
						hit_num+=ret;
					}
					else
					{
						MESA_handle_runtime_log(g_tsg_para.logger,
												RLOG_LV_DEBUG,
												"SCAN_FQDN_CAT",
												"Not hit %s: %s category_id: %d ret: %d stream_dir: %d addr: %s",
												(ret==-1) ?  "NULL" : ((identify_info.proto==PROTO_HTTP) ? "host" : "sni"),
												(ret==-1) ? "NULL" : identify_info.domain,
												internal_label->fqdn_category_id[i],
												ret,
												a_tcp->dir,
												(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_tcp->addr, thread_seq) : "")
											);
					}
				}
			}

			if(mid!=NULL)
			{
				Maat_clean_status(&mid);
				mid=NULL;
			}
			
			p_result=tsg_policy_decision_criteria(a_tcp, all_result, hit_num, &identify_info, thread_seq);
			
			if(p_result!=NULL)
			{
				switch((unsigned char)p_result->action)
				{
					case	TSG_ACTION_DENY:
						/* support block/alert(deny), Do action in fw_http_plug */
						break;
					case	TSG_ACTION_MONITOR:
						break;
					case	TSG_ACTION_BYPASS:
						init_context(pme, identify_info.proto, p_result, thread_seq);
						if(identify_info.proto>PROTO_UNKONWN && identify_info.proto<PROTO_MAX)
						{
							_context=(struct _master_context *)*pme;
							memcpy(_context->domain, identify_info.domain, identify_info.domain_len);
							_context->domain_len=identify_info.domain_len;
						}
						
						MESA_handle_runtime_log(g_tsg_para.logger,
												RLOG_LV_DEBUG,
												"ALLOW",
												"Hit allow policy, policy_id: %d service: %d action: %d addr: %s",
												p_result[0].config_id,
												p_result[0].service_id,
												(unsigned char)p_result[0].action,
												(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_tcp->addr, thread_seq) : "")
												);
						
						state=APP_STATE_GIVEME|APP_STATE_KILL_OTHER;
						FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_BYPASS], 0, FS_OP_ADD, 1);
						break;
					case	TSG_ACTION_INTERCEPT:
						FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_INTERCEPT], 0, FS_OP_ADD, 1);
						
						priority_label=(policy_priority_label_t *)dictator_malloc(thread_seq, sizeof(policy_priority_label_t));
						
						priority_label->result_num=1;
						priority_label->result_type=PULL_KNI_RESULT;
						priority_label->proto=identify_info.proto;
						priority_label->domain_len=identify_info.domain_len;
						memcpy(priority_label->domain, identify_info.domain, identify_info.domain_len);
						memcpy(priority_label->result, p_result, sizeof(struct Maat_rule_t));
						
						ret=project_req_add_struct(a_tcp, g_tsg_para.priority_project_id, (void *)priority_label);
						if(ret<0)
						{
							free_policy_label(thread_seq, (void *)priority_label);
							MESA_handle_runtime_log(g_tsg_para.logger,
													RLOG_LV_FATAL,
													"PROJECT_ADD",
													"Add policy_priority_label failed, intercept policy, policy_id: %d action: %d addr: %s",
													priority_label->result[0].config_id,
													(unsigned char)priority_label->result[0].action,
													(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_tcp->addr, thread_seq) : "")
													);
						}
						
						MESA_handle_runtime_log(g_tsg_para.logger, 
												RLOG_LV_DEBUG,
												"INTERCEPT",
												"Hit intercept policy, policy_id: %d action: %d addr: %s",
												priority_label->result[0].config_id,
												(unsigned char)priority_label->result[0].action,
												(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_tcp->addr, thread_seq) : "")
												);
						return APP_STATE_DROPME|APP_STATE_KILL_OTHER;
						break;
					case	TSG_ACTION_NONE:
					default:
						return APP_STATE_DROPME;
						break;
				}
			}

			break;
		case	OP_STATE_DATA:
			break;
		case	OP_STATE_CLOSE:
			if(_context!=NULL)
			{
				if(_context->hit_cnt>0 && _context->result!=NULL)
				{
					memset(&identify_info, 0, sizeof(identify_info));
					identify_info.proto=_context->proto;
					if(_context->domain_len>0)
					{
						memcpy(identify_info.domain, _context->domain, _context->domain_len);
						identify_info.domain_len=_context->domain_len;
					}
					master_send_log(a_tcp, _context->result, _context->hit_cnt, &identify_info, thread_seq);
					free_context(pme, thread_seq);
				}
			}
		default:
			break;
	}

	return state;
}

extern "C" char TSG_MASTER_UDP_ENTRY(struct streaminfo *a_udp, void **pme, int thread_seq,void *a_packet)
{
	int i=0,ret=0;
	int hit_num=0;
	scan_status_t mid=NULL;
	int state=APP_STATE_GIVEME;
	Maat_rule_t *p_result=NULL;
	Maat_rule_t result[MAX_RESULT_NUM]={0};
	struct _identify_info identify_info;
	struct _master_context *_context=(struct _master_context *)*pme;
	struct _session_attribute_label_t *internal_label=NULL;

	switch(a_udp->opstate)
	{
		case	OP_STATE_PENDING:			
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_UDP_LINKS], 0, FS_OP_ADD, 1);
			memset(&identify_info, 0, sizeof(identify_info));
			identify_application_protocol(a_udp, &identify_info, NULL, a_packet);

			internal_label=(struct _session_attribute_label_t *)dictator_malloc(thread_seq, sizeof(struct _session_attribute_label_t));
			memset(internal_label, 0, sizeof(struct _session_attribute_label_t));
			internal_label->proto=identify_info.proto;
			
			ret=project_req_add_struct(a_udp, g_tsg_para.internal_project_id, (const void *)internal_label);
			if(ret<0)
			{
				MESA_handle_runtime_log(g_tsg_para.logger,
										RLOG_LV_FATAL,
										"PROJECT_ADD",
										"Add internal_label failed, proto: %d addr: %s",
										internal_label->proto,
										(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_udp->addr, thread_seq) : "")
										);
			}
			else
			{
				MESA_handle_runtime_log(g_tsg_para.logger,
										RLOG_LV_DEBUG,
										"PROJECT_ADD",
										"Add internal_label successfully, proto: %d addr: %s",
										internal_label->proto,
										(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_udp->addr, thread_seq) : "")
										);	
			}

			ret=tsg_scan_nesting_addr(g_tsg_maat_feather, a_udp, identify_info.proto, &mid, result, MAX_RESULT_NUM);
			if(ret>0)
			{
				hit_num+=ret;
				FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_HIT_ADDR], 0, FS_OP_ADD, 1);		
			}

			if(PROTO_QUIC==identify_info.proto && identify_info.domain_len>0)
			{
				ret=tsg_scan_shared_policy(g_tsg_maat_feather, &identify_info, result+hit_num, MAX_RESULT_NUM-hit_num, &mid, thread_seq);
				if(ret>0)
				{
					FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_HIT_SHARE], 0, FS_OP_ADD, 1);
					MESA_handle_runtime_log(g_tsg_para.logger,
												RLOG_LV_DEBUG,
												"SCAN_QUIC_SNI",
												"Hit %s: %s policy_id: %d service: %d action: %d addr: %s",
												"QUIC SNI",
												identify_info.domain,
												result[hit_num].config_id,
												result[hit_num].service_id,
												(unsigned char)result[hit_num].action,
												(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_udp->addr, thread_seq) : "")
											);

					hit_num+=ret;
				}
				else
				{
					MESA_handle_runtime_log(g_tsg_para.logger,
												RLOG_LV_DEBUG,
												"SCAN_QUIC_SNI",
												"Not hit %s: %s stream_dir: %d addr: %s",
												"QUIC SNI",
												identify_info.domain,
												a_udp->dir,
												(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_udp->addr, thread_seq) : "")
											);
				}

				if(strlen(identify_info.domain)>0 && identify_info.domain_len>0)
				{
					internal_label->fqdn_category_id_num=tsg_get_fqdn_category_id(g_tsg_maat_feather, 
																					identify_info.domain,
																					internal_label->fqdn_category_id,
																					MAX_CATEGORY_ID_NUM,
																					g_tsg_para.logger,
																					thread_seq
																				);
				}

				for(i=0; i<internal_label->fqdn_category_id_num; i++)
				{
					ret=Maat_scan_intval(g_tsg_maat_feather,
											g_tsg_para.table_id[TABLE_QUIC_SNI],
											(unsigned int)internal_label->fqdn_category_id[i],
											result+hit_num,
											MAX_RESULT_NUM-hit_num,
											&mid,
											thread_seq
										);
					if(ret>0)
					{
						MESA_handle_runtime_log(g_tsg_para.logger,
												RLOG_LV_DEBUG,
												"SCAN_FQDN_CAT",
												"Hit %s: %s category_id: %d policy_id: %d service: %d action: %d addr: %s",
												"QUIC SNI",
												identify_info.domain,
												internal_label->fqdn_category_id[i],
												result[hit_num].config_id,
												result[hit_num].service_id,
												(unsigned char)result[hit_num].action,
												(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_udp->addr, thread_seq) : "")
											);
						hit_num+=ret;
					}
					else
					{
						MESA_handle_runtime_log(g_tsg_para.logger,
												RLOG_LV_DEBUG,
												"SCAN_FQDN_CAT",
												"Not hit %s: %s category_id: %d ret: %d stream_dir: %d addr: %s",
												(ret==-1) ?  "NULL" : ((identify_info.proto==PROTO_HTTP) ? "host" : "sni"),
												(ret==-1) ? "NULL" : identify_info.domain,
												internal_label->fqdn_category_id[i],
												ret,
												a_udp->dir,
												(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_udp->addr, thread_seq) : "")
											);
					}
				}
			}
			
			if(mid!=NULL)
			{
				Maat_clean_status(&mid);
				mid=NULL;
			}
			
			p_result=tsg_policy_decision_criteria(a_udp, result, hit_num, NULL, thread_seq);
			if(p_result!=NULL)
			{
				switch((unsigned char)p_result->action)
				{
					case	TSG_ACTION_DENY:
						break;
					case	TSG_ACTION_BYPASS:
						init_context(pme, identify_info.proto, p_result, thread_seq);
						if(identify_info.proto>PROTO_UNKONWN && identify_info.proto<PROTO_MAX)
						{
							_context=(struct _master_context *)*pme;
							memcpy(_context->domain, identify_info.domain, identify_info.domain_len);
							_context->domain_len=identify_info.domain_len;
						}
						
						FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_BYPASS], 0, FS_OP_ADD, 1);

						MESA_handle_runtime_log(g_tsg_para.logger,
												RLOG_LV_DEBUG,
												"ALLOW",
												"Hit allow policy, policy_id: %d service: %d action: %d addr: %s",
												p_result[0].config_id,
												p_result[0].service_id,
												(unsigned char)p_result[0].action,
												(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_udp->addr, thread_seq) : "")
												);
						
						state=APP_STATE_GIVEME|APP_STATE_KILL_OTHER;
						break;
					case	TSG_ACTION_MONITOR:
						break;
					case	TSG_ACTION_INTERCEPT:
					case	TSG_ACTION_MANIPULATE:
					default:
						return APP_STATE_DROPME;
						break;
				}
			}
			break;
		case	OP_STATE_DATA:
			break;
		case	OP_STATE_CLOSE:
			if(_context!=NULL)
			{
				if(_context->hit_cnt>0 && _context->result!=NULL)
				{
					memset(&identify_info, 0, sizeof(identify_info));
					identify_info.proto=_context->proto;
					if(_context->domain_len>0)
					{
						memcpy(identify_info.domain, _context->domain, _context->domain_len);
						identify_info.domain_len=_context->domain_len;
					}
					
					master_send_log(a_udp, _context->result, _context->hit_cnt, &identify_info, thread_seq);
					free_context(pme, thread_seq);
				}
			}
			break;
		default:
			break;
	}
	
	return state;
}

extern "C" int TSG_MASTER_INIT()
{
	int i=0,ret=0;
	int value=0,cycle=0;
	int output_prometheus=0;
	unsigned short fs_server_port=0;
	char app_name[MAX_STRING_LEN]={0};
	char label_buff[MAX_STRING_LEN*4]={0};
	char fs_server_ip[MAX_IPV4_LEN]={0};
	char fs_output_path[MAX_STRING_LEN*4]={0};
	char device_sn_filename[MAX_STRING_LEN]={0};
	char identify_proto_name[MAX_STRING_LEN*4]={0};
	
	memset(&g_tsg_para, 0, sizeof(g_tsg_para));
	
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM","LOG_LEVEL", &g_tsg_para.level, RLOG_LV_FATAL);
	MESA_load_profile_string_def(tsg_conffile, "SYSTEM","LOG_PATH", g_tsg_para.log_path, sizeof(g_tsg_para.log_path), "tsglog/tsg_master");

	g_tsg_para.logger=MESA_create_runtime_log_handle(g_tsg_para.log_path, g_tsg_para.level);
	if(g_tsg_para.logger==NULL)
	{
		printf("MESA_create_runtime_log_handle failed ...\n");
		return -1;
	}
	
	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "IDENTIFY_PROTO_NAME", identify_proto_name, sizeof(identify_proto_name), "HTTP;SSL;DNS;FTP;BGP;SIP;MAIL;STREAMING_MEDIA;QUIC;");
	tsg_proto_name2flag(identify_proto_name, &g_tsg_para.proto_flag);

	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "ENTRANCE_ID", &g_tsg_para.entrance_id, 0);
	MESA_load_profile_short_def(tsg_conffile, "SYSTEM", "TIMEOUT", (short *)&g_tsg_para.timeout, 300);

	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "DEVICE_ID_COMMAND", g_tsg_para.device_id_command, sizeof(g_tsg_para.device_id_command), NULL);
	g_tsg_para.device_id=get_device_id(g_tsg_para.device_id_command, g_tsg_para.entrance_id);
		
	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "DEVICE_SN_FILENAME", device_sn_filename, sizeof(device_sn_filename), "/opt/tsg/etc/tsg_sn.json");
	ret=tsg_get_sn(device_sn_filename, g_tsg_para.device_sn, sizeof(g_tsg_para.device_sn));
	if(ret==0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "GET_DEVICE_SN", "Get device SN failed; please check :%s", device_sn_filename);
	}

	ret=tsg_set_device_id_to_telegraf(g_tsg_para.device_sn);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "SET_DEVICE_SN_TO_TELEGRAF", "Set device SN(%s) failed; please check :%s", g_tsg_para.device_sn, "/etc/default/telegraf");
	}
	
	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "POLICY_PRIORITY_LABEL", label_buff, sizeof(label_buff), "POLICY_PRIORITY");
	g_tsg_para.priority_project_id=project_producer_register(label_buff, PROJECT_VAL_TYPE_STRUCT, free_policy_label);
	if(g_tsg_para.priority_project_id<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_FATAL,
									"PROJECT_REGISTER",
									"Register %s failed; please check :%s and add <POLICY_PRIORITY	struct>",
									label_buff,
									"etc/project_list.conf"
								);
		return -1;
	}

	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "TSG_MASTER_INTERNAL_LABEL", label_buff, sizeof(label_buff), "TSG_MASTER_INTERNAL_LABEL");
	g_tsg_para.internal_project_id=project_producer_register(label_buff, PROJECT_VAL_TYPE_STRUCT, free_session_attribute_label);
	if(g_tsg_para.internal_project_id<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, 
									RLOG_LV_FATAL,
									"PROJECT_REGISTER",
									"Register %s failed; please check :%s and add <TSG_MASTER_INTERNAL_LABEL	struct>",
									label_buff,
									"etc/project_list.conf"
								);
	}

	ret=tsg_rule_init(tsg_conffile, g_tsg_para.logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "INIT_MAAT", "tsg_rule_init failed ...");
		return -1;
	}

	g_tsg_log_instance=tsg_sendlog_init(tsg_conffile);
	if(g_tsg_log_instance==NULL)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "INIT_SENDLOG", "tsg_sendlog_init failed ...");
		return -1;
	}
	g_tsg_log_instance->internal_project_id=g_tsg_para.internal_project_id;

	MESA_load_profile_int_def(tsg_conffile, "FIELD_STAT", "CYCLE", &cycle, 30);
	MESA_load_profile_short_nodef(tsg_conffile, "FIELD_STAT","TELEGRAF_PORT", (short *)&(fs_server_port));
	MESA_load_profile_string_nodef(tsg_conffile,"FIELD_STAT","TELEGRAF_IP",fs_server_ip, sizeof(fs_server_ip));
	MESA_load_profile_string_def(tsg_conffile,"FIELD_STAT","OUTPUT_PATH",fs_output_path, sizeof(fs_output_path), "tsg_stat.log");
	MESA_load_profile_string_def(tsg_conffile,"FIELD_STAT","APP_NAME", app_name, sizeof(app_name), "tsg_master");
	MESA_load_profile_int_def(tsg_conffile, "FIELD_STAT", "PROMETHEUS", &output_prometheus, 1);

	g_tsg_para.fs2_handle=FS_create_handle();

	value=1;//Rewrite
	FS_set_para(g_tsg_para.fs2_handle, PRINT_MODE, &value, sizeof(value));
	value=1;//Do not create stat thread
	FS_set_para(g_tsg_para.fs2_handle, CREATE_THREAD, &value, sizeof(value));
	
    FS_set_para(g_tsg_para.fs2_handle, STAT_CYCLE, &cycle, sizeof(cycle));
    FS_set_para(g_tsg_para.fs2_handle, APP_NAME, app_name, strlen(app_name)+1);
	FS_set_para(g_tsg_para.fs2_handle, OUTPUT_DEVICE, fs_output_path, strlen(fs_output_path)+1);

	value=1;
	FS_set_para(g_tsg_para.fs2_handle, OUTPUT_PROMETHEUS, &output_prometheus, sizeof(output_prometheus));

    if(fs_server_port > 0 && strlen(fs_server_ip) > 0)
    {
        FS_set_para(g_tsg_para.fs2_handle, STATS_SERVER_IP,fs_server_ip, strlen(fs_server_ip)+1);
        FS_set_para(g_tsg_para.fs2_handle, STATS_SERVER_PORT,&(fs_server_port), sizeof(fs_server_port));
    }

	value=FS_OUTPUT_INFLUX_LINE;
	FS_set_para(g_tsg_para.fs2_handle, STATS_FORMAT, &value, sizeof(value));

	for(i=0; i<TSG_FS2_MAX; i++)
	{
		g_tsg_para.fs2_field_id[i]=FS_register(g_tsg_para.fs2_handle, FS_STYLE_FIELD, FS_CALC_SPEED, g_tsg_fs2_field[i].name);
	}

	char buff[32]={0};
	int thread_num=get_thread_count();
	for(i=0; i<thread_num && g_tsg_log_instance!=NULL; i++)
	{
		snprintf(buff, sizeof(buff), "send_log_percent_%02d", i);
		g_tsg_log_instance->fs_status_ids[i]=FS_register(g_tsg_para.fs2_handle, FS_STYLE_STATUS, FS_CALC_CURRENT, buff);
	}
	
	FS_start(g_tsg_para.fs2_handle);

	for(i=0; i<thread_num; i++)
	{
		FS_operate(g_tsg_para.fs2_handle,g_tsg_log_instance ->fs_status_ids[i], 0, FS_OP_SET, g_tsg_log_instance->send_log_percent[i]);
	}
	
	ret=tsg_statistic_init(tsg_conffile, g_tsg_para.logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "INIT_STATISTIC", "tsg_statistic_init failed ...");
		return -1;
	}
	
	return 0;
}



extern "C" int TSG_MASTER_UNLOAD()
{
	sleep(5);
	return 0;
}

