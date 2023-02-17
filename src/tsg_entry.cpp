#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <unistd.h>

#include <MESA/rdp.h>
#include <MESA/http.h>
#include <MESA/ftp.h>
#include <MESA/ssl.h>
#include <MESA/mail.h>
#include <MESA/quic.h>
#include <MESA/sip.h>
#include <MESA/stratum.h>
#include <MESA/dtls.h>
#include <MESA/stream.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>
#include <MESA/MESA_jump_layer.h>

#include "app_label.h"
#include "tsg_rule.h"
#include "tsg_entry.h"
#include "tsg_send_log.h"
#include "tsg_statistic.h"
#include "tsg_send_log_internal.h"
#include "tsg_ssl_utils.h"
#include "tsg_ssh_utils.h"
#include "tsg_protocol_common.h"

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

char TSG_MASTER_VERSION_20200805 = 0;
const char *tsg_conffile="tsgconf/main.conf";
g_tsg_para_t g_tsg_para;

struct id2field g_tsg_fs2_field[TSG_FS2_MAX]={{0, TSG_FS2_TCP_LINKS, "tcp_links"},
										 {0, TSG_FS2_UDP_LINKS, "udp_links"}, 
										 {0, TSG_FS2_BYPASS, "bypass"},
										 {0, TSG_FS2_HIT_ADDR, "hit_addr"},
										 {0, TSG_FS2_HIT_SHARE, "hit_share"},
										 {0, TSG_FS2_INTERCEPT, "intercept"},
										 {0, TSG_FS2_SHAPING, "shaping"},
										 {0, TSG_FS2_EXCLUSION, "exclusion"},
										 {0, TSG_FS2_APP_DPKT_RESULT, "D_result"},
										 {0, TSG_FS2_APP_Q_RESULT, "Q_result"},
										 {0, TSG_FS2_APP_USER_RESULT, "U_result"},
										 {0, TSG_FS2_APP_BUILT_IN_RESULT, "B_result"},
										 {0, TSG_FS2_INJECT_PKT_SUCCESS, "inject_succuess"},
										 {0, TSG_FS2_INJECT_PKT_FAILED, "inject_failed"},
										 {0, TSG_FS2_MIRRORED_PKT_SUCCESS, "mirror_pkt_suc"},
										 {0, TSG_FS2_MIRRORED_BYTE_SUCCESS, "mirror_byte_suc"},
										 {0, TSG_FS2_MIRRORED_PKT_FAILED, "mirror_pkt_fai"},
										 {0, TSG_FS2_MIRRORED_BYTE_FAILED, "mirror_byte_fai"},
										 {0, TSG_FS2_SET_TIMOUT_SUCCESS, "set_timeout_suc"},
										 {0, TSG_FS2_SET_TIMOUT_FAILED, "set_timeout_fai"},
                                         {0, TSG_FS2_SUCESS_TAMPER, "tamper_sucess"},
                                         {0, TSG_FS2_TAMPER_FAILED_PLOAD_LESS_4, "tamper_nopload"},
                                         {0, TSG_FS2_TAMPER_FAILED_NOSWAP, "tamper_noswap"},
										 {0, TSG_FS2_ASN_ADD, "asn_add"},
										 {0, TSG_FS2_ASN_DEL, "asn_del"},
										 {0, TSG_FS2_GTPC_ADD, "gtpc_add"},
										 {0, TSG_FS2_GTPC_DEL, "gtpc_del"},
										 {0, TSG_FS2_LOCATION_ADD, "location_add"},
										 {0, TSG_FS2_LOCATION_DEL, "location_del"},
										 {0, TSG_FS2_FQDN_ADD, "fqdn_add"},
										 {0, TSG_FS2_FQDN_DEL, "fqdn_del"},
										 {0, TSG_FS2_SUBSCRIBER_ADD, "subscriber_add"},
										 {0, TSG_FS2_SUBSCRIBER_DEL, "subscriber_del"},
										 {0, TSG_FS2_SECURIRY_ADD, "security_add"},
										 {0, TSG_FS2_SECURIRY_DEL, "security_del"},
										 {0, TSG_FS2_MIRRORED_ADD, "mirrored_add"},
										 {0, TSG_FS2_MIRRORED_DEL, "mirrored_del"},
										 {0, TSG_FS2_HTTP_RES_ADD, "http_res_add"},
										 {0, TSG_FS2_HTTP_RES_DEL, "http_res_del"},
										 {0, TSG_FS2_DNS_RES_ADD, "dns_profile_add"},
										 {0, TSG_FS2_DNS_RES_DEL, "dns_profile_del"},
										 {0, TSG_FS2_APP_ID_ADD, "app_id_add"},
										 {0, TSG_FS2_APP_ID_DEL, "app_id_del"},
										 {0, TSG_FS2_TUNNEL_CATALOG_ADD, "t_catalog_add"},
										 {0, TSG_FS2_TUNNEL_CATALOG_DEL, "t_catalog_del"},
										 {0, TSG_FS2_TUNNEL_ENDPOINT_ADD, "t_endpoint_add"},
										 {0, TSG_FS2_TUNNEL_ENDPOINT_DEL, "t_endpoint_del"},
										 {0, TSG_FS2_TUNNEL_LABEL_ADD, "t_label_add"},
										 {0, TSG_FS2_TUNNEL_LABEL_DEL, "t_label_del"}
										};

struct id2field g_tsg_proto_name2id[PROTO_MAX]={{PROTO_UNKONWN, 0, "unknown"}, 
										 {PROTO_IPv4, 	0,	"IPV4"},
										 {PROTO_IPv6, 	0,	"IPV6"},
										 {PROTO_TCP, 	0, 	"TCP"},
										 {PROTO_UDP, 	0, 	"UDP"},
										 {PROTO_HTTP, 	0, 	"HTTP"},
										 {PROTO_MAIL, 	0, 	"MAIL"},
										 {PROTO_DNS, 	0, 	"DNS"},
										 {PROTO_FTP, 	0, 	"FTP"},
										 {PROTO_SSL, 	0, 	"SSL"},
										 {PROTO_SIP, 	0, 	"SIP"},
										 {PROTO_BGP, 	0, 	"BGP"},
										 {PROTO_STREAMING_MEDIA, 0, "STREAMING_MEDIA"},
										 {PROTO_QUIC, 	0,	 "QUIC"},
										 {PROTO_SSH, 	0, 	"SSH"},
										 {PROTO_SMTP, 	0, 	"SMTP"},
										 {PROTO_IMAP, 	0, 	"IMAP"},
										 {PROTO_POP3, 	0, 	"POP3"},
										 {PROTO_RTP, 	0, 	"RTP"},
										 {PROTO_APP, 	0,	"BASE"},
										 {PROTO_L2TP, 	0,	"L2TP"},
										 {PROTO_PPTP, 	0,	"PPTP"},
										 {PROTO_STRATUM, 	0,	"Stratum"},
										 {PROTO_RDP, 	0,	"RDP"},
										 {PROTO_DTLS, 	0,	"DTLS"}
										};

#define	DECCRYPTION_EXCLUSION_ALLOW_POLICY_ID	1

static int init_page_template(const char *conffile)
{
	char page_path[256];
	memset(page_path, 0, sizeof(page_path));
	MESA_load_profile_string_def(conffile, "HTTP_PLUG", "PAGE403", page_path, sizeof(page_path), "./tsgconf/HTTP403.html");
	g_tsg_para.tpl_403 = ctemplate::Template::GetTemplate(page_path, ctemplate::DO_NOT_STRIP);
	
	memset(page_path, 0, sizeof(page_path));
	MESA_load_profile_string_def(conffile, "HTTP_PLUG", "PAGE404", page_path, sizeof(page_path), "./tsgconf/HTTP404.html");
	g_tsg_para.tpl_404 = ctemplate::Template::GetTemplate(page_path, ctemplate::DO_NOT_STRIP);

	memset(page_path, 0, sizeof(page_path));
	MESA_load_profile_string_def(conffile, "HTTP_PLUG", "PAGE200", page_path, sizeof(page_path), "./tsgconf/HTTP200.html");
	g_tsg_para.tpl_200 = ctemplate::Template::GetTemplate(page_path, ctemplate::DO_NOT_STRIP);

	memset(page_path, 0, sizeof(page_path));
	MESA_load_profile_string_def(conffile, "HTTP_PLUG", "PAGE204", page_path, sizeof(page_path), "./tsgconf/HTTP204.html");
	g_tsg_para.tpl_204 = ctemplate::Template::GetTemplate(page_path, ctemplate::DO_NOT_STRIP);

	return 0;
}

static int init_fs2_handle(const char *conffile)
{
	int value=0,cycle=0;
	int output_prometheus=0;
	unsigned short fs_server_port=0;
	char app_name[128]={0};
	char fs_server_ip[MAX_IPV4_LEN]={0};
	char fs_output_path[128]={0};

	MESA_load_profile_int_def(conffile, "FIELD_STAT", "CYCLE", &cycle, 30);
	MESA_load_profile_short_nodef(conffile, "FIELD_STAT","TELEGRAF_PORT", (short *)&(fs_server_port));
	MESA_load_profile_string_nodef(conffile,"FIELD_STAT","TELEGRAF_IP",fs_server_ip, sizeof(fs_server_ip));
	MESA_load_profile_string_def(conffile,"FIELD_STAT","OUTPUT_PATH",fs_output_path, sizeof(fs_output_path), "tsg_stat.log");
	MESA_load_profile_string_def(conffile,"FIELD_STAT","APP_NAME", app_name, sizeof(app_name), "tsg_master");
	MESA_load_profile_int_def(conffile, "FIELD_STAT", "PROMETHEUS", &output_prometheus, 1);

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

	for(int i=0; i<TSG_FS2_MAX; i++)
	{
		g_tsg_para.fs2_field_id[i]=FS_register(g_tsg_para.fs2_handle, FS_STYLE_FIELD, FS_CALC_SPEED, g_tsg_fs2_field[i].name);
	}

	return 0;
}

static int init_context(void **pme, int thread_seq)
{
	*pme=dictator_malloc(thread_seq, sizeof(struct master_context));
	memset(*pme, 0, sizeof(struct master_context));
	
	return 0;
}

static int tsg_get_sn(char *filename, char *device_sn, int device_sn_len)
{
	int flags=0;
	
	FILE *fp=fopen(filename, "rb");
	if(fp)
	{
		char buff[4096]={0};
		int ret=fread(buff, sizeof(buff), 1, fp);
		if(ret<(int)sizeof(buff))
		{
			cJSON *object=cJSON_Parse(buff);
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

static int set_app_timeout(const struct streaminfo *a_stream, struct app_id_dict *dict, unsigned short *timeout)
{
	if(a_stream==NULL || dict==NULL)
	{
		return 0;
	}
	
	switch(a_stream->type)
	{
		case	STREAM_TYPE_TCP:
			if((*timeout) >= dict->tcp_timeout)
			{
				return 0;
			}
			
			*timeout=dict->tcp_timeout;
			break;
		case	STREAM_TYPE_UDP:
			if((*timeout) >= dict->udp_timeout)
			{
				return 0;
			}
			
			*timeout=dict->udp_timeout;
			break;
		default:
			return 0;
	}
	
	int ret=MESA_set_stream_opt(a_stream, MSO_TIMEOUT, (void *)timeout, sizeof(unsigned short));
	if(ret<0)
	{
		FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_SET_TIMOUT_FAILED], 0, FS_OP_ADD, 1); 		
	}
	else
	{
		FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_SET_TIMOUT_SUCCESS], 0, FS_OP_ADD, 1);
	}
	
	return 1;
}

static int get_device_id(char *command, int datacenter_id)
{
	FILE *fp=NULL; 
	char buffer[128]={0};

	fp=popen(command, "r"); 
	if(fp)
	{
		fgets(buffer,sizeof(buffer),fp); 
    	pclose(fp);
	}
	
	return (datacenter_id<<7)+(atoi(buffer)%128);
}

static int get_deploy_mode(void)
{
	char s_mode[128]={0};
	int len=sizeof(s_mode);
	int ret=sapp_get_platform_opt(SPO_DEPLOYMENT_MODE_STR, s_mode, &len);
	if(ret>=0)
	{
		if((memcmp(s_mode, "mirror", strlen(s_mode)))==0 || (memcmp(s_mode, "dumpfile", strlen(s_mode)))==0)
		{
			g_tsg_para.deploy_mode=DEPLOY_MODE_MIRROR;
		}
		else if((memcmp(s_mode, "inline", strlen(s_mode)))==0)
		{
			g_tsg_para.deploy_mode=DEPLOY_MODE_INLINE;
		}
		else if((memcmp(s_mode, "transparent", strlen(s_mode)))==0)
		{
			g_tsg_para.deploy_mode=DEPLOY_MODE_TRANSPARENT;
		}
		else
		{
			g_tsg_para.deploy_mode=DEPLOY_MODE_MIRROR;
		}
	}

	return 0;
}

static char get_direction(const struct streaminfo *a_stream)
{
	int i_or_e=0;
	char direction=0;

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

	return direction;
}

static int print_hit_path(const struct streaminfo *a_stream, struct master_context *context)
{
	if(g_tsg_para.hit_path_switch==0)
	{
		return 0;
	}

	char path_buff[1024*128]={0};
	int i=0, n_read=0, offset=0;
	struct Maat_hit_path_t hit_path[1024];

	n_read=Maat_get_scan_status(g_tsg_maat_feather, &(context->mid), MAAT_GET_SCAN_HIT_PATH, hit_path, sizeof(hit_path));
	for(i=0; i<n_read; i++)
	{
		if(i==0)
		{
			path_buff[offset++]='[';
		}
		offset+=snprintf(path_buff+offset, 
							sizeof(path_buff)-offset, 
							"{n:%d,v_id:%d,c_id:%d,t_id:%d,s_id:%d,r_id:%d},",
							hit_path[i].Nth_scan,
							hit_path[i].virtual_table_id,
							hit_path[i].compile_id,
							hit_path[i].top_group_id,
							hit_path[i].sub_group_id,
							hit_path[i].region_id
						);
	}

	MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "HIT_PATH", "Hit path: %s{}] addr: %s", path_buff, PRINTADDR(a_stream, g_tsg_para.level));
	
	return 1;
}

static int is_only_monitor(struct Maat_rule_t *result, int hit_cnt)
{
	int i=0;

	for(i=0; i<hit_cnt; i++)
	{
		if(result[i].action==TSG_ACTION_BYPASS || result[i].action==TSG_ACTION_INTERCEPT || result[i].action==TSG_ACTION_DENY)
		{
			return 0;
		}
	}

	return 1;
}

static int is_dns_protocol(const struct streaminfo *a_stream)
{
	struct stream_tuple4_v4 *tpl4 = NULL;
	struct stream_tuple4_v6 *tpl6 = NULL;

	if(a_stream->pudpdetail==NULL || a_stream->pudpdetail->pdata==NULL || a_stream->pudpdetail->datalen<12)
	{
		return 0;
	}
	
	switch(a_stream->addr.addrtype)
	{
		case ADDR_TYPE_IPV4:
			tpl4=a_stream->addr.tuple4_v4;
			if((ntohs(tpl4->source)!=53) && (ntohs(tpl4->dest)!=53))
			{
				return 0;
			}
			break;
		case ADDR_TYPE_IPV6:
			tpl6=a_stream->addr.tuple4_v6;
			if((ntohs(tpl6->source)!=53) && (ntohs(tpl6->dest)!=53))
			{
				return 0;
			}
			break;
		default:
			return 0;
			break;
	}

	struct _dns_hdr *dns_hdr=(struct _dns_hdr *)(a_stream->pudpdetail->pdata);
	if(dns_hdr->qdcount==1 && dns_hdr->z==0)
	{
		return 1;
	}

	return 0;
}

static int is_deny_application(Maat_rule_t *p_result)
{
	int ret=0;
	struct compile_user_region *user_region=NULL;

	user_region=(struct compile_user_region *)Maat_rule_get_ex_data(g_tsg_maat_feather, p_result, g_tsg_para.table_id[TABLE_SECURITY_COMPILE]);
	if(user_region==NULL)
	{
		return 0;
	}

	if(user_region->method_type==TSG_METHOD_TYPE_APP_DROP)
	{
		ret=1;
	}
	
	security_compile_free(g_tsg_para.table_id[TABLE_SECURITY_COMPILE], p_result, NULL, (MAAT_RULE_EX_DATA *)&user_region, 0, NULL);
	
	return ret;
}

static int is_deny_after_N_packets(Maat_rule_t *p_result)
{
	int ret=0;
	struct compile_user_region *user_region=NULL;

	user_region=(struct compile_user_region *)Maat_rule_get_ex_data(g_tsg_maat_feather, p_result, g_tsg_para.table_id[TABLE_SECURITY_COMPILE]);
	if(user_region==NULL)
	{
		return 0;
	}

	if(user_region->method_type!=TSG_METHOD_TYPE_APP_DROP && user_region->method_type!=TSG_METHOD_TYPE_DROP)
	{
		return 0;
	}

	if(user_region->deny!=NULL && user_region->deny->after_n_packets>0)
	{
		ret=1;
	}
	
	security_compile_free(g_tsg_para.table_id[TABLE_SECURITY_COMPILE], p_result, NULL, (MAAT_RULE_EX_DATA *)&user_region, 0, NULL);
	
	return ret;
}

long long get_current_time_ms(void)
{
	int size=sizeof(long long); 	
	long long current_time_ms=0;		
	sapp_get_platform_opt(SPO_CURTIME_TIMET_MS, &current_time_ms, &size);

	return current_time_ms;
}

static int get_table_id(tsg_protocol_t protocol)
{
	switch(protocol)
	{
		case	PROTO_HTTP:
			return g_tsg_para.table_id[TABLE_HTTP_HOST];
		case	PROTO_SSL:
			return g_tsg_para.table_id[TABLE_SSL_SNI];
		case	PROTO_QUIC:
			return g_tsg_para.table_id[TABLE_QUIC_SNI];
		case	PROTO_DTLS:
			return g_tsg_para.table_id[TABLE_DTLS_SNI];
		default:
			break;
	}

	return -1;
}

static int get_raw_packet_len(const struct streaminfo *a_stream)
{
	int raw_packet_len=0;

	if(a_stream->type==STREAM_TYPE_TCP)
	{
		if(a_stream->ptcpdetail==NULL || a_stream->ptcpdetail->pdata==NULL || a_stream->ptcpdetail->datalen==0)
		{
			return 0;
		}
	}
	
	int ret=get_rawpkt_opt_from_streaminfo(a_stream, RAW_PKT_GET_TOT_LEN, &raw_packet_len);
	if(ret<0)
	{
		return 0;
	}

	return raw_packet_len;
}

static int get_default_para(const struct streaminfo *a_stream, int compile_id)
{
	int after_n_packets=0;
	struct Maat_rule_t p_result={0};
	struct compile_user_region *user_region=NULL;

	p_result.config_id=compile_id;
	user_region=(struct compile_user_region *)Maat_rule_get_ex_data(g_tsg_maat_feather, &p_result, g_tsg_para.table_id[TABLE_SECURITY_COMPILE]);
	if(user_region!=NULL && user_region->method_type==TSG_METHOD_TYPE_DEFAULT)
	{
		if(user_region->session_para!=NULL && user_region->session_para->result.action==TSG_ACTION_DENY)
		{
			switch(a_stream->type)
			{
				case	STREAM_TYPE_TCP:
					after_n_packets=user_region->session_para->tcp.after_n_packets;
					break;
				case	STREAM_TYPE_UDP:
					after_n_packets=user_region->session_para->udp.after_n_packets;
					break;
				default:
					break;
			}
		}
		
		security_compile_free(g_tsg_para.table_id[TABLE_SECURITY_COMPILE], &p_result, NULL, (MAAT_RULE_EX_DATA *)&user_region, 0, NULL);
	}

	return after_n_packets;
}

static int get_default_policy(int compile_id, struct Maat_rule_t *result)
{
	int ret=0;
	struct Maat_rule_t p_result={0};
	struct compile_user_region *user_region=NULL;

	p_result.config_id=compile_id;
	user_region=(struct compile_user_region *)Maat_rule_get_ex_data(g_tsg_maat_feather, &p_result, g_tsg_para.table_id[TABLE_SECURITY_COMPILE]);
	if(user_region!=NULL)
	{
		if(user_region->method_type==TSG_METHOD_TYPE_DEFAULT)
		{
			if(user_region->session_para!=NULL && user_region->session_para->result.action==TSG_ACTION_DENY)
			{
				memcpy(result, &(user_region->session_para->result), sizeof(struct Maat_rule_t));
			}
			
			ret=1;
		}
		security_compile_free(g_tsg_para.table_id[TABLE_SECURITY_COMPILE], &p_result, NULL, (MAAT_RULE_EX_DATA *)&user_region, 0, NULL);
	}

	return ret;
}

static int get_packet_sequence(const struct streaminfo *a_stream)
{
	unsigned int packet_sequence=0;
	unsigned long long value=0;
	int value_len=sizeof(unsigned long long);

	value=0;
	MESA_get_stream_opt(a_stream, MSO_TOTAL_INBOUND_PKT, (void *)&value, &value_len);
	packet_sequence+=(unsigned int)value;

	value=0;
	MESA_get_stream_opt(a_stream, MSO_TOTAL_OUTBOUND_PKT, (void *)&value, &value_len);
	packet_sequence+=(unsigned int)value;

	return packet_sequence;
}

static int is_do_default_policy(const struct streaminfo *a_stream, int after_n_packets)
{
	if(after_n_packets<=0 || a_stream->pdetail==NULL)
	{
		return 0;
	}

	switch(a_stream->type)
	{
		case	STREAM_TYPE_TCP:
			if((int)(a_stream->ptcpdetail->clientpktnum+a_stream->ptcpdetail->serverpktnum) >= after_n_packets)
			{
				return 1;
			}
			break;
		case	STREAM_TYPE_UDP:
			if((int)(a_stream->pudpdetail->clientpktnum+a_stream->pudpdetail->serverpktnum) >= after_n_packets)
			{
				return 1;
			}
			break;
		default:
			break;
	}

	return 0;
}

int set_hited_app_id(const struct streaminfo *a_stream, unsigned int hited_app_id)
{
	struct gather_app_result *gather_result=NULL;
	
	gather_result=(struct gather_app_result *)tsg_get_xxx_from_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_GATHER_APP_RESULT].id);
	if(gather_result==NULL)
	{
		return 0;
	}
	
	gather_result[ORIGIN_HITED_APP].app_num=1;		
	gather_result[ORIGIN_HITED_APP].origin=ORIGIN_HITED_APP;
	gather_result[ORIGIN_HITED_APP].attributes[0].app_id=hited_app_id;
	gather_result[ORIGIN_HITED_APP].attributes[0].surrogate_id=0;

	return 1;
}

static int master_send_log(const struct streaminfo *a_stream, struct Maat_rule_t *p_result, int result_num, struct master_context *context, int thread_seq)
{
	tsg_log_t log_msg;
	char *domain_field_name=NULL;
	char *schema_field_name=NULL;
	char *quic_ua_field_name=NULL;
	char *quic_version_field_name=NULL;
	struct TLD_handle_t *TLD_handle=NULL;
	tsg_protocol_t proto=PROTO_UNKONWN;
	struct tsg_conn_sketch_notify_data *notify=NULL;
	if(context!=NULL)
	{
		proto=context->proto;
	}

	log_msg.a_stream=(struct streaminfo *)a_stream;
	log_msg.result=p_result;
	log_msg.result_num=result_num;

	if(p_result[0].action==TSG_ACTION_MONITOR && g_tsg_para.bridge[BRIDGE_TYPE_RECV_CONN_SKETCH_DATA].id>=0)
	{
		switch(proto)
		{
			case	PROTO_SSH:
			case	PROTO_RDP:
			case	PROTO_STRATUM:
					notify=(struct tsg_conn_sketch_notify_data *)tsg_get_xxx_from_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_RECV_CONN_SKETCH_DATA].id);
					if (notify != NULL && notify->pdata.TLD_handle!=NULL && (notify->protocol== PROTO_SSH || notify->protocol== PROTO_STRATUM  || notify->protocol== PROTO_RDP))
					{
						TLD_handle = TLD_duplicate(notify->pdata.TLD_handle);
						if (TLD_handle!=NULL)
						{
							tsg_send_log(g_tsg_log_instance, TLD_handle, &log_msg, thread_seq);
							tsg_set_policy_flow((struct streaminfo *)a_stream, p_result, thread_seq);
							return 1;
						}
					}
				break;
			default:
				break;
		}
	}

	TLD_handle=TLD_create(thread_seq);
	schema_field_name=log_field_id2name(g_tsg_log_instance, LOG_COMMON_SCHAME_TYPE);
	
	if(proto>PROTO_UNKONWN && proto<PROTO_MAX)
	{
		if(proto==PROTO_IMAP || proto==PROTO_SMTP || proto==PROTO_POP3)
		{
			TLD_append(TLD_handle, schema_field_name, (void *)g_tsg_proto_name2id[PROTO_MAIL].name, TLD_TYPE_STRING);
			TLD_append(TLD_handle, (char *)"mail_protocol_type", (void *)g_tsg_proto_name2id[proto].name, TLD_TYPE_STRING);
		}
		else
		{			
			TLD_append(TLD_handle, schema_field_name, (void *)g_tsg_proto_name2id[proto].name, TLD_TYPE_STRING);
		}

		
		if(proto==PROTO_HTTP)
		{
			TLD_append(TLD_handle, (char *)"http_version", (void *)"http1", TLD_TYPE_STRING);
			TLD_append(TLD_handle, (char *)"http_sequence", (void *)1, TLD_TYPE_LONG);
		}

		if(context!=NULL && context->domain!=NULL)
		{
			switch(proto)
			{
				case	PROTO_HTTP:
					domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_HTTP_HOST);
					TLD_append(TLD_handle, domain_field_name, (void *)context->domain, TLD_TYPE_STRING);

					if(context->http_url!=NULL)
					{
						domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_HTTP_URL);
						TLD_append(TLD_handle, domain_field_name, (void *)context->http_url, TLD_TYPE_STRING);
					}
					break;
				case	PROTO_SSL:
					domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_SSL_SNI);
					TLD_append(TLD_handle, domain_field_name, (void *)context->domain, TLD_TYPE_STRING);
					break;
				case	PROTO_QUIC:
					domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_QUIC_SNI);
					TLD_append(TLD_handle, domain_field_name, (void *)context->domain, TLD_TYPE_STRING);
					break;
				case	PROTO_DTLS:
					domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_DTLS_SNI);
					TLD_append(TLD_handle, domain_field_name, (void *)context->domain, TLD_TYPE_STRING);
					break;
				default:
					break;
			}
		}
		
		if(context!=NULL && context->quic_version>0)
		{
			char quic_version[64]={0};
			if(quic_version_int2string(context->quic_version, quic_version, sizeof(quic_version)))
			{
				quic_version_field_name=log_field_id2name(g_tsg_log_instance, LOG_QUIC_VERSION);
				TLD_append(TLD_handle, quic_version_field_name, (void *)quic_version, TLD_TYPE_STRING);
			}

			if(context->quic_ua!=NULL)
			{
				quic_ua_field_name=log_field_id2name(g_tsg_log_instance, LOG_QUIC_USER_AGENT);
				TLD_append(TLD_handle, quic_ua_field_name, (void *)context->quic_ua, TLD_TYPE_STRING);
			}
		}
	}
	else
	{
		TLD_append(TLD_handle, schema_field_name, (void *)g_tsg_proto_name2id[PROTO_APP].name, TLD_TYPE_STRING);
	}	

	if(context!=NULL && context->hited_app_id>0)
	{		
		set_hited_app_id(a_stream, context->hited_app_id);
	}
	
	tsg_send_log(g_tsg_log_instance, TLD_handle, &log_msg, thread_seq);
	
	if(p_result->config_id!=DECCRYPTION_EXCLUSION_ALLOW_POLICY_ID)
	{
		tsg_set_policy_flow((struct streaminfo *)a_stream, p_result, thread_seq);
	}
	
	return 1;
}

static int tsg_proto_name2flag(char *proto_list, int *flag)
{
	char *e=NULL;
	char *s=proto_list;
	while(s)
	{
		e=index(s, ';');
		if(!e)
		{
			break;
		}

		for(int i=0; i< PROTO_MAX; i++)
		{
			if((strncasecmp(s, g_tsg_proto_name2id[i].name, e-s))==0)
			{
				*flag|=(1<<g_tsg_proto_name2id[i].type);
				break;
			}
		}
		
		s=e+1;
	}

	return 0;
}

static char *malloc_copy_string(char *origin, int length, int thread_seq)
{
	if(length<=0 && origin==NULL)
	{
		return NULL;
	}
	
	char *dest=(char *)dictator_malloc(thread_seq, length+1);
	memcpy(dest, origin, length);
	dest[length]='\0';

	return dest;
}

int copy_app_result(struct gather_app_result *gather_result, struct app_identify_result *identify_result, int packet_sequence)
{
	if(identify_result->app_id_num<=gather_result->app_num)
	{
		return 0;
	}
	
	gather_result->app_num=0;
	for(int i=0; (i < identify_result->app_id_num) && i<MAX_APP_ID_NUM && (gather_result->app_num < MAX_APP_ID_NUM); i++)
	{		
		gather_result->origin=identify_result->origin;
		gather_result->attributes[i].app_id=identify_result->app_id[i];
		gather_result->attributes[i].surrogate_id=identify_result->surrogate_id[i];
		gather_result->attributes[i].packet_sequence=packet_sequence;
		gather_result->app_num++;
	}

	return 0;
}

static int l7_protocol_mapper(const char *conffile)
{
	int ret=0;
	FILE *fp=NULL;
	char line[1024]={0};
	char type_name[32]={0};
	char filename[128]={0};
	struct l7_protocol *protocol=NULL;
	
	MESA_load_profile_string_def(conffile, "SYSTEM", "L7_PROTOCOL_FILE", filename, sizeof(filename), "./tsgconf/tsg_l7_protocol.conf");

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
		
	    protocol=(struct l7_protocol *)calloc(1, sizeof(struct l7_protocol));
		ret=sscanf(line, "%31s %31s %d", type_name, protocol->name, &protocol->id);
		assert(ret==3);

	    HASH_ADD(hh1, g_tsg_para.name_by_id, id, sizeof(int), protocol);
	    HASH_ADD(hh2, g_tsg_para.id_by_name, name, strlen(protocol->name), protocol);
		
		memset(line, 0, sizeof(line));
	}

	fclose(fp);
	fp=NULL;

	return 1;
}

char *tsg_l7_protocol_id2name(unsigned int l7_protocol_id)
{	
	struct l7_protocol *l7_proto=NULL;
	HASH_FIND(hh1, g_tsg_para.name_by_id, &l7_protocol_id, sizeof(l7_protocol_id), l7_proto);
	if(l7_proto!=NULL)
	{
		return l7_proto->name;
	}

	return NULL;
}

unsigned int tsg_l7_protocol_name2id(const char *l7_protocol_name)
{
	struct l7_protocol *l7_proto=NULL;

	HASH_FIND(hh2, g_tsg_para.id_by_name, l7_protocol_name, strlen(l7_protocol_name), l7_proto);
	if(l7_proto!=NULL)
	{
		return l7_proto->id;
	}

	return 0;
}

static int set_l7_protocol_to_pme(struct master_context *context, unsigned int app_id)
{
	char *l7_protocol_name=tsg_l7_protocol_id2name(app_id);
	if(l7_protocol_name!=NULL)
	{
		for(int i=PROTO_HTTP; i<PROTO_MAX; i++)
		{
			if((strcasecmp(g_tsg_proto_name2id[i].name, l7_protocol_name))==0)
			{
				context->proto=(tsg_protocol_t)g_tsg_proto_name2id[i].type;
				return 1;
			}
		}
	}
	
	context->proto=PROTO_APP;

	return 0;
}

int is_intercept_exclusion(const struct streaminfo *a_stream, Maat_rule_t *p_result, char *domain, int thread_seq)
{
	if(domain!=NULL)
	{
		scan_status_t mid=NULL;
		struct Maat_rule_t tmp_result;
		int ret=Maat_full_scan_string(g_tsg_maat_feather, g_tsg_para.table_id[TABLE_EXCLUSION_SSL_SNI], CHARSET_UTF8, domain, strlen(domain), &tmp_result, NULL, 1, &mid,thread_seq);
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
										domain,
										tmp_result.config_id,
										tmp_result.service_id,
										(unsigned char)tmp_result.action,
										p_result->config_id,
										p_result->service_id,
										(unsigned char)p_result->action,
										PRINTADDR(a_stream, g_tsg_para.level)
									);
						
			return 1;
		}
	
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_DEBUG,
									"EXCLUSION_SSL_SNI",
									"Not hit %s stream_dir: %d addr: %s  scan ret: %d",
									domain,
									a_stream->dir,
									PRINTADDR(a_stream, g_tsg_para.level),
									ret
								);
	}

	return 0;
}

static int scan_fqdn_category_id(Maat_feather_t maat_feather, const struct streaminfo *a_stream, char *domain, Maat_rule_t *result, int result_num,  scan_status_t *mid, int table_id, int thread_seq)
{
	int scan_ret=0;
	struct session_attribute_label *attribute_label=NULL;
	
	attribute_label=(struct session_attribute_label *)project_req_get_struct(a_stream, g_tsg_para.session_attribute_project_id);
	if(attribute_label!=NULL && domain!=NULL && table_id>=0)
	{
		attribute_label->fqdn_category_id_num=tsg_get_fqdn_category_id(g_tsg_maat_feather, domain, attribute_label->fqdn_category_id, MAX_CATEGORY_ID_NUM, g_tsg_para.logger, thread_seq);
		scan_ret=tsg_scan_fqdn_category_id(g_tsg_maat_feather, a_stream, result, result_num, mid, table_id, attribute_label->fqdn_category_id, attribute_label->fqdn_category_id_num, thread_seq);
	}

	return scan_ret;
}

static int set_l7_protocol_label(const struct streaminfo *a_stream, tsg_protocol_t protocol)
{
	struct gather_app_result *gather_result=NULL;
	
	gather_result=(struct gather_app_result *)tsg_get_xxx_from_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_GATHER_APP_RESULT].id);
	if(gather_result!=NULL)
	{
		return 0;
	}
	
	gather_result=(struct gather_app_result *)dictator_malloc(a_stream->threadnum, sizeof(struct gather_app_result)*ORIGIN_MAX);
	memset(gather_result, 0, sizeof(struct gather_app_result)*ORIGIN_MAX);
	tsg_set_xxx_to_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_GATHER_APP_RESULT].id, (void *)gather_result);
	
	int app_id=tsg_l7_protocol_name2id(g_tsg_proto_name2id[protocol].name);
	if(app_id>0)
	{
		gather_result[ORIGIN_BASIC_PROTOCOL].app_num=1;
		gather_result[ORIGIN_BASIC_PROTOCOL].origin=ORIGIN_BASIC_PROTOCOL;
		gather_result[ORIGIN_BASIC_PROTOCOL].attributes[0].app_id=app_id;
		gather_result[ORIGIN_BASIC_PROTOCOL].attributes[0].surrogate_id=0;
		gather_result[ORIGIN_BASIC_PROTOCOL].attributes[0].packet_sequence=get_packet_sequence(a_stream);
	}

	return 0;
}

int set_after_n_packet_to_tcpall(const struct streaminfo *a_stream, int after_n_packets, int thread_seq)
{
	struct tcpall_context *_context=(struct tcpall_context *)tsg_get_xxx_from_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_ALL_CONTEXT].id);
	if(_context==NULL)
	{
		_context=(struct tcpall_context *)dictator_malloc(thread_seq, sizeof(struct tcpall_context));
		memset(_context, 0, sizeof(struct tcpall_context));
		tsg_set_xxx_to_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_ALL_CONTEXT].id, (void *)_context);
	}
			
	_context->hited_para.after_n_packets=after_n_packets;
	
	return 1;
}

int set_hited_app_id_to_tcpall(const struct streaminfo *a_stream, int hited_app_id, int thread_seq)
{
	struct tcpall_context *_context=(struct tcpall_context *)tsg_get_xxx_from_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_ALL_CONTEXT].id);
	if(_context==NULL)
	{
		_context=(struct tcpall_context *)dictator_malloc(thread_seq, sizeof(struct tcpall_context));
		memset(_context, 0, sizeof(struct tcpall_context));
		tsg_set_xxx_to_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_ALL_CONTEXT].id, (void *)_context);
	}
			
	_context->hited_para.hited_app_id=hited_app_id;
	
	return 1;
}

int set_protocol_to_tcpall(const struct streaminfo *a_stream, tsg_protocol_t protocol, int thread_seq)
{
	struct tcpall_context *_context=(struct tcpall_context *)tsg_get_xxx_from_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_ALL_CONTEXT].id);
	if(_context==NULL)
	{
		_context=(struct tcpall_context *)dictator_malloc(thread_seq, sizeof(struct tcpall_context));
		memset(_context, 0, sizeof(struct tcpall_context));
		tsg_set_xxx_to_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_ALL_CONTEXT].id, (void *)_context);
	}
			
	_context->protocol=protocol;
	
	return 1;
}

int set_method_to_tcpall(const struct streaminfo *a_stream, enum TSG_METHOD_TYPE method_type, int thread_seq)
{
	struct tcpall_context *_context=(struct tcpall_context *)tsg_get_xxx_from_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_ALL_CONTEXT].id);
	if(_context==NULL)
	{
		_context=(struct tcpall_context *)dictator_malloc(thread_seq, sizeof(struct tcpall_context));
		memset(_context, 0, sizeof(struct tcpall_context));
		tsg_set_xxx_to_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_ALL_CONTEXT].id, (void *)_context);
	}

	switch(_context->method_type)
	{
		case	TSG_METHOD_TYPE_UNKNOWN:
		case	TSG_METHOD_TYPE_DEFAULT:
		case	TSG_METHOD_TYPE_MIRRORED:			
			_context->method_type=method_type;
			break;
		default:
			return 0;
			break;
	}

	return 1;
}

int set_bucket_to_tcpall(const struct streaminfo *a_stream, struct leaky_bucket *bucket, int thread_seq)
{
	struct tcpall_context *_context=(struct tcpall_context *)tsg_get_xxx_from_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_ALL_CONTEXT].id);
	if(_context==NULL)
	{
		_context=(struct tcpall_context *)dictator_malloc(thread_seq, sizeof(struct tcpall_context));
		memset(_context, 0, sizeof(struct tcpall_context));
		tsg_set_xxx_to_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_ALL_CONTEXT].id, (void *)_context);
	}

	switch(_context->method_type)
	{
		case	TSG_METHOD_TYPE_RATE_LIMIT:
			return 1;
			break;
		case	TSG_METHOD_TYPE_DEFAULT:
		case	TSG_METHOD_TYPE_UNKNOWN:
			break;
		default:
			return 0;
			break;
	}

	_context->method_type=TSG_METHOD_TYPE_RATE_LIMIT;
	_context->bucket=bucket;

	return 1;
}

char get_direction_from_tcpall(const struct streaminfo *a_stream)
{
	struct tcpall_context *context=(struct tcpall_context *)tsg_get_xxx_from_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_ALL_CONTEXT].id);
	if(context!=NULL)
	{
		return context->direction;
	}

	return -1;
}

static void set_shaping_result_to_project(const struct streaminfo *a_stream, struct Maat_rule_t *p_result, int p_result_num, int thread_seq)
{
	if(p_result==NULL || p_result_num==0)
	{
		return ;
	}
	
	struct notify_shaping_policy *shaping_label=(struct notify_shaping_policy *)tsg_get_xxx_from_bridge((struct streaminfo *)a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id);
	if(shaping_label==NULL)
	{
		shaping_label=(struct notify_shaping_policy *)dictator_malloc(thread_seq, sizeof(struct notify_shaping_policy));
		memset(shaping_label, 0, sizeof(struct notify_shaping_policy));
	}

	int inc_result_num=0;
	struct Maat_rule_t *inc_result=&(shaping_label->shaping_result[shaping_label->shaping_result_num]);
	int num=MIN(MAX_RESULT_NUM-shaping_label->shaping_result_num, p_result_num);
	for(int i=0; i<num; i++)
	{
		int repeat_result=0;
		for(int j=0; j<shaping_label->shaping_result_num+inc_result_num; j++)
		{
			if(p_result[i].config_id==shaping_label->shaping_result[j].config_id)
			{
				repeat_result=1;
				break;
			}
		}

		if(repeat_result==0)
		{
			memcpy(&(inc_result[inc_result_num++]), &(p_result[i]), sizeof(struct Maat_rule_t));
		}
	}

	if(inc_result==0)
	{
		return ;
	}

	struct notify_shaping_policy sync_result={0, {0}};
	sync_result.shaping_result_num=inc_result_num;
	memcpy(sync_result.shaping_result, inc_result, inc_result_num*sizeof(struct Maat_rule_t));
	stream_bridge_sync_data_put(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id, (void *)&sync_result);

	shaping_label->shaping_result_num+=inc_result_num;
	int ret=tsg_set_xxx_to_bridge((struct streaminfo *)a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id, (void *)shaping_label);
	if(ret<0)
	{
		free_shaping_result(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id, (void *)shaping_label);
		return ;
	}
}

int tsg_notify_hited_shaping_result(const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, int thread_seq)
{
	set_shaping_result_to_project(a_stream, result, result_num, thread_seq);
	return 0;
}

int set_log_field_to_project(const struct streaminfo * a_stream, char *domain, void *para, tsg_protocol_t proto, int thread_seq)
{
	struct policy_priority_label *priority_label=(struct policy_priority_label *)tsg_get_xxx_from_bridge((struct streaminfo *)a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id);
	if(priority_label==NULL)
	{
		priority_label=(struct policy_priority_label *)dictator_malloc(thread_seq, sizeof(struct policy_priority_label));
		memset(priority_label, 0, sizeof(struct policy_priority_label));

		int ret=tsg_set_xxx_to_bridge((struct streaminfo *)a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id, (void *)priority_label);
		if(ret<0)
		{
			free_policy_label(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id, (void *)priority_label);
		}
	}

	priority_label->proto=proto;
	if(domain!=NULL)
	{
		priority_label->domain_len=MIN(sizeof(priority_label->domain)-1 ,strlen(domain));
		memcpy(priority_label->domain, domain, priority_label->domain_len);
	}

	if(para!=NULL)
	{
		int length=strlen((const char*)para);
		priority_label->para=dictator_malloc(thread_seq,length+1);
		memcpy(priority_label->para, para, length);
		((char *)priority_label->para)[length]='\0';
	}

	return 0;
}

static void set_security_result_to_project(const struct streaminfo *a_stream, struct Maat_rule_t *p_result, int p_result_num, PULL_RESULT_TYPE result_type, int thread_seq)
{
	if(p_result==NULL || p_result_num==0)
	{
		return ;
	}

	struct policy_priority_label *priority_label=(struct policy_priority_label *)tsg_get_xxx_from_bridge((struct streaminfo *)a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id);
	if(priority_label==NULL)
	{
		priority_label=(struct policy_priority_label *)dictator_malloc(thread_seq, sizeof(struct policy_priority_label));
		memset(priority_label, 0, sizeof(struct policy_priority_label));

		int ret=tsg_set_xxx_to_bridge((struct streaminfo *)a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id, (void *)priority_label);
		if(ret<0)
		{
			free_policy_label(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id, (void *)priority_label);
		}
	}
	
	int num=MIN(MAX_RESULT_NUM-priority_label->security_result_num, p_result_num);
	for(int i=0; i<num; i++)
	{
		int repeat_result=0;
		for(int j=0; j<priority_label->security_result_num; j++)
		{
			if(p_result[i].config_id==priority_label->security_result[j].config_id)
			{
				repeat_result=1;
				break;
			}
		}

		if(repeat_result==0)
		{
			memcpy(&(priority_label->security_result[priority_label->security_result_num++]), &(p_result[i]), sizeof(struct Maat_rule_t));
		}
	}
	
	return ;
}

int tsg_notify_hited_security_result(const struct streaminfo * a_stream, struct Maat_rule_t * p_result, int p_result_num, int thread_seq)
{
	set_security_result_to_project(a_stream, p_result, p_result_num, PULL_FW_RESULT, thread_seq);
	return 0;
}


void set_session_attribute_label(const struct streaminfo *a_stream, enum TSG_ATTRIBUTE_TYPE type, void *value, int value_len, int thread_seq)
{
	unsigned long long create_time=0;
	unsigned long long current_time=0;
	int ret=0,size=sizeof(create_time);
	struct _ssl_ja3_info_t *ja3_info=NULL;
	struct session_attribute_label *attribute_label=NULL;

	attribute_label=(struct session_attribute_label *)project_req_get_struct(a_stream, g_tsg_para.session_attribute_project_id);
	if(attribute_label==NULL)
	{
		attribute_label=(struct session_attribute_label *)dictator_malloc(thread_seq, sizeof(struct session_attribute_label));
		memset(attribute_label, 0, sizeof(struct session_attribute_label));

		ret=project_req_add_struct((struct streaminfo *)a_stream, g_tsg_para.session_attribute_project_id, (const void *)attribute_label);
		if(ret<0)
		{
			dictator_free(thread_seq, (void *)attribute_label);
			attribute_label=NULL;
			return ;
		}
	}

	switch(type)
	{
		case	TSG_ATTRIBUTE_TYPE_ESTABLISH_LATECY:
			ret=MESA_get_stream_opt(a_stream, MSO_STREAM_CREATE_TIMESTAMP_MS, (void *)&create_time, &size);
			if(ret<0)
			{
				break;
			}
			
			size=sizeof(current_time);
			ret=sapp_get_platform_opt(SPO_CURTIME_TIMET_MS, (void *)&current_time, &size);
			if(ret<0)
			{
				break;
			}

			attribute_label->establish_latency_ms=current_time-create_time;
			break;
		case	TSG_ATTRIBUTE_TYPE_PROTOCOL:
			attribute_label->proto=(tsg_protocol_t)(*(int *)value);
			break;
		case	TSG_ATTRIBUTE_TYPE_HTTP_ACTION_FILESIZE:
			attribute_label->http_action_file_size=(*(int *)value);
			break;
		case	TSG_ATTRIBUTE_TYPE_JA3_HASH:
			ja3_info=ssl_get_ja3_fingerprint((struct streaminfo *)a_stream, (unsigned char *)a_stream->ptcpdetail->pdata, (unsigned int)a_stream->ptcpdetail->datalen, a_stream->threadnum);
			if(ja3_info!=NULL)
			{
				if(attribute_label!=NULL && ja3_info->fp!=NULL && ja3_info->fp_len>0)
				{
					attribute_label->ja3_fingerprint=(char *)dictator_malloc(a_stream->threadnum, ja3_info->fp_len+1);
					memset(attribute_label->ja3_fingerprint, 0, ja3_info->fp_len+1);
					memcpy(attribute_label->ja3_fingerprint, ja3_info->fp, ja3_info->fp_len);
				}			
			}
			break;
		case	TSG_ATTRIBUTE_TYPE_MLTS_USER_INFO:
			tsg_get_umts_user_info(a_stream, &(attribute_label->user_info));
			break;
		case	TSG_ATTRIBUTE_TYPE_SUBSCRIBER_ID:
			tsg_get_subscribe_id(a_stream, &attribute_label->client_subscribe_id, &attribute_label->server_subscribe_id);
			break;
		case	TSG_ATTRIBUTE_TYPE_ASN:
			tsg_get_ip_asn(a_stream, g_tsg_para.table_id[TABLE_ASN_USER_DEFINED], (void **)&(attribute_label->client_asn), (void **)&(attribute_label->server_asn));
			tsg_get_ip_asn(a_stream, g_tsg_para.table_id[TABLE_ASN_BUILT_IN], (void **)&(attribute_label->client_asn), (void **)&(attribute_label->server_asn));
			break;
		case	TSG_ATTRIBUTE_TYPE_LOCATION:
			tsg_get_ip_location(a_stream, g_tsg_para.table_id[TABLE_LOCATION_USER_DEFINED], (void **)&(attribute_label->client_location), (void **)&(attribute_label->server_location));
			tsg_get_ip_location(a_stream, g_tsg_para.table_id[TABLE_LOCATION_BUILT_IN], (void **)&(attribute_label->client_location), (void **)&(attribute_label->server_location));
			break;
		case	TSG_ATTRIBUTE_TYPE_CATEGORY_ID:
			if(value_len<=0 || value_len>MAX_CATEGORY_ID_NUM)
			{
				break;
			}
			memcpy(attribute_label->fqdn_category_id, value, sizeof(unsigned int)*value_len);
			attribute_label->fqdn_category_id_num=value_len;
			break;
		case	TSG_ATTRIBUTE_TYPE_SESSION_FLAGS:
			attribute_label->session_flags=*(unsigned long *)(value);
			break;
		default:
			break;
	}

	return ;
}

static char set_tcp_establish_latency_ms(const struct streaminfo *a_tcp, int thread_seq,const void *ip_hdr)
{
	struct tcphdr *tcp=NULL;

	if(ip_hdr==NULL || a_tcp==NULL)
	{
		return 0;
	}
	
	switch(a_tcp->addr.addrtype)
	{
		case	ADDR_TYPE_IPV4: 	
			tcp=(struct tcphdr *)MESA_net_jump_to_layer(ip_hdr, __ADDR_TYPE_IP_PAIR_V4, ADDR_TYPE_TCP); 			
			break;
		case	ADDR_TYPE_IPV6: 			
			tcp=(struct tcphdr *)MESA_net_jump_to_layer(ip_hdr, __ADDR_TYPE_IP_PAIR_V6, ADDR_TYPE_TCP);
			break;
		default:
			return 0;
			break;
	}
	
	if((tcp!=NULL) && !(tcp->syn))
	{
		set_session_attribute_label(a_tcp, TSG_ATTRIBUTE_TYPE_ESTABLISH_LATECY, NULL, 0, a_tcp->threadnum);
		return 1;
	}

	return 0;
}

int tsg_set_device_id_to_telegraf(char *device_sn)
{
	if(device_sn)
	{
		FILE *fp=fopen("/etc/default/telegraf", "wb");
		if(fp)
		{
			char buff[128]={0};
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
	struct session_attribute_label *label=(struct session_attribute_label *)project_req_value;

	if(label!=NULL)
	{
		if(label->client_asn!=NULL)
		{
			ASN_number_free(0, (MAAT_PLUGIN_EX_DATA *)&(label->client_asn), 0, g_tsg_para.logger);
			label->client_asn=NULL;
		}

		if(label->server_asn!=NULL)
		{
			ASN_number_free(0, (MAAT_PLUGIN_EX_DATA *)&(label->server_asn), 0, g_tsg_para.logger);
			label->server_asn=NULL;
		}

		if(label->client_location!=NULL)
		{
			location_free_data(0, (MAAT_PLUGIN_EX_DATA *)&(label->client_location), 0, g_tsg_para.logger);
			label->client_location=NULL;
		}

		if(label->server_location!=NULL)
		{
			location_free_data(0, (MAAT_PLUGIN_EX_DATA *)&(label->server_location), 0, g_tsg_para.logger);
			label->server_location=NULL;
		}

		if(label->client_subscribe_id!=NULL)
		{
			subscriber_id_free(0, (MAAT_PLUGIN_EX_DATA *)&label->client_subscribe_id, 0, g_tsg_para.logger);
			label->client_subscribe_id=NULL;
		}

		if(label->server_subscribe_id!=NULL)
		{
			subscriber_id_free(0, (MAAT_PLUGIN_EX_DATA *)&label->server_subscribe_id, 0, g_tsg_para.logger);
			label->server_subscribe_id=NULL;
		}

		if(label->ja3_fingerprint!=NULL)
		{
			dictator_free(thread_seq, (void *)label->ja3_fingerprint);
			label->ja3_fingerprint=NULL;
		}

		if(label->user_info!=NULL)
		{
			gtp_c_free_data(0, (MAAT_PLUGIN_EX_DATA *)&label->user_info, 0, g_tsg_para.logger);
			label->user_info=NULL;
		}

		if(label->client_endpoint!=NULL)
		{
			tunnel_endpoint_free(0, (MAAT_PLUGIN_EX_DATA *)&label->client_endpoint, 0, g_tsg_para.logger);
			label->client_endpoint=NULL;
		}

		if(label->server_endpoint!=NULL)
		{
			tunnel_endpoint_free(0, (MAAT_PLUGIN_EX_DATA *)&label->server_endpoint, 0, g_tsg_para.logger);
			label->server_endpoint=NULL;
		}
		dictator_free(thread_seq, project_req_value);
		project_req_value=NULL;
	}
}

struct Maat_rule_t *tsg_policy_decision_criteria(Maat_rule_t *result, int result_num)
{
	int i=0;
	Maat_rule_t *p_result=NULL;

	for(i=0; i<result_num; i++)
	{
		if(p_result==NULL)
		{
			p_result=&result[i];
			continue;
		}
		
		if((unsigned char)result[i].action>(unsigned char)p_result->action)
		{
			p_result=&result[i];
			continue;
		}
		
		if(result[i].action==p_result->action)
		{
			if(result[i].config_id>p_result->config_id)
			{
				p_result=&result[i];
			}
		}	
	}

	return p_result;
}

static int identify_application_protocol(const struct streaminfo *a_stream, struct master_context *context, void *a_packet)
{
	int ret=0;

	switch(a_stream->type)
	{
		case	STREAM_TYPE_TCP:
			if(g_tsg_para.proto_flag&(1<<PROTO_HTTP))  //http
			{
				char *host=NULL, *url=NULL;
				void *parser_result=http_field_parser((char *)a_stream->ptcpdetail->pdata, (unsigned int)a_stream->ptcpdetail->datalen, a_stream->curdir);
				if(parser_result!=NULL)
				{
					context->proto=PROTO_HTTP;
					
					int length=http_get_filed_result(parser_result, HTTP_HOST, &host);
					context->domain=malloc_copy_string(host, length, a_stream->threadnum);
					length=http_get_filed_result(parser_result, HTTP_MESSAGE_URL, &url);
					context->http_url=malloc_copy_string(url, length, a_stream->threadnum);

					http_free_filed_result(parser_result);
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
					context->proto=PROTO_SSL;
					if(chello->sni!=NULL)
					{
						context->domain=malloc_copy_string(chello->sni, strlen(chello->sni), a_stream->threadnum);
					}

					context->is_esni=(int)chello->is_encrypt_sni;
					
					ssl_chello_free(chello);
					return 1;
				}
				
			    ssl_chello_free(chello);
			}
	
			if(g_tsg_para.proto_flag&(1<<PROTO_FTP))  //ftp
			{
				ret=ftp_control_identify((struct streaminfo *)a_stream);
				if(ret>0)
				{
					context->proto=PROTO_FTP;
					return 1;
				}

				ret=ftp_data_identify((struct streaminfo *)a_stream);
				if(ret>0)
				{
					context->proto=PROTO_FTP;
					return 1;
				}
			}
			
			if(g_tsg_para.proto_flag&(1<<PROTO_MAIL))  //mail
			{
				ret=mail_protocol_identify_by_first_payload((struct streaminfo *)a_stream,(char *)a_stream->ptcpdetail->pdata, a_stream->ptcpdetail->datalen, a_stream->threadnum);
				if(ret>0)
				{
					switch(ret)
					{
						case	SMTP_PROTOCOL:
							context->proto=PROTO_SMTP;
							return 1;
							break;
						case	POP3_PROTOCOL:
							context->proto=PROTO_POP3;
							return 1;
							break;
						case	IMAP_PROTOCOL:
							context->proto=PROTO_IMAP;
							return 1;
							break;
						default:
							break;
					}
				}
			}

			if(g_tsg_para.proto_flag&(1<<PROTO_SSH))  //ssh
			{
				ret = ssh_protocol_identify((unsigned char *)a_stream->ptcpdetail->pdata, (unsigned int)a_stream->ptcpdetail->datalen,g_tsg_para.logger);
				if(ret > 0)
				{
					context->proto=PROTO_SSH;
					return 1;
				}
			}

			if(g_tsg_para.proto_flag&(1<<PROTO_STRATUM))  //Stratum
			{
				ret=stratum_identify((struct streaminfo *)a_stream, NULL, a_stream->threadnum, a_packet);
				if(ret==IS_STRATUM)
				{
					context->proto=PROTO_STRATUM;
					return 1;
				}
			}

			if(g_tsg_para.proto_flag&(1<<PROTO_RDP))  //RDP
			{
				ret=rdp_protocol_identify((const char *)a_stream->ptcpdetail->pdata, a_stream->ptcpdetail->datalen, (unsigned int)a_stream->threadnum);
				if(ret==1)
				{
					context->proto=PROTO_RDP;
					return 1;
				}
			}

			break;
		case	STREAM_TYPE_UDP:
			if(g_tsg_para.proto_flag&(1<<PROTO_DNS))  //dns
			{
				if(is_dns_protocol(a_stream))
				{
					context->proto=PROTO_DNS;
					return 1;
				}
			}
			
			if(g_tsg_para.proto_flag&(1<<PROTO_QUIC))  //quic
			{
				char ua_buff[512]={0};
				char sni_buff[512]={0};
				int sni_len=sizeof(sni_buff),ua_len=sizeof(ua_buff);
				context->quic_version=quic_protocol_identify((struct streaminfo *)a_stream, a_packet, sni_buff, &sni_len, ua_buff, &ua_len);
				if(context->quic_version > 0)
				{
					context->proto=PROTO_QUIC;
					context->domain=malloc_copy_string(sni_buff, sni_len, a_stream->threadnum);
					context->quic_ua=malloc_copy_string(ua_buff, ua_len, a_stream->threadnum);
					return 1;
				}
			}

			if(g_tsg_para.proto_flag&(1<<PROTO_SIP))
			{
				unsigned char sip_ret=0;
				char *from=NULL, *to=NULL;
				unsigned int from_len=0, to_len=0;
				sip_ret=sip_identify_from_to((char *)a_stream->pudpdetail->pdata, (unsigned int)a_stream->pudpdetail->datalen, &from, &from_len, &to, &to_len);
				if(sip_ret==SIP_TRUE)
				{
					context->proto=PROTO_SIP;
					return 1;
				}				
			}

			if(g_tsg_para.proto_flag&(1<<PROTO_RDP))  //RDP
			{
				ret=rdpudp_protocol_identify((const char *)a_stream->pudpdetail->pdata, a_stream->pudpdetail->datalen, (unsigned int)a_stream->threadnum);
				if(ret==1)
				{
					context->proto=PROTO_RDP;
					return 1;
				}
			}

			if (g_tsg_para.proto_flag&(1<<PROTO_DTLS)) //DTLS
			{
				bool is_dtls = dtls_identifyStream((struct streaminfo *)a_stream);
				if (is_dtls)
				{
					char sni_buff[512]={0};
					int sni_len=sizeof(sni_buff);
					context->proto = PROTO_DTLS;
					ret = dtls_parse_sni((const char *)a_stream->pudpdetail->pdata, a_stream->pudpdetail->datalen, sni_buff, sni_len);
					if (ret == 0 && strlen(sni_buff) > 0)
					{
						context->domain = malloc_copy_string(sni_buff, sni_len, a_stream->threadnum);
						return 1;
					}
				}
			}
			break;
		default:
			break;
	}

	if(context->proto<PROTO_HTTP || context->proto>PROTO_MAX)
	{
		context->proto = PROTO_UNKONWN;
	}
	
	return ret;
}

int scan_application_id_and_properties(const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, struct master_context *context, struct gather_app_result *identify_result, int thread_seq)
{
	int i=0,hit_num=0;
	int hited_app_id=0;
	int after_n_packets=0;
	char *name=NULL;
	char app_id_buff[32]={0};
	struct app_id_dict *dict=NULL;
	struct Maat_rule_t *p_result, *d_result=NULL;

	for(i=0; i< identify_result->app_num; i++)
	{
		snprintf(app_id_buff, sizeof(app_id_buff), "%u", identify_result->attributes[i].app_id);
		dict=(struct app_id_dict *)Maat_plugin_get_EX_data(g_tsg_maat_feather, g_tsg_para.table_id[TABLE_APP_ID_DICT], (const char *)app_id_buff);
		if(dict!=NULL)
		{
			hit_num+=tsg_scan_app_properties_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, &(context->mid), dict->risk, (char *)"risk", thread_seq);
			hit_num+=tsg_scan_app_properties_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, &(context->mid), dict->category, (char *)"category", thread_seq);	
			hit_num+=tsg_scan_app_properties_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, &(context->mid), dict->technology, (char *)"technology", thread_seq);	
			hit_num+=tsg_scan_app_properties_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, &(context->mid), dict->subcategroy, (char *)"subcategory", thread_seq);	
			hit_num+=tsg_scan_app_properties_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, &(context->mid), dict->characteristics, (char *)"characteristics", thread_seq);

			hit_num+=tsg_scan_app_id_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, &(context->mid), dict->app_name, identify_result->attributes[i].app_id, thread_seq);
			after_n_packets=dict->deny_app_para.after_n_packets;
			
			set_app_timeout(a_stream, dict, &(context->timeout));
			app_id_dict_free(g_tsg_para.table_id[TABLE_APP_ID_DICT], (MAAT_PLUGIN_EX_DATA *)&dict, 0, NULL);
		}
		else
		{
			name=tsg_l7_protocol_id2name(identify_result->attributes[i].app_id);
			hit_num+=tsg_scan_app_id_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, &(context->mid), ((name==NULL) ? (char *)"" : name), identify_result->attributes[i].app_id, thread_seq);
		}

		p_result=tsg_fetch_deny_rule(result, hit_num);
		if(d_result==NULL)
		{
			d_result=p_result;
			hited_app_id=identify_result->attributes[i].app_id;
			continue;
		}
		
		if(d_result->config_id!=p_result->config_id)
		{
			d_result=p_result;
			hited_app_id=identify_result->attributes[i].app_id;
		}
	}	

	if(hit_num>0)
	{
		if(identify_result->origin!=ORIGIN_BASIC_PROTOCOL)
		{
			context->hited_app_id=hited_app_id;
		}
		
		context->hited_para.hited_app_id=hited_app_id;
		context->hited_para.after_n_packets=after_n_packets;
	}
	else
	{
		if(identify_result->origin==ORIGIN_BASIC_PROTOCOL && after_n_packets>0) //for tsg_protocol_t
		{
			context->hited_para.after_n_packets=after_n_packets;			
		}
	}
		
	return hit_num;
}

static int master_deal_shaping_result(const struct streaminfo *a_stream, struct Maat_rule_t *shaping_result, int shaping_result_num)
{
	//get shaping rule
	set_shaping_result_to_project(a_stream, shaping_result, shaping_result_num, a_stream->threadnum);

	FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_SHAPING], 0, FS_OP_ADD, 1);
	set_method_to_tcpall(a_stream, TSG_METHOD_TYPE_UNKNOWN, a_stream->threadnum);

	return 0;
}

static unsigned char master_deal_scan_result(const struct streaminfo *a_stream, struct master_context *context, struct Maat_rule_t *result, int hit_num, const void *a_packet)
{
	struct Maat_rule_t *p_result=NULL;
	unsigned char state=APP_STATE_GIVEME;
	struct Maat_rule_t shaping_result[MAX_RESULT_NUM]={0};
	struct Maat_rule_t security_result[MAX_RESULT_NUM]={0};

	int security_result_num=tsg_fetch_hited_security_result(result, hit_num, security_result, MAX_RESULT_NUM);
	p_result=tsg_policy_decision_criteria(security_result, hit_num);
	if(p_result!=NULL)
	{
		print_hit_path(a_stream, context);
		switch((unsigned char)p_result->action)
		{
			case	TSG_ACTION_DENY:
				if(is_deny_application(p_result))
				{
					if(context->hited_para.hited_app_id==0)
					{
						context->hited_para.hited_app_id=tsg_l7_protocol_name2id(g_tsg_proto_name2id[context->proto].name);
					}

					set_hited_app_id_to_tcpall(a_stream, context->hited_para.hited_app_id, a_stream->threadnum);
					state=tsg_deny_application(a_stream, p_result, context->proto, context->hited_para.hited_app_id, ACTION_RETURN_TYPE_APP, a_packet);
				}
				else
				{
					state=tsg_deal_deny_action(a_stream, p_result, context->proto, ACTION_RETURN_TYPE_APP, a_packet);
				}

				if(is_deny_after_N_packets(p_result))
				{
					set_security_result_to_project(a_stream, p_result, 1, PULL_FW_RESULT, a_stream->threadnum);
					if(a_stream->type==STREAM_TYPE_TCP)
					{
						break;
					}
				}

				if(context->hited_result==NULL)
				{
					context->hited_result=(struct Maat_rule_t *)dictator_malloc(1, sizeof(struct Maat_rule_t));
					memcpy(context->hited_result, p_result, sizeof(struct Maat_rule_t));
				}
				break;
			case	TSG_ACTION_MONITOR:
				if(context->proto==PROTO_RTP)
				{
					break;
				}
				tsg_notify_hited_monitor_result(a_stream, result, hit_num, a_stream->threadnum);
				set_security_result_to_project(a_stream, security_result, security_result_num, PULL_FW_RESULT, a_stream->threadnum);
				break;
			case	TSG_ACTION_BYPASS:
				context->is_hited_allow=1;
				context->hited_result=(struct Maat_rule_t *)dictator_malloc(1, sizeof(struct Maat_rule_t));
				memcpy(context->hited_result, p_result, sizeof(struct Maat_rule_t));
				//set_security_result_to_project(a_stream, p_result, 1, PULL_FW_RESULT, a_stream->threadnum);
				FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_BYPASS], 0, FS_OP_ADD, 1);
				state=APP_STATE_GIVEME|APP_STATE_KILL_OTHER;

				set_method_to_tcpall(a_stream, TSG_METHOD_TYPE_ALLOW, a_stream->threadnum);
				break;
			case	TSG_ACTION_INTERCEPT:
				if(is_intercept_exclusion(a_stream, p_result, context->domain, a_stream->threadnum))
				{
					FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_EXCLUSION], 0, FS_OP_ADD, 1);
					break;
				}
				
				set_security_result_to_project(a_stream, p_result, 1, PULL_KNI_RESULT, a_stream->threadnum);
				FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_INTERCEPT], 0, FS_OP_ADD, 1);
				state=APP_STATE_DROPME|APP_STATE_KILL_OTHER;

				set_method_to_tcpall(a_stream, TSG_METHOD_TYPE_UNKNOWN, a_stream->threadnum);
				break;
			default:
				break;
		}

		set_log_field_to_project(a_stream, context->domain, context->para, context->proto, a_stream->threadnum);
	}

	int shaping_result_num=tsg_fetch_hited_shaping_result(result, hit_num, shaping_result, MAX_RESULT_NUM);
	if(state==APP_STATE_GIVEME && shaping_result_num>0)
	{
		master_deal_shaping_result(a_stream, shaping_result, shaping_result_num);
	}

	return state;
}

int app_identify_result_cb(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	struct master_context *context=NULL;
	struct gather_app_result *gather_result=NULL;
	struct Maat_rule_t scan_result[MAX_RESULT_NUM]={0};
	struct app_identify_result *identify_result=(struct app_identify_result *)data;

	if(data==NULL)
	{
		return 0;
	}

	context=(struct master_context *)tsg_get_xxx_from_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_DATA_CONTEXT].id);
	if(context==NULL)
	{
		init_context((void **)(&context), a_stream->threadnum);
		tsg_set_xxx_to_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_DATA_CONTEXT].id, (void *)context);
	}

	gather_result=(struct gather_app_result *)tsg_get_xxx_from_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_GATHER_APP_RESULT].id);
	if(gather_result==NULL)
	{
		gather_result=(struct gather_app_result *)dictator_malloc(a_stream->threadnum, sizeof(struct gather_app_result)*ORIGIN_MAX);
		memset(gather_result, 0, sizeof(struct gather_app_result)*ORIGIN_MAX);
		tsg_set_xxx_to_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_GATHER_APP_RESULT].id, (void *)gather_result);
	}
	
	switch(identify_result->origin)
	{
			break;
		case	ORIGIN_QM_ENGINE:
			context->is_app_link=FLAG_TRUE;
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_APP_Q_RESULT], 0, FS_OP_ADD, 1);
			break;
		case	ORIGIN_USER_DEFINE:
			context->is_app_link=FLAG_TRUE;
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_APP_USER_RESULT], 0, FS_OP_ADD, 1);
			break;
		case	ORIGIN_BUILT_IN:
			context->is_app_link=FLAG_TRUE;
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_APP_BUILT_IN_RESULT], 0, FS_OP_ADD, 1);
			break;
		case	ORIGIN_BASIC_PROTOCOL:
			context->is_app_link=FLAG_TRUE;
			if(context->proto==PROTO_UNKONWN || context->proto==PROTO_APP)
			{
				set_l7_protocol_to_pme(context, identify_result->app_id[identify_result->app_id_num-1]);
			}
			break;
		case	ORIGIN_UNKNOWN:
			context->is_app_link=FLAG_TRUE;
			break;
		default:
			MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "APP_BRIDGE_CB", "Unknown type: %d addr: %s", identify_result->origin, PRINTADDR(a_stream, g_tsg_para.level));
			return 0;
	}

	copy_app_result(&(gather_result[identify_result->origin]), identify_result, get_packet_sequence(a_stream));

	if(context->mid==NULL)
	{
		return 0;
	}
	
	context->last_scan_time=get_current_time_ms();
	int hit_num=scan_application_id_and_properties((struct streaminfo *)a_stream, scan_result, MAX_RESULT_NUM, context, &(gather_result[identify_result->origin]), a_stream->threadnum);

	context->sync_cb_state=master_deal_scan_result(a_stream, context, scan_result, hit_num, NULL);
	return 0;
}

int session_flags_identify_result_cb(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	if(data==NULL)
	{
		return 0;
	}

	struct master_context *context=NULL;
	struct Maat_rule_t scan_result[MAX_RESULT_NUM]={0};

	context=(struct master_context *)tsg_get_xxx_from_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_DATA_CONTEXT].id);
	if(context==NULL)
	{
		init_context((void **)(&context), a_stream->threadnum);
		tsg_set_xxx_to_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_DATA_CONTEXT].id, (void *)context);
	}

	context->session_flag=*(unsigned long *)(data);
	set_session_attribute_label(a_stream, TSG_ATTRIBUTE_TYPE_SESSION_FLAGS, data, sizeof(unsigned long), a_stream->threadnum);

	int hit_num=tsg_scan_session_flags(g_tsg_maat_feather, a_stream, scan_result, MAX_RESULT_NUM, &context->mid, g_tsg_para.table_id[TABLE_SESSION_FLAGS], context->session_flag, a_stream->threadnum);

	context->sync_cb_state=master_deal_scan_result(a_stream, context, scan_result, hit_num, NULL);

	return 0;
}


static int deal_pending_state(const struct streaminfo *a_stream, struct master_context *context, struct Maat_rule_t *result, int result_num, void *a_packet)
{
	int hit_num=0;
	
	int ret=identify_application_protocol(a_stream, context, a_packet);
	if(ret==1)
	{
		set_l7_protocol_label(a_stream, context->proto);
		context->is_app_link=FLAG_TRUE;
		set_session_attribute_label(a_stream, TSG_ATTRIBUTE_TYPE_PROTOCOL, (void *)&(context->proto), sizeof(int), a_stream->threadnum);

		if(context->proto==PROTO_SSL)
		{
			set_session_attribute_label(a_stream, TSG_ATTRIBUTE_TYPE_JA3_HASH, NULL, 0, a_stream->threadnum);
		}
		
		int table_id=get_table_id(context->proto);	
		hit_num+=tsg_scan_shared_policy(g_tsg_maat_feather, a_stream, context->domain, result+hit_num, MAX_RESULT_NUM-hit_num, &context->mid, table_id, a_stream->threadnum);
		hit_num+=scan_fqdn_category_id(g_tsg_maat_feather, a_stream, context->domain, result+hit_num, MAX_RESULT_NUM-hit_num, &context->mid, table_id, a_stream->threadnum);
		if(context->is_esni)
		{
			unsigned int protocol_id=tsg_l7_protocol_name2id("ESNI");
			hit_num+=tsg_scan_app_id_policy(g_tsg_maat_feather, a_stream, result+hit_num, MAX_RESULT_NUM-hit_num, &context->mid, (char *)"ESNI", protocol_id, a_stream->threadnum);
		}

		if(context->proto==PROTO_HTTP && context->http_url!=NULL)
		{
			hit_num+=tsg_scan_shared_policy(g_tsg_maat_feather, a_stream, context->http_url, result+hit_num, MAX_RESULT_NUM-hit_num, &context->mid, g_tsg_para.table_id[TABLE_HTTP_URL], a_stream->threadnum);
		}
	}

	ret=tsg_scan_nesting_addr(g_tsg_maat_feather, a_stream, context->proto, &context->mid, result+hit_num, MAX_RESULT_NUM-hit_num);
	if(ret>0)
	{
		hit_num+=ret;
		FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_HIT_ADDR], 0, FS_OP_ADD, 1);		
	}

	struct gather_app_result *gather_result=(struct gather_app_result *)tsg_get_xxx_from_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_GATHER_APP_RESULT].id);
	for(int i=0; i<ORIGIN_MAX && gather_result!=NULL; i++)
	{
		if(i==ORIGIN_HITED_APP || i==ORIGIN_QM_ENGINE_L7)
		{
			continue;
		}
		hit_num+=scan_application_id_and_properties(a_stream, result+hit_num, MAX_RESULT_NUM-hit_num, context, &(gather_result[i]), a_stream->threadnum);
	}
			
	
	if((is_only_monitor(result, hit_num)) && context->proto==PROTO_DNS)	// business deal action of monitor 
	{
		hit_num=0;
	}

	return hit_num;
}

static unsigned char tsg_master_data_entry(const struct streaminfo *a_stream, void **pme, int thread_seq,void *a_packet)
{
	int i=0,ret=0,hit_num=0;
	unsigned char state=APP_STATE_GIVEME;
	Maat_rule_t hited_result[MAX_RESULT_NUM];
	struct gather_app_result *gather_result=NULL;
	struct master_context *context=(struct master_context *)*pme;
	struct app_identify_result unknown_result;

	if(*pme==NULL)
	{
		context=(struct master_context *)tsg_get_xxx_from_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_DATA_CONTEXT].id);
		if(context==NULL)
		{
			init_context(pme, thread_seq);
			context=(struct master_context *)*pme;
			tsg_set_xxx_to_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_DATA_CONTEXT].id, *pme);
		}
		else
		{
			*pme=(void *)context;
		}
		context->last_scan_time=get_current_time_ms();
	}
	
	switch(a_stream->opstate)
	{
		case	OP_STATE_PENDING:
			if(a_stream->type==STREAM_TYPE_TCP)
			{		
				FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_TCP_LINKS], 0, FS_OP_ADD, 1); 		
			}
			else
			{
				FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_UDP_LINKS], 0, FS_OP_ADD, 1);
			}
			
			hit_num+=deal_pending_state(a_stream, context, hited_result+hit_num, MAX_RESULT_NUM-hit_num, a_packet);
			state=master_deal_scan_result(a_stream, context, hited_result, hit_num, a_packet);
			context->deal_pkt_num++;
			break;
		case	OP_STATE_DATA:
			if(context->is_app_link==FLAG_FALSE && (context->deal_pkt_num++) == (g_tsg_para.identify_app_max_pkt_num+1))
			{
				unknown_result.app_id_num=1;
				unknown_result.surrogate_id[0]=0;
				unknown_result.origin=ORIGIN_UNKNOWN;
				unknown_result.app_id[0]=g_tsg_para.unknown_app_id;

				app_identify_result_cb(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_APP_IDENTIFY_RESULT].id, (void *)&unknown_result);
			}
		
			if(context->is_hited_allow)
			{
				state=APP_STATE_KILL_OTHER|APP_STATE_GIVEME;
				break;
			}

			if(context->sync_cb_state&APP_STATE_KILL_OTHER || context->sync_cb_state&APP_STATE_DROPPKT)
			{
				//tcpall, udp -> allow, Deny(after drop N packets)
				state=context->sync_cb_state|APP_STATE_DROPME;
				break;
			}
			
			if(get_current_time_ms()-context->last_scan_time < (g_tsg_para.scan_time_interval*1000))
			{
				break;
			}

			if(context->mid!=NULL)
			{
				Maat_clean_status(&context->mid);
				context->mid=NULL;
			}
			
			context->last_scan_time=get_current_time_ms();
			ret=tsg_scan_nesting_addr(g_tsg_maat_feather, a_stream, context->proto, &context->mid, hited_result+hit_num, MAX_RESULT_NUM-hit_num);
			if(ret>0)
			{
				hit_num+=ret;
			}
			
			gather_result=(struct gather_app_result *)tsg_get_xxx_from_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_GATHER_APP_RESULT].id);
			for(i=0; i<ORIGIN_MAX && gather_result!=NULL; i++)
			{
				if(i==ORIGIN_HITED_APP || i==ORIGIN_QM_ENGINE_L7)
				{
					continue;
				}
				hit_num+=scan_application_id_and_properties(a_stream, hited_result+hit_num, MAX_RESULT_NUM-hit_num, context, &(gather_result[i]), thread_seq);
			}

			if(context->session_flag>0)
			{
				hit_num+=tsg_scan_session_flags(g_tsg_maat_feather, 
													a_stream,
													hited_result+hit_num,
													MAX_RESULT_NUM-hit_num,
													&context->mid,
													g_tsg_para.table_id[TABLE_SESSION_FLAGS],
													context->session_flag,
													thread_seq
												);
			}
			
			state=master_deal_scan_result(a_stream, context, hited_result, hit_num, a_packet);
			break;
		default:
			break;
	}
		
	if((a_stream->opstate==OP_STATE_CLOSE) || (state&APP_STATE_DROPME)==APP_STATE_DROPME)
	{
		if(context->hited_result)
		{
			master_send_log(a_stream, context->hited_result, 1, context, thread_seq);
		}
		*pme=NULL;
	}

	return state;
}

static unsigned char tsg_master_all_entry(const struct streaminfo *a_stream, unsigned char stream_state, void **pme, int thread_seq, const void *a_packet)
{
	int ret=0;
	int eth_rawpkt_len=0;
	scan_status_t scan_mid=NULL;
	struct Maat_rule_t *p_result=NULL;
	unsigned char state=APP_STATE_GIVEME;
	struct Maat_rule_t hited_result[MAX_TSG_ALL_RESULT_NUM]={0};
	struct Maat_rule_t security_result[MAX_RESULT_NUM]={0};	
	struct Maat_rule_t shaping_result[MAX_RESULT_NUM]={0};
	struct tcpall_context *all_context=(struct tcpall_context *)(*pme);
	struct policy_priority_label *priority_label=NULL;

	if(stream_state==OP_STATE_PENDING && all_context->method_type!=TSG_METHOD_TYPE_ALLOW && !(all_context->udp_data_dropme))
	{
		if(all_context->method_type==TSG_METHOD_TYPE_UNKNOWN)
		{			
			all_context->method_type=TSG_METHOD_TYPE_DEFAULT;
			all_context->default_policy_after_n_packets=get_default_para(a_stream, g_tsg_para.default_compile_id);
		}
		
		int hit_num=tsg_scan_nesting_addr(g_tsg_maat_feather, a_stream, PROTO_UNKONWN, &scan_mid, hited_result, MAX_TSG_ALL_RESULT_NUM);
		if(hit_num>0)
		{
			int security_result_num=tsg_fetch_hited_security_result(hited_result, hit_num, security_result, MAX_RESULT_NUM);
			p_result=tsg_policy_decision_criteria(security_result, security_result_num);
			if(p_result!=NULL)
			{
				switch(p_result->action)
				{
					case	TSG_ACTION_DENY:
						state=tsg_deal_deny_action(a_stream, p_result, PROTO_UNKONWN, ACTION_RETURN_TYPE_TCPALL, a_packet);
						master_send_log(a_stream, p_result, 1, NULL, thread_seq);
						break;
					case	TSG_ACTION_MONITOR:
						tsg_notify_hited_monitor_result(a_stream, security_result, hit_num, thread_seq);
						set_security_result_to_project(a_stream, security_result, security_result_num, PULL_FW_RESULT,thread_seq);
						break;
					default:
						break;
				}
			}

			int shaping_result_num=tsg_fetch_hited_shaping_result(hited_result, hit_num, shaping_result, MAX_RESULT_NUM);
			if(state==APP_STATE_GIVEME && shaping_result_num>0)
			{
				master_deal_shaping_result(a_stream, shaping_result, shaping_result_num);
			}
		}
		
		Maat_clean_status(&scan_mid);
		scan_mid=NULL;
	}

	switch(all_context->method_type)
	{
		case	TSG_METHOD_TYPE_RATE_LIMIT:
			eth_rawpkt_len=get_raw_packet_len(a_stream);
			if(eth_rawpkt_len<=0)
			{
				break;
			}
	
			ret=is_permit_pass(eth_rawpkt_len*8, all_context->bucket, thread_seq);
			if(ret==0)
			{
				state|=APP_STATE_GIVEME|APP_STATE_DROPPKT;
			}
			break;
		case    TSG_METHOD_TYPE_TAMPER:
			if(0 == send_tamper_xxx(a_stream, &all_context->tamper_count, a_packet))
			{
				state|=APP_STATE_GIVEME|APP_STATE_DROPPKT;
			}
			break;
		case	TSG_METHOD_TYPE_DEFAULT:
			if(!is_do_default_policy(a_stream, all_context->default_policy_after_n_packets) || stream_state==OP_STATE_CLOSE)
			{
				break;
			}
			
			if(get_default_policy(g_tsg_para.default_compile_id, &security_result[0]))
			{
				state=tsg_deal_deny_action(a_stream, &security_result[0], PROTO_UNKONWN, ACTION_RETURN_TYPE_TCPALL, a_packet);
				master_send_log(a_stream, &security_result[0], 1, NULL, thread_seq);
			}
			break;
		case	TSG_METHOD_TYPE_DROP:
		case	TSG_METHOD_TYPE_APP_DROP:
			// contain hited current packet, platform calls tcp first and tcpall secondary.
			if(((all_context->hited_para.after_n_packets > 0) && a_stream->type==STREAM_TYPE_TCP) ||
				((all_context->hited_para.after_n_packets > 0) && a_stream->type==STREAM_TYPE_UDP)
				|| stream_state==OP_STATE_CLOSE)
			{			
				all_context->hited_para.after_n_packets--;
				break;
			}
			priority_label=(struct policy_priority_label *)tsg_get_xxx_from_bridge(a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id);
			//ret=tsg_pull_policy_result((struct streaminfo *)a_stream,PULL_FW_RESULT, &security_result[0], 1, &tmp_identify_info);
			if(priority_label==NULL || priority_label->security_result[0].action!=TSG_ACTION_DENY)
			{
				break;
			}

			if(all_context->hited_para.hited_app_id<=0)
			{
				state=tsg_deal_deny_action(a_stream, &priority_label->security_result[0], all_context->protocol, ACTION_RETURN_TYPE_TCPALL, a_packet);
			}
			else
			{
				state=tsg_deny_application(a_stream, &priority_label->security_result[0], all_context->protocol, all_context->hited_para.hited_app_id, ACTION_RETURN_TYPE_TCPALL, a_packet);
			}
			break;
		default:
			break;
	}

	return state;
}

extern "C" unsigned char TSG_MASTER_TCP_ENTRY(const struct streaminfo *a_tcp, void **pme, int thread_seq,void *a_packet)
{
	return tsg_master_data_entry(a_tcp, pme, thread_seq, a_packet);
}

extern "C" unsigned char TSG_MASTER_UDP_ENTRY(const struct streaminfo *a_udp, void **pme, int thread_seq,void *a_packet)
{
	unsigned char state1=APP_STATE_GIVEME;
	unsigned char state2=APP_STATE_GIVEME;
	struct udp_context *context=(struct udp_context *)(*pme);

	if(*pme==NULL)
	{
		unsigned short tunnel_type=0;
		int tunnel_type_len=sizeof(tunnel_type);
		int ret=MESA_get_stream_opt(a_udp, MSO_STREAM_UP_LAYER_TUNNEL_TYPE, (void *)&tunnel_type, &tunnel_type_len);
		if(ret==0 && tunnel_type&STREAM_TUNNEL_GPRS_TUNNEL)
		{
			return APP_STATE_DROPME;
		}
		
		*pme=dictator_malloc(thread_seq, sizeof(struct udp_context));
		memset(*pme, 0, sizeof(struct udp_context));
		context=(struct udp_context *)(*pme);
		
		context->all_entry=(struct tcpall_context *)dictator_malloc(thread_seq, sizeof(struct tcpall_context));
		memset(context->all_entry, 0, sizeof(struct tcpall_context));
		tsg_set_xxx_to_bridge(a_udp, g_tsg_para.bridge[BRIDGE_TYPE_ALL_CONTEXT].id, (void *)(context->all_entry));

		context->all_entry->direction=get_direction(a_udp);
	}

	if(context->all_entry->udp_data_dropme==0)
	{
		state2=tsg_master_data_entry(a_udp, (void **)&(context->data_entry), thread_seq, a_packet);	
	}
	
	if(!(state2&APP_STATE_DROPME) || context->all_entry->hited_para.after_n_packets>0)
	{
		if(state2&APP_STATE_DROPME)
		{
			context->all_entry->udp_data_dropme=1;
			state2=state2&(~(APP_STATE_DROPME));
		}
		
		state1=tsg_master_all_entry(a_udp, a_udp->opstate, (void **)&(context->all_entry), thread_seq, a_packet);
	}

	if(state1&APP_STATE_DROPME || state2&APP_STATE_DROPME || a_udp->opstate==OP_STATE_CLOSE)
	{
		dictator_free(thread_seq, *pme);
		*pme=NULL;
	}

	return (state1|state2);
}

extern "C" unsigned char TSG_MASTER_TCPALL_ENTRY(const struct streaminfo *a_tcp, void **pme, int thread_seq, const void *a_packet)
{
	struct tcpall_context *_context=(struct tcpall_context *)(*pme);

	if(*pme==NULL)
	{		
		*pme=(void *)tsg_get_xxx_from_bridge(a_tcp, g_tsg_para.bridge[BRIDGE_TYPE_ALL_CONTEXT].id);
		if(*pme==NULL)
		{
			*pme=(struct tcpall_context *)dictator_malloc(thread_seq, sizeof(struct tcpall_context));
			memset(*pme, 0, sizeof(struct tcpall_context));	
			tsg_set_xxx_to_bridge(a_tcp, g_tsg_para.bridge[BRIDGE_TYPE_ALL_CONTEXT].id, (void *)(*pme));
		}

		_context=(struct tcpall_context *)(*pme);
		_context->direction=get_direction(a_tcp);
	}
	
	if(_context->set_latency_flag==0)
	{
		_context->set_latency_flag=set_tcp_establish_latency_ms(a_tcp, thread_seq, a_packet);
	}
	
	return tsg_master_all_entry(a_tcp, a_tcp->pktstate, pme, thread_seq, a_packet);
}

extern "C" int TSG_MASTER_INIT()
{
	int ret=0;
	char label_buff[128]={0};
	char device_sn_filename[128]={0};
	char identify_proto_name[256]={0};
	
	memset(&g_tsg_para, 0, sizeof(g_tsg_para));
	
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM","LOG_LEVEL", &g_tsg_para.level, RLOG_LV_FATAL);
	MESA_load_profile_string_def(tsg_conffile, "SYSTEM","LOG_PATH", g_tsg_para.log_path, sizeof(g_tsg_para.log_path), "log/tsg_master");

	g_tsg_para.logger=MESA_create_runtime_log_handle(g_tsg_para.log_path, g_tsg_para.level);
	if(g_tsg_para.logger==NULL)
	{
		printf("MESA_create_runtime_log_handle failed ...\n");
		return -1;
	}

	srand(time(0));
	get_deploy_mode();

	MESA_load_profile_int_def(tsg_conffile, "RESET", "NUM", &g_tsg_para.reset.pkt_num, 1);
	MESA_load_profile_int_def(tsg_conffile, "RESET", "SEED1", &g_tsg_para.reset.seed1, 65535);
	MESA_load_profile_int_def(tsg_conffile, "RESET", "SEED2", &g_tsg_para.reset.seed2, 13);
	MESA_load_profile_int_def(tsg_conffile, "RESET", "FLAGS", &g_tsg_para.reset.th_flags, 0x14);
	MESA_load_profile_int_def(tsg_conffile, "RESET", "DIR", &g_tsg_para.reset.dir, DIR_DOUBLE);
	MESA_load_profile_int_def(tsg_conffile, "RESET", "REMEDY", &g_tsg_para.reset.remedy, 1);

	MESA_load_profile_int_def(tsg_conffile, "SYSTEM","DEFAULT_POLICY_ID", &g_tsg_para.default_compile_id, 0);
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM","HIT_PATH_SWITCH", &g_tsg_para.hit_path_switch, 0);
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM","UNKNOWN_APP_ID", &g_tsg_para.unknown_app_id, 4);

	g_tsg_para.default_vlan.num=1;
	MESA_load_profile_int_def(tsg_conffile, "TRAFFIC_MIRROR","DEFAULT_VLAN_ID", &(g_tsg_para.default_vlan.id[0]), 2);

	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "IDENTIFY_PROTO_NAME", identify_proto_name, sizeof(identify_proto_name), "HTTP;SSL;DNS;FTP;BGP;MAIL;STREAMING_MEDIA;QUIC;SIP;SSH;Stratum;RDP;DTLS;");
	tsg_proto_name2flag(identify_proto_name, &g_tsg_para.proto_flag);

	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "DATACENTER_ID", &g_tsg_para.datacenter_id, 0);
	MESA_load_profile_short_def(tsg_conffile, "SYSTEM", "TIMEOUT", (short *)&g_tsg_para.timeout, 300);
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "SCAN_TIME_INTERVAL", &g_tsg_para.scan_time_interval, 120);
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "IENTIFY_APP_MAX_PKT_NUM", &g_tsg_para.identify_app_max_pkt_num, 20);
	
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "FEATURE_TAMPER", &g_tsg_para.feature_tamper, 0);

	ret=MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "DEVICE_SEQ_IN_DATA_CENTER", &g_tsg_para.device_seq_in_dc, 0);
	if(ret<0)
	{
		MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "DEVICE_ID_COMMAND", g_tsg_para.device_id_command, sizeof(g_tsg_para.device_id_command), NULL);
		g_tsg_para.device_seq_in_dc=get_device_id(g_tsg_para.device_id_command, g_tsg_para.datacenter_id);
	}
	else
	{
		g_tsg_para.device_seq_in_dc=(g_tsg_para.datacenter_id<<7)+((g_tsg_para.device_seq_in_dc)%128);
	}
	
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

	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "TSG_MASTER_INTERNAL_LABEL", label_buff, sizeof(label_buff), "TSG_MASTER_INTERNAL_LABEL");
	g_tsg_para.session_attribute_project_id=project_producer_register(label_buff, PROJECT_VAL_TYPE_STRUCT, free_session_attribute_label);
	if(g_tsg_para.session_attribute_project_id<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "PROJECT_REGISTER", "Register %s failed.", label_buff);
	}

	ret=tsg_init_bridge(tsg_conffile);
	if(ret<0)
	{
		return -1;
	}

	init_page_template(tsg_conffile);
	init_fs2_handle(tsg_conffile);

	ret=tsg_rule_init(tsg_conffile, g_tsg_para.logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "INIT_MAAT", "tsg_rule_init failed ...");
		return -1;
	}
	
	g_tsg_log_instance=tsg_sendlog_init(tsg_conffile, g_tsg_para.fs2_handle);
	if(g_tsg_log_instance==NULL)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "INIT_SENDLOG", "tsg_sendlog_init failed ...");
		return -1;
	}
	g_tsg_log_instance->session_attribute_project_id=g_tsg_para.session_attribute_project_id;
	
	FS_start(g_tsg_para.fs2_handle);

	ret=tsg_statistic_init(tsg_conffile, g_tsg_para.logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "INIT_STATISTIC", "tsg_statistic_init failed ...");
		return -1;
	}

	l7_protocol_mapper(tsg_conffile);

	ret=tsg_gtp_signaling_hash_init(tsg_conffile, g_tsg_para.logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "INIT_GTP_HASH", "tsg_gtp_signaling_hash_init failed ...");
		return -1;
	}
		
	return 0;
}

extern "C" int TSG_MASTER_UNLOAD()
{
	tsg_sendlog_destroy(g_tsg_log_instance);
	tsg_statistic_destroy();

	Maat_burn_feather(g_tsg_maat_feather);
	g_tsg_maat_feather=NULL;

	if(g_tsg_para.dynamic_maat_switch==1)
	{
		Maat_burn_feather(g_tsg_dynamic_maat_feather);
		g_tsg_dynamic_maat_feather=NULL;
	}

	FS_stop(&(g_tsg_para.fs2_handle));

	MESA_destroy_runtime_log_handle(g_tsg_para.logger);
	g_tsg_para.logger=NULL;

	return 0;
}
