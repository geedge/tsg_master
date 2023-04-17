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
#include <MESA/maat.h>
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
#include "tsg_rule_internal.h"
#include "tsg_protocol_common.h"
#include "tsg_sync_state.h"

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

struct id2field g_tsg_fs2_field[TSG_FS2_MAX]={{0, TSG_FS2_TCP_LINKS, "tcp_links"},
										 {0, TSG_FS2_UDP_LINKS, "udp_links"}, 
										 {0, TSG_FS2_BYPASS, "bypass"},
										 {0, TSG_FS2_HIT_ADDR, "hit_addr"},
										 {0, TSG_FS2_HIT_SHARE, "hit_share"},
										 {0, TSG_FS2_INTERCEPT, "intercept"},
										 {0, TSG_FS2_SHAPING, "shaping"},
										 {0, TSG_FS2_S_CHAINING, "s_chaining"},
										 {0, TSG_FS2_CTRL_OPENING, "ctrl_open"},
										 {0, TSG_FS2_CTRL_CLOSING, "ctrl_close"},
										 {0, TSG_FS2_CTRL_ACTIVE, "ctrl_active"},
										 {0, TSG_FS2_CTRL_RESETALL, "ctrl_rstall"},
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
	*pme=dictator_malloc(thread_seq, sizeof(struct session_runtime_process_context));
	memset(*pme, 0, sizeof(struct session_runtime_process_context));
	
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

static int is_only_monitor(struct maat_rule *result, int hit_cnt)
{
	int i=0;

	for(i=0; i<hit_cnt; i++)
	{
		//if(result[i].action==TSG_ACTION_BYPASS || result[i].action==TSG_ACTION_INTERCEPT || result[i].action==TSG_ACTION_DENY)
		if(result[i].action>TSG_ACTION_MONITOR)
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

static int is_deny_application(struct maat_rule *p_result)
{
	struct maat_compile *maat_compile=(struct maat_compile *)matched_rule_cites_security_compile(g_tsg_maat_feather, p_result->rule_id);
	if(maat_compile==NULL || maat_compile->user_region==NULL)
	{
		return 0;
	}

	if(maat_compile->user_region->method_type==TSG_METHOD_TYPE_APP_DROP)
	{
		plugin_ex_data_security_compile_free(maat_compile);
		return 1;
	}
	
	return 0;
}

static int is_deny_after_N_packets(struct maat_rule *p_result)
{
	struct maat_compile *maat_compile=(struct maat_compile *)matched_rule_cites_security_compile(g_tsg_maat_feather, p_result->rule_id);
	if(maat_compile==NULL || maat_compile->user_region==NULL)
	{
		return 0;
	}

	if(maat_compile->user_region->method_type!=TSG_METHOD_TYPE_APP_DROP && maat_compile->user_region->method_type!=TSG_METHOD_TYPE_DROP)
	{
		return 0;
	}

	if(maat_compile->user_region->deny!=NULL && maat_compile->user_region->deny->after_n_packets>0)
	{
		plugin_ex_data_security_compile_free(maat_compile);
		return 1;
	}

	return 0;
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

static int get_default_para(const struct streaminfo *a_stream)
{
	int after_n_packets=0;
	long long compile_id=tsg_default_compile_id_get();
	struct maat_compile *maat_compile=(struct maat_compile *)matched_rule_cites_security_compile(g_tsg_maat_feather, compile_id);
	if(maat_compile!=NULL && maat_compile->user_region!=NULL && maat_compile->user_region->method_type==TSG_METHOD_TYPE_DEFAULT)
	{
		if(maat_compile->user_region->session_para!=NULL && maat_compile->user_region->session_para->result.action==TSG_ACTION_DENY)
		{
			switch(a_stream->type)
			{
				case	STREAM_TYPE_TCP:
					after_n_packets=maat_compile->user_region->session_para->tcp.after_n_packets;
					break;
				case	STREAM_TYPE_UDP:
					after_n_packets=maat_compile->user_region->session_para->udp.after_n_packets;
					break;
				default:
					break;
			}
		}
		
		plugin_ex_data_security_compile_free(maat_compile);
	}

	return after_n_packets;
}

static int get_default_policy(struct maat_rule *result)
{
	long long compile_id=tsg_default_compile_id_get();
	struct maat_compile *maat_compile=(struct maat_compile *)matched_rule_cites_security_compile(g_tsg_maat_feather, compile_id);
	if(maat_compile!=NULL && maat_compile->user_region!=NULL)
	{
		if(maat_compile->user_region->method_type==TSG_METHOD_TYPE_DEFAULT)
		{
			if(maat_compile->user_region->session_para!=NULL && maat_compile->user_region->session_para->result.action==TSG_ACTION_DENY)
			{
				memcpy(result, &(maat_compile->user_region->session_para->result), sizeof(struct maat_rule));
			}
			
			plugin_ex_data_security_compile_free(maat_compile);
			return 1;
		}
		
		plugin_ex_data_security_compile_free(maat_compile);
	}

	return 0;
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

static int protocol_name2flag(char *proto_list, int *flag)
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

int device_id_set_telegraf(char *device_sn)
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

int app_gather_results_update(struct gather_app_result *gather_result, struct app_identify_result *identify_result, int packet_sequence)
{
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

static int l7_protocol_mapper_init(const char *conffile)
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

static int srt_process_context_set_l7_protocol(struct session_runtime_process_context *srt_process_context, unsigned int app_id)
{
	const char *l7_protocol_name=tsg_l7_protocol_id2name(app_id);
	if(l7_protocol_name!=NULL)
	{
		for(int i=PROTO_HTTP; i<PROTO_MAX; i++)
		{
			if((strcasecmp(g_tsg_proto_name2id[i].name, l7_protocol_name))==0)
			{
				srt_process_context->proto=(enum TSG_PROTOCOL)g_tsg_proto_name2id[i].type;
				return 1;
			}
		}
	}
	
	srt_process_context->proto=PROTO_APP;

	return 0;
}

static int session_app_gather_results_set_l7_protocol(const struct streaminfo *a_stream, enum TSG_PROTOCOL protocol)
{
	struct gather_app_result *gather_result=(struct gather_app_result *)session_gather_app_results_get(a_stream);
	if(gather_result!=NULL)
	{
		return 0;
	}
	
	gather_result=(struct gather_app_result *)dictator_malloc(a_stream->threadnum, sizeof(struct gather_app_result)*ORIGIN_MAX);
	memset(gather_result, 0, sizeof(struct gather_app_result)*ORIGIN_MAX);
	session_gather_app_results_async(a_stream, (void *)gather_result);
	
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

int session_app_gather_results_update_matched_app_id(const struct streaminfo *a_stream, unsigned int hited_app_id)
{
	struct gather_app_result *gather_result=(struct gather_app_result *)session_gather_app_results_get(a_stream);
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

int session_state_sync_in_opening_and_closing(const struct streaminfo *a_stream, unsigned char state)
{
	struct segment_id_list sid_list={0};

	if(g_tsg_para.service_chaining_sid>0)
	{
		sid_list.sid_list[sid_list.sz_sidlist++]=(unsigned short)g_tsg_para.service_chaining_sid;
	}

	if(g_tsg_para.shaping_sid>0)
	{
		sid_list.sid_list[sid_list.sz_sidlist++]=(unsigned short)g_tsg_para.shaping_sid;
	}

	if(sid_list.sz_sidlist==0)
	{
		return 0;
	}

	unsigned long long trace_id=tsg_get_stream_trace_id((struct streaminfo *)a_stream);
	MESA_set_stream_opt(a_stream, MSO_STREAM_SET_DATAMETA_TRACE_ID, (void *)&trace_id, sizeof(unsigned long long));

	MESA_set_stream_opt(a_stream, MSO_STREAM_PREPLEND_SEGMENT_ID_LIST, (void *)&sid_list, sizeof(struct segment_id_list));

	if(g_tsg_para.send_resetall==0)
	{
		if(atomic_inc(&g_tsg_para.send_resetall)==1)
		{
			tsg_sync_resetall_state(a_stream);
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_CTRL_RESETALL], 0, FS_OP_ADD, 1);
		}
	}

	switch(state)
	{
		case	OP_STATE_PENDING:
			tsg_sync_opening_state(a_stream, state);
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_CTRL_OPENING], 0, FS_OP_ADD, 1);
			break;
		case	OP_STATE_CLOSE:
			tsg_sync_closing_state(a_stream, state);
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_CTRL_CLOSING], 0, FS_OP_ADD, 1);
			break;
		default:
			break;
	}

	sid_list.sz_sidlist=0;
	MESA_set_stream_opt(a_stream, MSO_STREAM_PREPLEND_SEGMENT_ID_LIST, (void *)&sid_list, sizeof(struct segment_id_list));

	return 1;
}

size_t matched_rules_increase_in_avtiving(const struct matched_policy_rules *matched_rules, struct maat_rule *new_rules, size_t n_new_rules, struct maat_rule *inc_rules, size_t n_inc_rules)
{
	size_t n_inc_rules_offset=0;
	size_t num=MIN(MAX_RESULT_NUM-matched_rules->n_rules, n_new_rules);
	for(size_t i=0; i<num; i++)
	{
		int repeat_rule=0;
		for(size_t j=0; j<matched_rules->n_rules+n_inc_rules_offset; j++)
		{
			if((new_rules[i].rule_id==matched_rules->rules[j].rule_id) || (new_rules[i].rule_id==inc_rules[j].rule_id))
			{
				repeat_rule=1;
				break;
			}
		}

		if(repeat_rule==0 && n_inc_rules>n_inc_rules_offset)
		{
			memcpy(&(inc_rules[n_inc_rules_offset++]), &(new_rules[i]), sizeof(struct maat_rule));
		}
	}

	return n_inc_rules_offset;
}

int session_set_segment_id_in_activing(const struct streaminfo *a_stream, TSG_SERVICE service, struct maat_rule *inc_rules, size_t n_inc_rules)
{
	unsigned short segment_id=0;
	enum policy_type p_type=POLICY_UPDATE_MAX;
	switch(service)
	{
		case	TSG_SERVICE_CHAINING:
			p_type=POLICY_UPDATE_SERVICE_CHAINING;
			segment_id=(unsigned short)g_tsg_para.service_chaining_sid;
			break;
		case	TSG_SERVICE_SHAPING:
			p_type=POLICY_UPDATE_SHAPING;
			segment_id=(unsigned short)g_tsg_para.shaping_sid;
			break;
		default:
			return 0;
	}

	if(segment_id==0)
	{
		return 0;
	}

	MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_INFO, "set_segment_id", "set in active status , service:%d, sid:%u,session addr:%s", service, segment_id, PRINTADDR(a_stream, g_tsg_para.level));

	struct segment_id_list *segment_ids=(struct segment_id_list *)session_control_segment_ids_get(a_stream);
	if(segment_ids==NULL)
	{
		segment_ids=(struct segment_id_list *)dictator_malloc(a_stream->threadnum, sizeof(struct segment_id_list));
		memset(segment_ids, 0, sizeof(struct segment_id_list));
	}

	int add_sid=1;
	for(size_t i=0; i<segment_ids->sz_sidlist; i++)
	{
		if(segment_ids->sid_list[i]==segment_id)
		{
			add_sid=0;
			break;
		}
	}

	if(add_sid==1)
	{
		segment_ids->sid_list[segment_ids->sz_sidlist++]=segment_id;
	}
	
	struct segment_id_list sid_list;
	sid_list.sz_sidlist=1;
	sid_list.sid_list[0]=segment_id;
	MESA_set_stream_opt(a_stream, MSO_STREAM_PREPLEND_SEGMENT_ID_LIST, (void *)&sid_list, sizeof(struct segment_id_list));

	struct update_policy policy_array;
	policy_array.n_ids=n_inc_rules;
	policy_array.type=p_type;
	
	for(size_t i=0; i<n_inc_rules; i++)
	{
		policy_array.ids[i]=inc_rules[i].rule_id;
	}

	tsg_sync_policy_update(a_stream, &policy_array, 1);

	MESA_set_stream_opt(a_stream, MSO_STREAM_PREPLEND_SEGMENT_ID_LIST, (void *)segment_ids, sizeof(struct segment_id_list));

	session_control_segment_ids_async(a_stream, segment_ids);
	return 1;
}

int session_state_sync_in_activing(const struct streaminfo *a_stream, TSG_SERVICE service, struct maat_rule *rules, size_t n_rules, int thread_seq)
{
	if(rules==NULL || n_rules==0)
	{
		return 0;
	}

	struct matched_policy_rules *matched_rules=(struct matched_policy_rules *)session_matched_rules_get(a_stream, service);
	if(matched_rules==NULL)
	{
		matched_rules=(struct matched_policy_rules *)dictator_malloc(thread_seq, sizeof(struct matched_policy_rules));
		memset((void *)matched_rules, 0, sizeof(struct matched_policy_rules));
	}

	struct maat_rule inc_rules[MAX_RESULT_NUM]={0};
	size_t n_inc_results=matched_rules_increase_in_avtiving(matched_rules, rules, n_rules, inc_rules, MAX_RESULT_NUM-matched_rules->n_rules);
	if(n_inc_results==0)
	{
		return 0;
	}
	
	int ret=session_set_segment_id_in_activing(a_stream, service, inc_rules, n_inc_results);
	if(ret==0)
	{
		return 0;
	}
	
	//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_CTRL_ACTIVE], 0, FS_OP_ADD, 1);

	memcpy(matched_rules->rules+matched_rules->n_rules, inc_rules, n_inc_results*sizeof(struct maat_rule));
	matched_rules->n_rules+=n_inc_results;
	ret=session_matched_rules_async(a_stream, service, (void *)matched_rules);
	if(ret<0)
	{
		session_matched_rules_free(a_stream, service, (void *)matched_rules);
		return 0;
	}

	return 1;
}

static int session_runtime_process_log_send(const struct streaminfo *a_stream, struct maat_rule *rules, int n_rules, struct session_runtime_process_context *srt_process_context, int thread_seq)
{
	char *domain_field_name=NULL;
	char *schema_field_name=NULL;
	char *quic_ua_field_name=NULL;
	char *quic_version_field_name=NULL;
	struct TLD_handle_t *TLD_handle=NULL;
	enum TSG_PROTOCOL proto=PROTO_UNKONWN;
	struct tsg_conn_sketch_notify_data *notify=NULL;
	if(srt_process_context!=NULL)
	{
		proto=srt_process_context->proto;
	}

	if(rules[0].action==TSG_ACTION_MONITOR)
	{
		switch(proto)
		{
			case	PROTO_SSH:
			case	PROTO_RDP:
			case	PROTO_STRATUM:
					notify=(struct tsg_conn_sketch_notify_data *)session_conn_sketch_notify_data_get(a_stream);
					if (notify != NULL && notify->pdata.TLD_handle!=NULL && (notify->protocol== PROTO_SSH || notify->protocol== PROTO_STRATUM  || notify->protocol== PROTO_RDP))
					{
						TLD_handle = TLD_duplicate(notify->pdata.TLD_handle);
						if (TLD_handle!=NULL)
						{
							tsg_send_log(g_tsg_log_instance, TLD_handle, a_stream, LOG_TYPE_SECURITY_EVENT, rules, n_rules, thread_seq);
							tsg_set_policy_flow(a_stream, rules, thread_seq);
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

		if(srt_process_context!=NULL && srt_process_context->domain!=NULL)
		{
			switch(proto)
			{
				case	PROTO_HTTP:
					domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_HTTP_HOST);
					TLD_append(TLD_handle, domain_field_name, (void *)srt_process_context->domain, TLD_TYPE_STRING);

					if(srt_process_context->http_url!=NULL)
					{
						domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_HTTP_URL);
						TLD_append(TLD_handle, domain_field_name, (void *)srt_process_context->http_url, TLD_TYPE_STRING);
					}
					break;
				case	PROTO_SSL:
					domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_SSL_SNI);
					TLD_append(TLD_handle, domain_field_name, (void *)srt_process_context->domain, TLD_TYPE_STRING);
					break;
				case	PROTO_QUIC:
					domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_QUIC_SNI);
					TLD_append(TLD_handle, domain_field_name, (void *)srt_process_context->domain, TLD_TYPE_STRING);
					break;
				case	PROTO_DTLS:
					domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_DTLS_SNI);
					TLD_append(TLD_handle, domain_field_name, (void *)srt_process_context->domain, TLD_TYPE_STRING);
					break;
				default:
					break;
			}
		}
		
		if(srt_process_context!=NULL && srt_process_context->quic_version>0)
		{
			char quic_version[64]={0};
			if(quic_version_int2string(srt_process_context->quic_version, quic_version, sizeof(quic_version)))
			{
				quic_version_field_name=log_field_id2name(g_tsg_log_instance, LOG_QUIC_VERSION);
				TLD_append(TLD_handle, quic_version_field_name, (void *)quic_version, TLD_TYPE_STRING);
			}

			if(srt_process_context->quic_ua!=NULL)
			{
				quic_ua_field_name=log_field_id2name(g_tsg_log_instance, LOG_QUIC_USER_AGENT);
				TLD_append(TLD_handle, quic_ua_field_name, (void *)srt_process_context->quic_ua, TLD_TYPE_STRING);
			}
		}
	}
	else
	{
		TLD_append(TLD_handle, schema_field_name, (void *)g_tsg_proto_name2id[PROTO_APP].name, TLD_TYPE_STRING);
	}	

	if(srt_process_context!=NULL && srt_process_context->hited_app_id>0)
	{		
		session_app_gather_results_update_matched_app_id(a_stream, srt_process_context->hited_app_id);
	}
	
	tsg_send_log(g_tsg_log_instance, TLD_handle, a_stream, LOG_TYPE_SECURITY_EVENT, rules, n_rules, thread_seq);
	
	if(rules->rule_id!=DECCRYPTION_EXCLUSION_ALLOW_POLICY_ID)
	{
		tsg_set_policy_flow(a_stream, rules, thread_seq);
	}
	
	return 1;
}

static char session_tcp_establish_latency_ms_set(const struct streaminfo *a_tcp, int thread_seq,const void *ip_hdr)
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
		srt_attribute_set_establish_latecy(a_tcp);
		return 1;
	}

	return 0;
}

struct maat_rule *matched_rules_decision_criteria(struct maat_rule *rules, size_t n_rules)
{
	struct maat_rule *p_result=NULL;

	for(size_t i=0; i<n_rules; i++)
	{
		if(p_result==NULL)
		{
			p_result=&rules[i];
			continue;
		}
		
		if((unsigned char)rules[i].action>(unsigned char)p_result->action)
		{
			p_result=&rules[i];
			continue;
		}
		
		if(rules[i].action==p_result->action)
		{
			if(rules[i].rule_id>p_result->rule_id)
			{
				p_result=&rules[i];
			}
		}	
	}

	return p_result;
}

static int session_l7_protocol_idnetify(const struct streaminfo *a_stream, struct session_runtime_process_context *srt_process_context, void *a_packet)
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
					srt_process_context->proto=PROTO_HTTP;
					
					int length=http_get_filed_result(parser_result, HTTP_HOST, &host);
					srt_process_context->http_host=malloc_copy_string(host, length, a_stream->threadnum);
					length=http_get_filed_result(parser_result, HTTP_MESSAGE_URL, &url);
					srt_process_context->http_url=malloc_copy_string(url, length, a_stream->threadnum);

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
					srt_process_context->proto=PROTO_SSL;
					if(chello->sni!=NULL)
					{
						srt_process_context->ssl_sni=malloc_copy_string(chello->sni, strlen(chello->sni), a_stream->threadnum);
					}

					srt_process_context->is_esni=(int)chello->is_encrypt_sni;
					
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
					srt_process_context->proto=PROTO_FTP;
					return 1;
				}

				ret=ftp_data_identify((struct streaminfo *)a_stream);
				if(ret>0)
				{
					srt_process_context->proto=PROTO_FTP;
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
							srt_process_context->proto=PROTO_SMTP;
							return 1;
							break;
						case	POP3_PROTOCOL:
							srt_process_context->proto=PROTO_POP3;
							return 1;
							break;
						case	IMAP_PROTOCOL:
							srt_process_context->proto=PROTO_IMAP;
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
					srt_process_context->proto=PROTO_SSH;
					return 1;
				}
			}

			if(g_tsg_para.proto_flag&(1<<PROTO_STRATUM))  //Stratum
			{
				ret=stratum_identify((struct streaminfo *)a_stream, NULL, a_stream->threadnum, a_packet);
				if(ret==IS_STRATUM)
				{
					srt_process_context->proto=PROTO_STRATUM;
					return 1;
				}
			}

			if(g_tsg_para.proto_flag&(1<<PROTO_RDP))  //RDP
			{
				ret=rdp_protocol_identify((const char *)a_stream->ptcpdetail->pdata, a_stream->ptcpdetail->datalen, (unsigned int)a_stream->threadnum);
				if(ret==1)
				{
					srt_process_context->proto=PROTO_RDP;
					return 1;
				}
			}

			break;
		case	STREAM_TYPE_UDP:
			if(g_tsg_para.proto_flag&(1<<PROTO_DNS))  //dns
			{
				if(is_dns_protocol(a_stream))
				{
					srt_process_context->proto=PROTO_DNS;
					return 1;
				}
			}
			
			if(g_tsg_para.proto_flag&(1<<PROTO_QUIC))  //quic
			{
				char ua_buff[512]={0};
				char sni_buff[512]={0};
				int sni_len=sizeof(sni_buff),ua_len=sizeof(ua_buff);
				srt_process_context->quic_version=quic_protocol_identify((struct streaminfo *)a_stream, a_packet, sni_buff, &sni_len, ua_buff, &ua_len);
				if(srt_process_context->quic_version > 0)
				{
					srt_process_context->proto=PROTO_QUIC;
					srt_process_context->quic_sni=malloc_copy_string(sni_buff, sni_len, a_stream->threadnum);
					srt_process_context->quic_ua=malloc_copy_string(ua_buff, ua_len, a_stream->threadnum);
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
					srt_process_context->proto=PROTO_SIP;
					return 1;
				}				
			}

			if(g_tsg_para.proto_flag&(1<<PROTO_RDP))  //RDP
			{
				ret=rdpudp_protocol_identify((const char *)a_stream->pudpdetail->pdata, a_stream->pudpdetail->datalen, (unsigned int)a_stream->threadnum);
				if(ret==1)
				{
					srt_process_context->proto=PROTO_RDP;
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
					srt_process_context->proto = PROTO_DTLS;
					ret = dtls_parse_sni((const char *)a_stream->pudpdetail->pdata, a_stream->pudpdetail->datalen, sni_buff, sni_len);
					if (ret == 0 && strlen(sni_buff) > 0)
					{
						srt_process_context->dtls_sni = malloc_copy_string(sni_buff, sni_len, a_stream->threadnum);
						return 1;
					}
				}
			}
			break;
		default:
			break;
	}

	if(srt_process_context->proto<PROTO_HTTP || srt_process_context->proto>PROTO_MAX)
	{
		srt_process_context->proto = PROTO_UNKONWN;
	}
	
	return ret;
}


static size_t tsg_scan_fqdn_category_id(const struct streaminfo *a_stream, struct maat *feather, char *domain, int table_idx, struct maat_state *s_mid, maat_rule *results, size_t n_result)
{
	struct session_runtime_attribute *srt_attribute=(struct session_runtime_attribute *)session_runtime_attribute_get(a_stream);
	if(srt_attribute!=NULL && domain!=NULL && table_idx>=0)
	{
		srt_attribute->n_fqdn_category_ids=tsg_get_fqdn_category_ids(g_tsg_maat_feather, domain, srt_attribute->fqdn_category_ids, MAX_CATEGORY_ID_NUM);
		return tsg_scan_fqdn_category_id(a_stream, g_tsg_maat_feather, srt_attribute->fqdn_category_ids, srt_attribute->n_fqdn_category_ids, table_idx, s_mid, results, n_result);
	}

	return 0;
}

size_t session_app_id_and_properties_scan(const struct streaminfo *a_stream, struct maat_rule *results, size_t n_results, struct session_runtime_process_context *srt_process_context, struct gather_app_result *identify_result, int thread_seq)
{
	size_t hit_num=0;
	int hited_app_id=0;
	int after_n_packets=0;
	struct maat_rule *p_result, *d_result=NULL;

	for(int i=0; i< identify_result->app_num; i++)
	{
		struct app_id_dict *dict=(struct app_id_dict *)matched_rule_cites_app_id_dict(g_tsg_maat_feather, (long long)identify_result->attributes[i].app_id);
		if(dict!=NULL)
		{
			hit_num+=tsg_scan_app_properties_policy(a_stream, g_tsg_maat_feather, dict->risk, (char *)"risk", (srt_process_context->mid), results+hit_num, n_results-hit_num);
			hit_num+=tsg_scan_app_properties_policy(a_stream, g_tsg_maat_feather, dict->category, (char *)"category", (srt_process_context->mid), results+hit_num, n_results-hit_num);
			hit_num+=tsg_scan_app_properties_policy(a_stream, g_tsg_maat_feather, dict->technology, (char *)"technology", (srt_process_context->mid), results+hit_num, n_results-hit_num);
			hit_num+=tsg_scan_app_properties_policy(a_stream, g_tsg_maat_feather, dict->subcategory, (char *)"subcategory", (srt_process_context->mid), results+hit_num, n_results-hit_num);
			hit_num+=tsg_scan_app_properties_policy(a_stream, g_tsg_maat_feather, dict->characteristics, (char *)"characteristics", (srt_process_context->mid), results+hit_num, n_results-hit_num);
		
			hit_num+=tsg_scan_app_id_policy(a_stream, g_tsg_maat_feather, identify_result->attributes[i].app_id, (srt_process_context->mid), results+hit_num, n_results-hit_num);
			after_n_packets=dict->deny_app_para.after_n_packets;
			
			set_app_timeout(a_stream, dict, &(srt_process_context->timeout));

			plugin_ex_data_app_id_dict_free(dict);
		}
		else
		{
			hit_num+=tsg_scan_app_id_policy(a_stream, g_tsg_maat_feather, identify_result->attributes[i].app_id, (srt_process_context->mid), results+hit_num, n_results-hit_num);
		}

		p_result=tsg_select_deny_rule(results, hit_num);
		if(d_result==NULL)
		{
			d_result=p_result;
			hited_app_id=identify_result->attributes[i].app_id;
			continue;
		}
		
		if(d_result->rule_id!=p_result->rule_id)
		{
			d_result=p_result;
			hited_app_id=identify_result->attributes[i].app_id;
		}
	}	

	if(hit_num>0)
	{
		if(identify_result->origin!=ORIGIN_BASIC_PROTOCOL)
		{
			srt_process_context->hited_app_id=hited_app_id;
		}
		
		srt_process_context->hited_para.hited_app_id=hited_app_id;
		srt_process_context->hited_para.after_n_packets=after_n_packets;
	}
	else
	{
		if(identify_result->origin==ORIGIN_BASIC_PROTOCOL && after_n_packets>0) //for enum TSG_PROTOCOL
		{
			srt_process_context->hited_para.after_n_packets=after_n_packets;
		}
	}
		
	return hit_num;
}

static unsigned char matched_security_rules_deal(const struct streaminfo *a_stream, struct session_runtime_process_context *srt_process_context, struct maat_rule *security_rules, size_t n_security_rules, const void *a_packet, int thread_seq)
{
	unsigned char state=APP_STATE_GIVEME;
	struct maat_rule *p_rule=matched_rules_decision_criteria(security_rules, n_security_rules);
	if(p_rule->action==TSG_ACTION_SHUNT)
	{
		srt_action_context_set_rule_method(a_stream, TSG_METHOD_TYPE_SHUNT, a_stream->threadnum);
		return APP_STATE_DROPME|APP_STATE_KILL_OTHER;
	}

	switch(p_rule->action)
	{
		case	TSG_ACTION_DENY:
			if(srt_process_context->proto==PROTO_DNS)	/* deal action of deny in firewall */
			{
				break;
			}
			
			if(is_deny_application(p_rule))
			{
				if(srt_process_context->hited_para.hited_app_id==0)
				{
					srt_process_context->hited_para.hited_app_id=tsg_l7_protocol_name2id(g_tsg_proto_name2id[srt_process_context->proto].name);
				}

				srt_action_context_set_hitted_app_id(a_stream, srt_process_context->hited_para.hited_app_id, a_stream->threadnum);
				state=tsg_enforing_deny_application(a_stream, p_rule, srt_process_context->proto, srt_process_context->hited_para.hited_app_id, ACTION_RETURN_TYPE_APP, a_packet);
			}
			else
			{
				state=tsg_enforing_deny(a_stream, p_rule, srt_process_context->proto, ACTION_RETURN_TYPE_APP, a_packet);
			}

			if(is_deny_after_N_packets(p_rule))
			{
				tsg_set_policy_flow(a_stream, p_rule, a_stream->threadnum);
				session_matched_rules_notify(a_stream, TSG_SERVICE_SECURITY, p_rule, 1, a_stream->threadnum);
				if(a_stream->type==STREAM_TYPE_TCP)
				{
					break;
				}
			}

			if(srt_process_context->hited_result==NULL)
			{
				srt_process_context->hited_result=(struct maat_rule *)dictator_malloc(1, sizeof(struct maat_rule));
				memcpy(srt_process_context->hited_result, p_rule, sizeof(struct maat_rule));
			}
			break;
		case	TSG_ACTION_MONITOR:
			if(srt_process_context->proto==PROTO_RTP)
			{
				break;
			}
			session_packet_capture_notify(a_stream, security_rules, n_security_rules, a_stream->threadnum);
			session_matched_rules_notify(a_stream, TSG_SERVICE_SECURITY, security_rules, n_security_rules, a_stream->threadnum);
			break;
		case	TSG_ACTION_BYPASS:
			srt_process_context->is_hited_allow=1;
			srt_process_context->hited_result=(struct maat_rule *)dictator_malloc(1, sizeof(struct maat_rule));
			memcpy(srt_process_context->hited_result, p_rule, sizeof(struct maat_rule));
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_BYPASS], 0, FS_OP_ADD, 1);
			state=APP_STATE_GIVEME|APP_STATE_KILL_FOLLOW;

			srt_action_context_set_rule_method(a_stream, TSG_METHOD_TYPE_ALLOW, a_stream->threadnum);
			break;
		case	TSG_ACTION_INTERCEPT:
			if(tsg_scan_intercept_exclusion(a_stream, g_tsg_maat_feather, p_rule, srt_process_context->domain, a_stream->threadnum))
			{
				FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_EXCLUSION], 0, FS_OP_ADD, 1);
				break;
			}
			
			session_matched_rules_notify(a_stream, TSG_SERVICE_INTERCEPT, p_rule, 1, a_stream->threadnum);
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_INTERCEPT], 0, FS_OP_ADD, 1);
			state=APP_STATE_DROPME|APP_STATE_KILL_OTHER;

			srt_action_context_set_rule_method(a_stream, TSG_METHOD_TYPE_UNKNOWN, a_stream->threadnum);
			break;
		default:
			break;
	}
	
	return state;
}

int matched_shaping_rules_deal(const struct streaminfo *a_stream, struct maat_rule *shaping_results, size_t n_shaping_results, int thread_seq)
{
	session_state_sync_in_activing(a_stream, TSG_SERVICE_SHAPING, shaping_results, n_shaping_results, thread_seq);

	FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_SHAPING], 0, FS_OP_ADD, 1);
	srt_action_context_set_rule_method(a_stream, TSG_METHOD_TYPE_UNKNOWN, thread_seq);

	return 0;
}

int matched_service_chaining_rules_deal(const struct streaminfo *a_stream, struct maat_rule *s_chaining_rules, size_t n_s_chaining_rules, int thread_seq)
{
	session_state_sync_in_activing(a_stream, TSG_SERVICE_CHAINING, s_chaining_rules, n_s_chaining_rules, thread_seq);
	srt_action_context_set_rule_method(a_stream, TSG_METHOD_TYPE_UNKNOWN, thread_seq);

	return 0;
}

unsigned char session_matched_rules_deal(const struct streaminfo *a_stream, struct session_runtime_process_context *srt_process_context, struct maat_rule *rules, size_t n_rules, const void *a_packet)
{
	unsigned char state=APP_STATE_GIVEME;
	struct maat_rule security_rules[MAX_RESULT_NUM]={0};
	size_t n_security_rules=tsg_select_matched_security_rules(rules, n_rules, security_rules, MAX_RESULT_NUM);
	if(n_security_rules>0)
	{
		state=matched_security_rules_deal(a_stream, srt_process_context, security_rules, n_security_rules, a_packet, a_stream->threadnum);
	}
	
	struct maat_rule shaping_rules[MAX_RESULT_NUM]={0};
	size_t n_shaping_rules=tsg_select_matched_shaping_rules(rules, n_rules, shaping_rules, MAX_RESULT_NUM);
	if(n_shaping_rules>0 && !(state&APP_STATE_KILL_OTHER))
	{
		matched_shaping_rules_deal(a_stream, shaping_rules, n_shaping_rules, a_stream->threadnum);
	}

	struct maat_rule s_chaining_rules[MAX_RESULT_NUM]={0};
	size_t n_s_chaining_rules=tsg_select_matched_service_chaining_rules(rules, n_rules, s_chaining_rules, MAX_RESULT_NUM);
	if(n_s_chaining_rules>0 && !(state&APP_STATE_KILL_OTHER))
	{
		matched_service_chaining_rules_deal(a_stream, s_chaining_rules, n_s_chaining_rules, a_stream->threadnum);
	}

	return state;
}

int session_app_identify_result_cb(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	if(data==NULL)
	{
		return 0;
	}

	struct session_runtime_process_context *srt_process_context=(struct session_runtime_process_context *)session_runtime_process_context_get(a_stream);
	if(srt_process_context==NULL)
	{
		init_context((void **)(&srt_process_context), a_stream->threadnum);
		session_runtime_process_context_async(a_stream, (void *)srt_process_context);
	}

	struct gather_app_result *gather_result=(struct gather_app_result *)session_gather_app_results_get(a_stream);
	if(gather_result==NULL)
	{
		gather_result=(struct gather_app_result *)dictator_malloc(a_stream->threadnum, sizeof(struct gather_app_result)*ORIGIN_MAX);
		memset(gather_result, 0, sizeof(struct gather_app_result)*ORIGIN_MAX);
		session_gather_app_results_async(a_stream, (void *)gather_result);
	}

	struct app_identify_result *identify_result=(struct app_identify_result *)data;
	switch(identify_result->origin)
	{
			break;
		case	ORIGIN_QM_ENGINE:
			srt_process_context->is_app_link=FLAG_TRUE;
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_APP_Q_RESULT], 0, FS_OP_ADD, 1);
			break;
		case	ORIGIN_USER_DEFINE:
			srt_process_context->is_app_link=FLAG_TRUE;
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_APP_USER_RESULT], 0, FS_OP_ADD, 1);
			break;
		case	ORIGIN_BUILT_IN:
			srt_process_context->is_app_link=FLAG_TRUE;
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_APP_BUILT_IN_RESULT], 0, FS_OP_ADD, 1);
			break;
		case	ORIGIN_BASIC_PROTOCOL:
			srt_process_context->is_app_link=FLAG_TRUE;
			if(srt_process_context->proto==PROTO_UNKONWN || srt_process_context->proto==PROTO_APP)
			{
				srt_process_context_set_l7_protocol(srt_process_context, identify_result->app_id[identify_result->app_id_num-1]);
			}
			break;
		case	ORIGIN_UNKNOWN:
			srt_process_context->is_app_link=FLAG_TRUE;
			break;
		default:
			MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "APP_BRIDGE_CB", "Unknown type: %d addr: %s", identify_result->origin, PRINTADDR(a_stream, g_tsg_para.level));
			return 0;
	}

	app_gather_results_update(&(gather_result[identify_result->origin]), identify_result, get_packet_sequence(a_stream));

	if(srt_process_context->mid==NULL)
	{
		return 0;
	}

	struct maat_rule scan_results[MAX_TSG_ALL_RESULT_NUM]={0};
	srt_process_context->last_scan_time=tsg_get_current_time_ms();
	size_t hit_num=session_app_id_and_properties_scan((struct streaminfo *)a_stream, scan_results, MAX_TSG_ALL_RESULT_NUM, srt_process_context, &(gather_result[identify_result->origin]), a_stream->threadnum);

	srt_process_context->sync_cb_state=session_matched_rules_deal(a_stream, srt_process_context, scan_results, hit_num, NULL);
	return 0;
}

int session_flags_identify_result_cb(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	if(data==NULL)
	{
		return 0;
	}

	struct session_runtime_process_context *srt_process_context=(struct session_runtime_process_context *)session_runtime_process_context_get(a_stream);
	if(srt_process_context==NULL)
	{
		init_context((void **)(&srt_process_context), a_stream->threadnum);
		session_runtime_process_context_async(a_stream, (void *)srt_process_context);
	}

	srt_process_context->session_flag=*(unsigned long *)(data);
	srt_attribute_set_flags(a_stream, srt_process_context->session_flag);

	if(srt_process_context->mid==NULL)
	{
		return 0;
	}
	
	struct maat_rule scan_results[MAX_TSG_ALL_RESULT_NUM]={0};
	size_t hit_num=tsg_scan_session_flags(a_stream, g_tsg_maat_feather, srt_process_context->session_flag, (srt_process_context->mid), scan_results, MAX_TSG_ALL_RESULT_NUM);
	srt_process_context->sync_cb_state=session_matched_rules_deal(a_stream, srt_process_context, scan_results, hit_num, NULL);

	return 0;
}

static size_t session_pending_state_deal(const struct streaminfo *a_stream, struct session_runtime_process_context *srt_process_context, struct maat_rule *results, int n_results, void *a_packet)
{
	size_t hit_num=0;
	int ret=session_l7_protocol_idnetify(a_stream, srt_process_context, a_packet);
	if(ret==1)
	{
		session_app_gather_results_set_l7_protocol(a_stream, srt_process_context->proto);
		srt_process_context->is_app_link=FLAG_TRUE;
		srt_attribute_set_protocol(a_stream, srt_process_context->proto);

		if(srt_process_context->proto==PROTO_SSL)
		{
			struct _ssl_ja3_info_t *ja3_info=ssl_get_ja3_fingerprint((struct streaminfo *)a_stream, (unsigned char *)a_stream->ptcpdetail->pdata, (unsigned int)a_stream->ptcpdetail->datalen, a_stream->threadnum);
			if(ja3_info!=NULL)
			{
				if(ja3_info->fp!=NULL && ja3_info->fp_len>0)
				{
					char *ja3_fingerprint=(char *)dictator_malloc(a_stream->threadnum, ja3_info->fp_len+1);
					memset(ja3_fingerprint, 0, ja3_info->fp_len+1);
					memcpy(ja3_fingerprint, ja3_info->fp, ja3_info->fp_len);
					srt_attribute_set_ja3_fingprint(a_stream, ja3_fingerprint);
				}
			}
		}
		
		int table_idx=tsg_table_idx_get_by_protocol(srt_process_context->proto);
		hit_num+=tsg_scan_shared_policy(a_stream, g_tsg_maat_feather, srt_process_context->domain, table_idx, (srt_process_context->mid), results+hit_num, n_results-hit_num);
		hit_num+=tsg_scan_fqdn_category_id(a_stream, g_tsg_maat_feather, srt_process_context->domain, table_idx, (srt_process_context->mid), results+hit_num, n_results-hit_num);
		if(srt_process_context->is_esni)
		{
			unsigned int protocol_id=tsg_l7_protocol_name2id("ESNI");
			hit_num+=tsg_scan_app_id_policy(a_stream, g_tsg_maat_feather, protocol_id, (srt_process_context->mid), results+hit_num, n_results-hit_num);
		}

		if(srt_process_context->proto==PROTO_HTTP && srt_process_context->http_url!=NULL)
		{
			table_idx=tsg_http_url_table_idx_get();
			hit_num+=tsg_scan_shared_policy(a_stream, g_tsg_maat_feather, srt_process_context->http_url, table_idx, (srt_process_context->mid), results+hit_num, n_results-hit_num);
		}
	}

	ret=tsg_scan_nesting_addr(a_stream, g_tsg_maat_feather, srt_process_context->proto, (srt_process_context->mid), results+hit_num, n_results-hit_num);
	if(ret>0)
	{
		hit_num+=ret;
		FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_HIT_ADDR], 0, FS_OP_ADD, 1);
	}

	struct gather_app_result *gather_result=(struct gather_app_result *)session_gather_app_results_get(a_stream);
	for(int i=0; i<ORIGIN_MAX && gather_result!=NULL; i++)
	{
		if(i==ORIGIN_HITED_APP || i==ORIGIN_QM_ENGINE_L7)
		{
			continue;
		}
		hit_num+=session_app_id_and_properties_scan(a_stream, results+hit_num, n_results-hit_num, srt_process_context, &(gather_result[i]), a_stream->threadnum);
	}
	
	hit_num+=tsg_scan_session_flags(a_stream, g_tsg_maat_feather, srt_process_context->session_flag, (srt_process_context->mid), results+hit_num, n_results-hit_num);
	
	if((is_only_monitor(results, hit_num)) && srt_process_context->proto==PROTO_DNS)	// business deal action of monitor 
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_INFO, "pending_state_deal", "is_only_monitor, clean hit_num to 0, :%s", PRINTADDR(a_stream, g_tsg_para.level));
		hit_num=0;
	}

	return hit_num;
}

static unsigned char tsg_master_data_entry(const struct streaminfo *a_stream, void **pme, int thread_seq,void *a_packet)
{
	int i=0,ret=0;
	size_t hit_num=0;
	unsigned char state=APP_STATE_GIVEME;
	struct maat_rule matched_rules[MAX_TSG_ALL_RESULT_NUM];
	struct gather_app_result *gather_result=NULL;
	struct session_runtime_process_context *srt_process_context=(struct session_runtime_process_context *)*pme;
	struct app_identify_result unknown_result;

	if(*pme==NULL)
	{
		srt_process_context=(struct session_runtime_process_context *)session_runtime_process_context_get(a_stream);
		if(srt_process_context==NULL)
		{
			init_context(pme, thread_seq);
			srt_process_context=(struct session_runtime_process_context *)*pme;
			session_runtime_process_context_async(a_stream, *pme);
		}
		else
		{
			*pme=(void *)srt_process_context;
		}
		srt_process_context->last_scan_time=tsg_get_current_time_ms();

		if(srt_process_context->mid==NULL)
		{
			srt_process_context->mid=maat_state_new(g_tsg_maat_feather, thread_seq);
		}
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
			
			hit_num+=session_pending_state_deal(a_stream, srt_process_context, matched_rules+hit_num, MAX_TSG_ALL_RESULT_NUM-hit_num, a_packet);
			state=session_matched_rules_deal(a_stream, srt_process_context, matched_rules, hit_num, a_packet);
			srt_process_context->deal_pkt_num++;
			break;
		case	OP_STATE_DATA:
			if(srt_process_context->is_app_link==FLAG_FALSE && (srt_process_context->deal_pkt_num++) == (g_tsg_para.identify_app_max_pkt_num+1))
			{
				unknown_result.app_id_num=1;
				unknown_result.surrogate_id[0]=0;
				unknown_result.origin=ORIGIN_UNKNOWN;
				unknown_result.app_id[0]=g_tsg_para.unknown_app_id;
		
				session_app_identify_result_cb(a_stream, 0, (void *)&unknown_result);
			}
		
			if(srt_process_context->is_hited_allow)
			{
				state=APP_STATE_KILL_OTHER|APP_STATE_GIVEME;
				break;
			}

			if(srt_process_context->sync_cb_state&APP_STATE_KILL_OTHER || srt_process_context->sync_cb_state&APP_STATE_DROPPKT)
			{
				//tcpall, udp -> allow, Deny(after drop N packets)
				state=srt_process_context->sync_cb_state|APP_STATE_DROPME;
				break;
			}
			
			if(tsg_get_current_time_ms()-srt_process_context->last_scan_time < (g_tsg_para.scan_time_interval*1000))
			{
				break;
			}

			if(srt_process_context->mid!=NULL)
			{
				maat_state_free(srt_process_context->mid);
				srt_process_context->mid=NULL;
			}
			
			srt_process_context->last_scan_time=tsg_get_current_time_ms();
			ret=tsg_scan_nesting_addr(a_stream, g_tsg_maat_feather, srt_process_context->proto, (srt_process_context->mid), matched_rules+hit_num, MAX_TSG_ALL_RESULT_NUM-hit_num);
			if(ret>0)
			{
				hit_num+=ret;
			}
			
			gather_result=(struct gather_app_result *)session_gather_app_results_get(a_stream);
			for(i=0; i<ORIGIN_MAX && gather_result!=NULL; i++)
			{
				if(i==ORIGIN_HITED_APP || i==ORIGIN_QM_ENGINE_L7)
				{
					continue;
				}
				hit_num+=session_app_id_and_properties_scan(a_stream, matched_rules+hit_num, MAX_TSG_ALL_RESULT_NUM-hit_num, srt_process_context, &(gather_result[i]), thread_seq);
			}

			if(srt_process_context->session_flag>0)
			{
				hit_num+=tsg_scan_session_flags(a_stream, g_tsg_maat_feather, srt_process_context->session_flag, (srt_process_context->mid), matched_rules+hit_num, MAX_TSG_ALL_RESULT_NUM-hit_num);
			}
			
			state=session_matched_rules_deal(a_stream, srt_process_context, matched_rules, hit_num, a_packet);
			break;
		default:
			break;
	}
		
	if((a_stream->opstate==OP_STATE_CLOSE) || (state&APP_STATE_DROPME)==APP_STATE_DROPME)
	{
		if(srt_process_context->hited_result)
		{
			session_runtime_process_log_send(a_stream, srt_process_context->hited_result, 1, srt_process_context, thread_seq);
		}
		*pme=NULL;
	}

	return state;
}

static unsigned char tsg_master_all_entry(const struct streaminfo *a_stream, unsigned char stream_state, void **pme, int thread_seq, const void *a_packet)
{
	int ret=0;
	int eth_rawpkt_len=0;
	struct maat_rule *p_result=NULL;
	unsigned char state=APP_STATE_GIVEME;
	struct maat_rule matched_rules[MAX_TSG_ALL_RESULT_NUM]={0};
	struct maat_rule security_results[MAX_RESULT_NUM]={0};	
	struct maat_rule shaping_results[MAX_RESULT_NUM]={0};
	struct session_runtime_action_context *srt_action_context=(struct session_runtime_action_context *)(*pme);

	if(stream_state==OP_STATE_PENDING && srt_action_context->method_type!=TSG_METHOD_TYPE_SHUNT && !(srt_action_context->udp_data_dropme))
	{
		if(srt_action_context->method_type==TSG_METHOD_TYPE_UNKNOWN)
		{
			srt_action_context->method_type=TSG_METHOD_TYPE_DEFAULT;
			srt_action_context->default_policy_after_n_packets=get_default_para(a_stream);
		}

		
		struct maat_state *scan_mid=maat_state_new(g_tsg_maat_feather, thread_seq);
		int hit_num=tsg_scan_nesting_addr(a_stream, g_tsg_maat_feather, PROTO_UNKONWN, scan_mid, matched_rules, MAX_TSG_ALL_RESULT_NUM);
		if(hit_num>0)
		{
			int security_result_num=tsg_select_matched_security_rules(matched_rules, hit_num, security_results, MAX_RESULT_NUM);
			p_result=matched_rules_decision_criteria(security_results, security_result_num);
			if(p_result!=NULL)
			{
				switch(p_result->action)
				{
					case	TSG_ACTION_DENY:
						state=tsg_enforing_deny(a_stream, p_result, PROTO_UNKONWN, ACTION_RETURN_TYPE_TCPALL, a_packet);
						session_runtime_process_log_send(a_stream, p_result, 1, NULL, thread_seq);
						break;
					case	TSG_ACTION_MONITOR:
						session_packet_capture_notify(a_stream, security_results, hit_num, thread_seq);
						session_matched_rules_notify(a_stream, TSG_SERVICE_SECURITY, security_results, security_result_num,thread_seq);
						break;
					default:
						break;
				}
			}

			size_t n_shaping_results=tsg_select_matched_shaping_rules(matched_rules, hit_num, shaping_results, MAX_RESULT_NUM);
			if(state==APP_STATE_GIVEME && n_shaping_results>0)
			{
				matched_shaping_rules_deal(a_stream, shaping_results, n_shaping_results, thread_seq);
			}

			struct maat_rule s_chaining_result[MAX_RESULT_NUM]={0};
			size_t n_s_chaining_results=tsg_select_matched_service_chaining_rules(matched_rules, hit_num, s_chaining_result, MAX_RESULT_NUM);
			if(state==APP_STATE_GIVEME && n_s_chaining_results>0)
			{
				matched_service_chaining_rules_deal(a_stream, s_chaining_result, n_s_chaining_results, thread_seq);
			}
		}
		
		maat_state_free(scan_mid);
		scan_mid=NULL;
	}

	switch(srt_action_context->method_type)
	{
		case	TSG_METHOD_TYPE_RATE_LIMIT:
			eth_rawpkt_len=get_raw_packet_len(a_stream);
			if(eth_rawpkt_len<=0)
			{
				break;
			}
	
			ret=is_permit_pass(eth_rawpkt_len*8, srt_action_context->bucket, thread_seq);
			if(ret==0)
			{
				state|=APP_STATE_GIVEME|APP_STATE_DROPPKT;
			}
			break;
		case    TSG_METHOD_TYPE_TAMPER:
			if(0 == send_tamper_xxx(a_stream, &srt_action_context->tamper_count, a_packet))
			{
				state|=APP_STATE_GIVEME|APP_STATE_DROPPKT;
			}
			break;
		case	TSG_METHOD_TYPE_DEFAULT:
			if(!is_do_default_policy(a_stream, srt_action_context->default_policy_after_n_packets) || stream_state==OP_STATE_CLOSE)
			{
				break;
			}
			
			if(get_default_policy(&security_results[0]))
			{
				state=tsg_enforing_deny(a_stream, &security_results[0], PROTO_UNKONWN, ACTION_RETURN_TYPE_TCPALL, a_packet);
				session_runtime_process_log_send(a_stream, &security_results[0], 1, NULL, thread_seq);
			}
			break;
		case	TSG_METHOD_TYPE_DROP:
		case	TSG_METHOD_TYPE_APP_DROP:
			// contain hited current packet, platform calls tcp first and tcpall secondary.
			if(((srt_action_context->hited_para.after_n_packets > 0) && a_stream->type==STREAM_TYPE_TCP) ||
				((srt_action_context->hited_para.after_n_packets > 0) && a_stream->type==STREAM_TYPE_UDP)
				|| stream_state==OP_STATE_CLOSE)
			{			
				srt_action_context->hited_para.after_n_packets--;
				break;
			}
			ret=session_matched_rules_copy(a_stream, TSG_SERVICE_SECURITY, &(security_results[0]), 1);
			//ret=tsg_pull_policy_result((struct streaminfo *)a_stream,PULL_FW_RESULT, &security_result[0], 1, &tmp_identify_info);
			if(ret<=0 || security_results[0].action!=TSG_ACTION_DENY)
			{
				break;
			}

			if(srt_action_context->hited_para.hited_app_id<=0)
			{
				state=tsg_enforing_deny(a_stream, &(security_results[0]), srt_action_context->protocol, ACTION_RETURN_TYPE_TCPALL, a_packet);
			}
			else
			{
				state=tsg_enforing_deny_application(a_stream, &(security_results[0]), srt_action_context->protocol, srt_action_context->hited_para.hited_app_id, ACTION_RETURN_TYPE_TCPALL, a_packet);
			}
			break;
		case	TSG_METHOD_TYPE_SHUNT:
			return APP_STATE_DROPME|APP_STATE_KILL_OTHER;
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
	struct udp_session_runtime_context *udp_srt_context=(struct udp_session_runtime_context *)(*pme);

	if(*pme==NULL)
	{
		unsigned short tunnel_type=0;
		int tunnel_type_len=sizeof(tunnel_type);
		int ret=MESA_get_stream_opt(a_udp, MSO_STREAM_UP_LAYER_TUNNEL_TYPE, (void *)&tunnel_type, &tunnel_type_len);
		if(ret==0 && tunnel_type&STREAM_TUNNEL_GPRS_TUNNEL)
		{
			return APP_STATE_DROPME;
		}

		session_state_sync_in_opening_and_closing(a_udp, a_udp->opstate);
		
		*pme=dictator_malloc(thread_seq, sizeof(struct udp_session_runtime_context));
		memset(*pme, 0, sizeof(struct udp_session_runtime_context));
		udp_srt_context=(struct udp_session_runtime_context *)(*pme);
		
		udp_srt_context->srt_action_context=(struct session_runtime_action_context *)dictator_malloc(thread_seq, sizeof(struct session_runtime_action_context));
		memset(udp_srt_context->srt_action_context, 0, sizeof(struct session_runtime_action_context));
		session_runtime_action_context_async(a_udp, (void *)(udp_srt_context->srt_action_context));

		udp_srt_context->srt_action_context->direction=get_direction(a_udp);
	}

	if(udp_srt_context->srt_action_context->udp_data_dropme==0)
	{
		state2=tsg_master_data_entry(a_udp, (void **)&(udp_srt_context->srt_process_context), thread_seq, a_packet);
	}
	
	if(!(state2&APP_STATE_DROPME) || udp_srt_context->srt_action_context->hited_para.after_n_packets>0)
	{
		if(state2&APP_STATE_DROPME)
		{
			udp_srt_context->srt_action_context->udp_data_dropme=1;
			state2=state2&(~(APP_STATE_DROPME));
		}
		
		state1=tsg_master_all_entry(a_udp, a_udp->opstate, (void **)&(udp_srt_context->srt_action_context), thread_seq, a_packet);
	}

	if(state1&APP_STATE_DROPME || state2&APP_STATE_DROPME || a_udp->opstate==OP_STATE_CLOSE)
	{
		dictator_free(thread_seq, *pme);
		*pme=NULL;

		session_state_sync_in_opening_and_closing(a_udp, a_udp->opstate);
	}

	return (state1|state2);
}

extern "C" unsigned char TSG_MASTER_TCPALL_ENTRY(const struct streaminfo *a_tcp, void **pme, int thread_seq, const void *a_packet)
{
	struct session_runtime_action_context *_context=(struct session_runtime_action_context *)(*pme);

	if(*pme==NULL)
	{
		session_state_sync_in_opening_and_closing(a_tcp, a_tcp->pktstate);
		*pme=(void *)session_runtime_action_context_get(a_tcp);
		if(*pme==NULL)
		{
			*pme=(struct session_runtime_action_context *)dictator_malloc(thread_seq, sizeof(struct session_runtime_action_context));
			memset(*pme, 0, sizeof(struct session_runtime_action_context));	
			session_runtime_action_context_async(a_tcp, (void *)(*pme));
		}

		_context=(struct session_runtime_action_context *)(*pme);
		_context->direction=get_direction(a_tcp);
	}
	
	if(_context->set_latency_flag==0)
	{
		_context->set_latency_flag=session_tcp_establish_latency_ms_set(a_tcp, thread_seq, a_packet);
	}
	
	unsigned char state=tsg_master_all_entry(a_tcp, a_tcp->pktstate, pme, thread_seq, a_packet);

	if(state&APP_STATE_DROPME || a_tcp->pktstate==OP_STATE_CLOSE)
	{
		session_state_sync_in_opening_and_closing(a_tcp, a_tcp->pktstate);
	}

	return state;
}

extern "C" int TSG_MASTER_INIT()
{
	int ret=0;
	char device_sn_filename[128]={0};
	char identify_proto_name[256]={0};
	
	memset(&g_tsg_para, 0, sizeof(g_tsg_para));
	
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM","LOG_LEVEL", &g_tsg_para.level, RLOG_LV_FATAL);
	MESA_load_profile_string_def(tsg_conffile, "SYSTEM","LOG_PATH", g_tsg_para.log_path, sizeof(g_tsg_para.log_path), "log/master");

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

	MESA_load_profile_int_def(tsg_conffile, "SYSTEM","UNKNOWN_APP_ID", &g_tsg_para.unknown_app_id, 4);

	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "IDENTIFY_PROTO_NAME", identify_proto_name, sizeof(identify_proto_name), "HTTP;SSL;DNS;FTP;BGP;MAIL;STREAMING_MEDIA;QUIC;SIP;SSH;Stratum;RDP;DTLS;");
	protocol_name2flag(identify_proto_name, &g_tsg_para.proto_flag);

	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "DATACENTER_ID", &g_tsg_para.datacenter_id, 0);
	MESA_load_profile_short_def(tsg_conffile, "SYSTEM", "TIMEOUT", (short *)&g_tsg_para.timeout, 300);
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "SCAN_TIME_INTERVAL", &g_tsg_para.scan_time_interval, 120);
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "IENTIFY_APP_MAX_PKT_NUM", &g_tsg_para.identify_app_max_pkt_num, 20);
	
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "FEATURE_TAMPER", &g_tsg_para.feature_tamper, 0);
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "SERVICE_CHAINING_SID", &g_tsg_para.service_chaining_sid, 0);
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "SHAPING_SID", &g_tsg_para.shaping_sid, 0);

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

	ret=device_id_set_telegraf(g_tsg_para.device_sn);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "SET_DEVICE_SN_TO_TELEGRAF", "Set device SN(%s) failed; please check :%s", g_tsg_para.device_sn, "/etc/default/telegraf");
	}

	ret=tsg_bridge_init(tsg_conffile);
	if(ret<0)
	{
		return -1;
	}

	init_page_template(tsg_conffile);
	init_fs2_handle(tsg_conffile);

	ret=tsg_maat_rule_init(tsg_conffile);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "INIT_MAAT", "tsg_maat_rule_init failed ...");
		return -1;
	}
	
	g_tsg_log_instance=tsg_sendlog_init(tsg_conffile, g_tsg_para.fs2_handle);
	if(g_tsg_log_instance==NULL)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "INIT_SENDLOG", "tsg_sendlog_init failed ...");
		return -1;
	}
	
	FS_start(g_tsg_para.fs2_handle);

	ret=tsg_statistic_init(tsg_conffile, g_tsg_para.logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "INIT_STATISTIC", "tsg_statistic_init failed ...");
		return -1;
	}

	l7_protocol_mapper_init(tsg_conffile);

	ret=tsg_gtp_signaling_hash_init(tsg_conffile, g_tsg_para.logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "INIT_GTP_HASH", "tsg_gtp_signaling_hash_init failed ...");
		return -1;
	}

	g_tsg_para.send_resetall=0;

	return 0;
}

extern "C" int TSG_MASTER_UNLOAD()
{
	return 0;
}
