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

#include "tsg_log.h"
#include "tsg_stat.h"
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
#include "tsg_proxy.h"
#include "tsg_bridge.h"
#include "uthash.h"
#include "statistics_metrics.h"

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
		tsg_stat_flow_update(STAT_STATUS_FAIL, FLOW_STAT_SET_TIMEOUT, 1);
	}
	else
	{
		tsg_stat_flow_update(STAT_STATUS_SUCCESS, FLOW_STAT_SET_TIMEOUT, 1);
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
		if((strcmp(s_mode, "mirror"))==0 || (strcmp(s_mode, "dumpfile"))==0)
		{
			g_tsg_para.deploy_mode=DEPLOY_MODE_MIRROR;
		}
		else if((strcmp(s_mode, "inline"))==0)
		{
			g_tsg_para.deploy_mode=DEPLOY_MODE_INLINE;
		}
		else if((strcmp(s_mode, "transparent"))==0)
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
				direction='E';	 //Internal to External
			}
			else
			{
				direction='I';	 //External to Internal
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

			return 1;
		}
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

static int l7_protocol_mapper_init(const char *conffile)
{
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
		sscanf(line, "%31s %31s %d", type_name, protocol->name, &protocol->id);

		HASH_ADD(hh1, g_tsg_para.name_by_id, id, sizeof(int), protocol);
		HASH_ADD(hh2, g_tsg_para.id_by_name, name, strlen(protocol->name), protocol);
		
		memset(line, 0, sizeof(line));
	}

	fclose(fp);
	fp=NULL;

	return 1;
}

static void free_l7_protocol_mapper()
{

	struct l7_protocol *out=NULL, *tmp=NULL;
	HASH_CLEAR(hh2, g_tsg_para.id_by_name);
	HASH_ITER(hh1, g_tsg_para.name_by_id, out ,tmp)
	{		
		if(out!=NULL)
		{
			HASH_DELETE(hh1, g_tsg_para.name_by_id, out);
			free(out);
			out=NULL;
		}
	}
	

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

/*
	L7(openvpn), appSketch(psiphon), Thrid(openvpn.ssl.wechat) = openvpn.ssl.psiphon
	L7(openvpn), appSketch(psiphon), Thrid(openvpn.qq_web.wechat) = openvpn.psiphon
	L7(openvpn), appSketch(psiphon), Thrid(openvpn.wechat) = openvpn.psiphon
	L7(openvpn.ssl), appSketch(psiphon), Thrid(openvpn.wechat) = openvpn.ssl.psiphon
	L7(openvpn.ssl), appSketch(psiphon), Thrid(openvpn) = openvpn.ssl.psiphon
	L7(openvpn.ssl), appSketch(psiphon), Thrid(openvpn.ssl.wechat) = openvpn.ssl.psiphon
	L7(null), appSketch(psiphon), Thrid(openvpn.ssl.wechat) = openvpn.ssl.psiphon
	L7(null), appSketch(psiphon), Thrid(wechat) = psiphon
	L7(null), appSketch(null), Thrid(openvpn.ssl.wechat) = openvpn.ssl.wechat
	L7(null), appSketch(null), Thrid(null) = unknown
*/

static int session_qm_result_l7_protocol_split(struct gather_app_result *gather_result)
{
	int i=0;
	for(i=gather_result->qm_engine_num; i>0; i--)
	{
		if(tsg_l7_protocol_id2name(gather_result->qm_engine[i-1].app_id))
		{
			break;
		}
	}

	gather_result->l7_qm_engine_num=i;
	return 0;
}

static unsigned int get_max_app_id(struct app_attributes *result, int result_num)
{
	int i=0;
	unsigned int max_app_id=0; 

	for(i=0; i< result_num; i++)
	{
		if(max_app_id < result->app_id)
		{
			max_app_id=result->app_id;
		}
	}

	return max_app_id;
}

/*
** Engine1 1.2 Engine2 1   -> 1.2
** Engine1 1.2 Engine2 1.3 -> 1.2
** Engine1 1   Engine2 1.2 -> 1.2
** Engine1 2   Engine2 1.2 -> 1.2
** Engine1 1   Engine2 2.3 -> 1
** Engine1 1   Engine2 2   -> 1
*/

static int copy_app_id(struct app_attributes *result, int result_num, unsigned int *combined_array, int combined_array_num)
{
	int i=0;
	for(i=0; i<result_num && i<combined_array_num; i++)
	{
		combined_array[i]=result[i].app_id;
	}

	return i;
}

#define	COMBINED_APP_ID_NUM	MAX_APP_ID_NUM*2
int session_application_full_path_combine(struct gather_app_result *gather_result, char *out_full_path, int out_full_path_len)
{
	int offset=0,combined_num=0;
	unsigned int combined_array[COMBINED_APP_ID_NUM]={0};

	if(gather_result->l7_protocol_num >= gather_result->l7_qm_engine_num)
	{
		combined_num+=copy_app_id(gather_result->l7_protocol, gather_result->l7_protocol_num, combined_array, COMBINED_APP_ID_NUM);
	}
	else
	{
		combined_num+=copy_app_id(gather_result->qm_engine, gather_result->l7_qm_engine_num, combined_array, COMBINED_APP_ID_NUM);
	}

	if(gather_result->matched_app_flag > 0)
	{
		combined_array[combined_num++]=gather_result->matched_app.app_id;
	}
	else if(gather_result->user_define_num>0)
	{
		if(combined_num<COMBINED_APP_ID_NUM)
		{
			combined_array[combined_num]=get_max_app_id(gather_result->user_define, gather_result->user_define_num);
			combined_num+=1;
		}
	}
	else if(gather_result->built_in_num>0)
	{
		combined_num+=copy_app_id(gather_result->built_in, gather_result->built_in_num, combined_array+combined_num, COMBINED_APP_ID_NUM-combined_num);
	}
	else if(gather_result->qm_engine_num-gather_result->l7_qm_engine_num > 0)
	{
		combined_num+=copy_app_id(  gather_result->qm_engine + gather_result->l7_qm_engine_num,
									gather_result->qm_engine_num - gather_result->l7_qm_engine_num, 
									combined_array+combined_num,
									COMBINED_APP_ID_NUM-combined_num
								);
	}
	else if(gather_result->unknown_flag>0)
	{
		combined_array[combined_num++]=gather_result->unknown.app_id;
	}
	else
	{
		// FATAL LOG
	}

	for(int i=0; i<combined_num; i++)
	{
		offset+=tsg_get_app_name_by_id(g_tsg_maat_feather, combined_array[i], out_full_path+offset, out_full_path_len-offset, 0);
		if(offset>0)
		{
			out_full_path[offset++]='.';
		}
	}

	if(offset>0)
	{
		out_full_path[offset-1]='\0';
	}

	return offset;
}

int session_application_full_path_update(const struct streaminfo *a_stream, char *app_full_path, int app_full_path_len)
{
	struct gather_app_result *gather_result=(struct gather_app_result *)session_gather_app_results_get(a_stream);
	if(gather_result!=NULL)
	{
		session_qm_result_l7_protocol_split(gather_result);
		session_application_full_path_combine(gather_result, app_full_path, app_full_path_len);
	}
	else
	{
		tsg_get_app_name_by_id(g_tsg_maat_feather, tsg_unknown_app_id_get(g_tsg_log_instance), app_full_path, app_full_path_len, 0);
	}

	return 1;
}

static const char *session_addr_type_string_convert(UCHAR addrtype)
{
	switch (addrtype)
	{
		case ADDR_TYPE_IPV4:
		case __ADDR_TYPE_IP_PAIR_V4:
			return ".IPv4";
		case ADDR_TYPE_IPV6:
		case __ADDR_TYPE_IP_PAIR_V6:
			return ".IPv6";
		case ADDR_TYPE_VLAN:
			return ".VLAN";
		case ADDR_TYPE_MAC:
			return ".ETHERNET";
		case ADDR_TYPE_ARP:
			return ".ARP";
		case ADDR_TYPE_GRE:
			return ".GRE";
		case ADDR_TYPE_MPLS:
			return ".MPLS";
		case ADDR_TYPE_PPPOE_SES:
			return ".PPPOE";
		case ADDR_TYPE_TCP:
			return ".TCP";
		case ADDR_TYPE_UDP:
			return ".UDP";
		case ADDR_TYPE_L2TP:
			return ".L2TP";
		case ADDR_TYPE_PPP:
			return ".PPP";
		case ADDR_TYPE_PPTP:
			return ".PPTP";
		case ADDR_TYPE_MAC_IN_MAC:
			return ".MAC_IN_MAC";
		case ADDR_TYPE_GPRS_TUNNEL:
			return ".GTP";
		case ADDR_TYPE_VXLAN:
			return ".VXLAN";
		default:
			return NULL;
	}
}

#define MAX_L4_PROTOCOL_STR_LEN 512
char *session_l4_protocol_label_update(const struct streaminfo *a_stream)
{
	if(a_stream==NULL)
	{
		return NULL;
	}

	const char *l4_protocol_str = NULL;
	int combined_l4_protocol_offset=MAX_L4_PROTOCOL_STR_LEN;
	char combined_l4_protocol_str[MAX_L4_PROTOCOL_STR_LEN]={0};
	struct streaminfo *cur_stream = (struct streaminfo *)a_stream;

	while (cur_stream != NULL)
	{
		switch (cur_stream->type)
		{
			case STREAM_TYPE_TCP:
				if (cur_stream->addr.addrtype == ADDR_TYPE_IPV4)
				{
					l4_protocol_str = ".IPv4.TCP";
				}
				else if (cur_stream->addr.addrtype == ADDR_TYPE_IPV6)
				{
					l4_protocol_str = ".IPv6.TCP";
				}
				break;
			case STREAM_TYPE_UDP:
				if (cur_stream->addr.addrtype == ADDR_TYPE_IPV4)
				{
					l4_protocol_str = ".IPv4.UDP";
				}
				else if (cur_stream->addr.addrtype == ADDR_TYPE_IPV6)
				{
					l4_protocol_str = ".IPv6.UDP";
				}
				break;
			case STREAM_TYPE_VLAN:
				l4_protocol_str = ".VLAN"; break;
			case STREAM_TYPE_PPPOE:
				l4_protocol_str = ".PPPOE"; break;
			case STREAM_TYPE_L2TP:
				l4_protocol_str = ".L2TP"; break;
			case STREAM_TYPE_OPENVPN:
				l4_protocol_str = ".OpenVPN"; break;
			case STREAM_TYPE_PPTP:
				l4_protocol_str = ".PPTP"; break;
			case STREAM_TYPE_NON:
			case STREAM_TYPE_ISAKMP:
				l4_protocol_str = session_addr_type_string_convert(cur_stream->addr.addrtype);
				break;
			// SOCKS4 SOCKS5 HTTP
			default:
				break;
		}

		if(l4_protocol_str!=NULL)
		{
			int n_l4_protocol_str = strlen(l4_protocol_str);

			if (combined_l4_protocol_offset - n_l4_protocol_str < 0)
			{
				break;
			}
			
			memcpy(combined_l4_protocol_str+combined_l4_protocol_offset-n_l4_protocol_str, l4_protocol_str, n_l4_protocol_str);
			combined_l4_protocol_offset-=n_l4_protocol_str;
			l4_protocol_str=NULL;
		}

		cur_stream = cur_stream->pfather;
	}

	if(combined_l4_protocol_offset>0 && combined_l4_protocol_offset<MAX_L4_PROTOCOL_STR_LEN)
	{
		int l4_protocol_len=MAX_L4_PROTOCOL_STR_LEN-combined_l4_protocol_offset-1;
		char *l4_protocol=(char *)dictator_malloc(a_stream->threadnum, l4_protocol_len+1);
		memcpy(l4_protocol, combined_l4_protocol_str+combined_l4_protocol_offset+1, l4_protocol_len); // +1 for del "."
		l4_protocol[l4_protocol_len]='\0';

		return l4_protocol;
	}
	
	return NULL;
}


int session_udp_current_traffic_statis_update(const struct streaminfo *a_stream, struct traffic_packet_info *current_traffic_statis)
{
	struct udp_flow_stat *uflow_stat = (struct udp_flow_stat *)project_req_get_struct(a_stream, g_tsg_log_instance->udp_flow_project_id);
	if (uflow_stat!=NULL)
	{
		current_traffic_statis->c2s_pkts=uflow_stat->C2S_pkt;
		current_traffic_statis->s2c_pkts=uflow_stat->S2C_pkt;
		current_traffic_statis->c2s_bytes=uflow_stat->C2S_all_byte_raw;
		current_traffic_statis->s2c_bytes=uflow_stat->S2C_all_byte_raw;
		current_traffic_statis->c2s_fragments=uflow_stat->C2S_ip_fragment_pkt;
		current_traffic_statis->s2c_fragments=uflow_stat->S2C_ip_fragment_pkt;

		return 1;
	}
	
	return 0;
}

int session_tcp_current_traffic_statis_update(const struct streaminfo *a_stream, struct traffic_packet_info *current_traffic_statis)
{
	struct tcp_flow_stat *tflow_stat = (struct tcp_flow_stat *)project_req_get_struct(a_stream, g_tsg_log_instance->tcp_flow_project_id);
	if(tflow_stat != NULL)
	{
		current_traffic_statis->c2s_pkts = tflow_stat->C2S_all_pkt;
		current_traffic_statis->s2c_pkts = tflow_stat->S2C_all_pkt;
		current_traffic_statis->c2s_bytes = tflow_stat->C2S_all_byte_raw;
		current_traffic_statis->s2c_bytes = tflow_stat->S2C_all_byte_raw;
		current_traffic_statis->c2s_fragments = tflow_stat->C2S_ip_fragment_pkt;
		current_traffic_statis->s2c_fragments = tflow_stat->S2C_ip_fragment_pkt;
		current_traffic_statis->c2s_tcp_lost_bytes = tflow_stat->C2S_seq_gap_loss_cnt;
		current_traffic_statis->s2c_tcp_lost_bytes = tflow_stat->S2C_seq_gap_loss_cnt;
		current_traffic_statis->c2s_tcp_ooorder_pkts = tflow_stat->C2S_ooorder_pkt;
		current_traffic_statis->s2c_tcp_ooorder_pkts = tflow_stat->S2C_ooorder_pkt;
		current_traffic_statis->c2s_tcp_retransmitted_pkts = tflow_stat->C2S_retransmission_pkt;
		current_traffic_statis->s2c_tcp_retransmitted_pkts = tflow_stat->S2C_retransmission_pkt;
		current_traffic_statis->c2s_tcp_retransmitted_bytes = tflow_stat->C2S_retransmission_byte;
		current_traffic_statis->s2c_tcp_retransmitted_bytes = tflow_stat->S2C_retransmission_byte;

		return 1;
	}
	
	return 0;
}

int session_current_traffic_statis_update(const struct streaminfo *a_stream, struct traffic_packet_info *current_traffic_statis, int thread_seq)
{
	int value_len=sizeof(unsigned long long);

	current_traffic_statis->sessions=1;
	MESA_get_stream_opt(a_stream, MSO_TOTAL_INBOUND_BYTE_RAW, (void *)&(current_traffic_statis->in_bytes), &value_len);
	MESA_get_stream_opt(a_stream, MSO_TOTAL_INBOUND_PKT, (void *)&(current_traffic_statis->in_pkts), &value_len);
	MESA_get_stream_opt(a_stream, MSO_TOTAL_OUTBOUND_BYTE_RAW, (void *)&(current_traffic_statis->out_bytes), &value_len);
	MESA_get_stream_opt(a_stream, MSO_TOTAL_OUTBOUND_PKT, (void *)&(current_traffic_statis->out_pkts), &value_len);

	switch (a_stream->type)
	{
		case STREAM_TYPE_TCP:
			session_tcp_current_traffic_statis_update(a_stream, current_traffic_statis);
			break;
		case STREAM_TYPE_UDP:
			session_udp_current_traffic_statis_update(a_stream, current_traffic_statis);
			break;
		default:
			break;
	}

	return 0;
}

int session_increase_traffic_statis_update(struct traffic_packet_info *current, struct traffic_packet_info *last, struct traffic_packet_info *increase)
{
	if(last==NULL)
	{
		*increase=*current;
		return 1;
	}
	
	increase->sessions=current->sessions-last->sessions;
	increase->in_pkts=current->in_pkts-last->in_pkts;
	increase->out_pkts=current->out_pkts-last->out_pkts;
	increase->c2s_pkts=current->c2s_pkts-last->c2s_pkts;
	increase->s2c_pkts=current->s2c_pkts-last->s2c_pkts;
	increase->c2s_fragments=current->c2s_fragments-last->c2s_fragments;
	increase->s2c_fragments=current->s2c_fragments-last->s2c_fragments;
	increase->c2s_tcp_ooorder_pkts=current->c2s_tcp_ooorder_pkts-last->c2s_tcp_ooorder_pkts;
	increase->s2c_tcp_ooorder_pkts=current->s2c_tcp_ooorder_pkts-last->s2c_tcp_ooorder_pkts;
	increase->c2s_tcp_retransmitted_pkts=current->c2s_tcp_retransmitted_pkts-last->c2s_tcp_retransmitted_pkts;
	increase->s2c_tcp_retransmitted_pkts=current->s2c_tcp_retransmitted_pkts-last->s2c_tcp_retransmitted_pkts;
	increase->in_bytes=current->in_bytes-last->in_bytes;
	increase->out_bytes=current->out_bytes-last->out_bytes;
	increase->c2s_bytes=current->c2s_bytes-last->c2s_bytes;
	increase->s2c_bytes=current->s2c_bytes-last->s2c_bytes;
	increase->c2s_tcp_lost_bytes=current->c2s_tcp_lost_bytes-last->c2s_tcp_lost_bytes;
	increase->s2c_tcp_lost_bytes=current->s2c_tcp_lost_bytes-last->s2c_tcp_lost_bytes;
	increase->c2s_tcp_retransmitted_bytes=current->c2s_tcp_retransmitted_bytes-last->c2s_tcp_retransmitted_bytes;
	increase->s2c_tcp_retransmitted_bytes=current->s2c_tcp_retransmitted_bytes-last->s2c_tcp_retransmitted_bytes;

	return 1;
}

int session_application_metrics_update(const struct streaminfo *a_stream, struct session_runtime_action_context *srt_action_context, int thread_seq)
{
	if((tsg_get_current_time_ms() - srt_action_context->last_update_metric_time < g_tsg_para.app_metric_update_interval_ms)
		&& a_stream->opstate!=OP_STATE_CLOSE && a_stream->pktstate!=OP_STATE_CLOSE && !(srt_action_context->state&APP_STATE_DROPME))
	{
		return 0;
	}

	char app_full_path[256]={0};
	struct traffic_packet_info current_traffic_statis={0},increase_traffic_statis={0};
	session_application_full_path_update(a_stream, app_full_path, sizeof(app_full_path));

	if(srt_action_context->l4_protocol==NULL)
	{
		srt_action_context->l4_protocol=session_l4_protocol_label_update(a_stream);
	}
	
	session_current_traffic_statis_update(a_stream, &current_traffic_statis, thread_seq);
	session_increase_traffic_statis_update(&current_traffic_statis, srt_action_context->last_traffic_statis, &increase_traffic_statis);
	tsg_set_application_metrics(a_stream, srt_action_context->l4_protocol, app_full_path, &increase_traffic_statis, thread_seq);

	if(srt_action_context->last_traffic_statis==NULL)
	{
		srt_action_context->last_traffic_statis=(struct traffic_packet_info *)dictator_malloc(thread_seq, sizeof(struct traffic_packet_info));
	}
	
	*(srt_action_context->last_traffic_statis)=current_traffic_statis;
	srt_action_context->last_update_metric_time = tsg_get_current_time_ms();

	return 1;
}

static int check_app_id(unsigned int *new_app_id, int n_new_app_id, unsigned int old_app_id)
{
	for(int j=0; j<n_new_app_id; j++)
	{
		if(old_app_id==new_app_id[j])
		{
			return 1;
		}
	}

	return 0;
}

int session_app_gather_results_set_l7_protocol(const struct streaminfo *a_stream, unsigned int *app_id, int n_app_id)
{
	if(app_id==NULL || n_app_id==0)
	{
		return 0;
	}
	
	struct gather_app_result *gather_result=(struct gather_app_result *)session_gather_app_results_get(a_stream);
	if(gather_result==NULL)
	{
		gather_result=(struct gather_app_result *)dictator_malloc(a_stream->threadnum, sizeof(struct gather_app_result));
		memset(gather_result, 0, sizeof(struct gather_app_result));
		session_gather_app_results_async(a_stream, (void *)gather_result);
	}

	int not_combined_flag=0;
	for(int i=0; i<gather_result->l7_protocol_num; i++)
	{
		not_combined_flag=check_app_id(app_id, n_app_id, gather_result->l7_protocol[i].app_id);
		if(not_combined_flag==1)
		{
			break;
		}
	}

	struct app_attributes *l7_protocol=(struct app_attributes *)dictator_malloc(a_stream->threadnum, sizeof(struct app_attributes)*n_app_id);
	for(int i=0; i<n_app_id; i++)
	{	
		l7_protocol[i].app_id=app_id[i];
		l7_protocol[i].surrogate_id=0;
		l7_protocol[i].packet_sequence=get_packet_sequence(a_stream);
	}

	if(not_combined_flag==0 && gather_result->l7_protocol_num>0)
	{
		l7_protocol=(struct app_attributes *)dictator_realloc(a_stream->threadnum, l7_protocol, sizeof(struct app_attributes)*(n_app_id+gather_result->l7_protocol_num));
		memcpy((void *)(l7_protocol+n_app_id), (void *)gather_result->l7_protocol, sizeof(struct app_attributes)*gather_result->l7_protocol_num);
		gather_result->l7_protocol_num+=n_app_id;
	}
	else
	{
		gather_result->l7_protocol_num=n_app_id;
	}

	if(gather_result->l7_protocol!=NULL)
	{
		dictator_free(a_stream->threadnum, gather_result->l7_protocol);
	}
	
	gather_result->l7_protocol=l7_protocol;

	return 0;
}

int session_app_gather_results_update_matched_app_id(const struct streaminfo *a_stream, unsigned int matched_app_id)
{
	if(matched_app_id==0)
	{
		return 0;
	}

	const char *app_name=tsg_l7_protocol_id2name(matched_app_id);
	if(app_name!=NULL)
	{
		return 0;
	}

	struct gather_app_result *gather_result=(struct gather_app_result *)session_gather_app_results_get(a_stream);
	if(gather_result==NULL)
	{
		return 0;
	}
	
	gather_result->matched_app_flag=1;
	gather_result->matched_app.app_id=matched_app_id;
	gather_result->matched_app.surrogate_id=0;

	return 1;
}

int session_state_control_packet(const struct streaminfo *a_stream, void *payload, unsigned int payload_len)
{
	if(payload==NULL || payload_len==0)
	{
		return 0;
	}
	
	int is_ctrl_pkt=0;
	const void *raw_pkt = get_rawpkt_from_streaminfo(a_stream);
	int ret=get_opt_from_rawpkt(raw_pkt, RAW_PKT_GET_IS_CTRL_PKT, (void *)&is_ctrl_pkt);
	if(ret<0 || is_ctrl_pkt==0)
	{
		return 0;
	}

	ret=tsg_parse_log_update_payload(a_stream, (const void *)payload, payload_len);
	if(ret>=0)
	{
		return 1;
	}
	
	return 0;
}

int session_state_sync_in_opening_and_closing(const struct streaminfo *a_stream, unsigned char state)
{
	struct segment_id_list sid_list={0};

	if(g_tsg_para.intercept_sid>0)
	{
		sid_list.sid_list[sid_list.sz_sidlist++]=(unsigned short)g_tsg_para.intercept_sid;
	}

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
		}
	}

	switch(state)
	{
		case	OP_STATE_PENDING:
			tsg_sync_opening_state(a_stream, state);
			break;
		case	OP_STATE_CLOSE:
			tsg_sync_closing_state(a_stream, state);
			break;
		default:
			break;
	}

	sid_list.sz_sidlist=0;
	MESA_set_stream_opt(a_stream, MSO_STREAM_PREPLEND_SEGMENT_ID_LIST, (void *)&sid_list, sizeof(struct segment_id_list));

	return 1;
}

int session_state_update_policy(struct update_policy *u_policy, struct maat_rule *matched_rules, size_t n_matched_rules, enum policy_type p_type)
{
	u_policy->n_ids=n_matched_rules;
	u_policy->type=p_type;
	
	for(size_t i=0; i<n_matched_rules; i++)
	{
		u_policy->ids[i]=matched_rules[i].rule_id;
	}

	return 0;
}

enum policy_type session_state_get_policy_type(TSG_SERVICE service)
{
	enum policy_type p_type=POLICY_UPDATE_MAX;
	switch(service)
	{
		case	TSG_SERVICE_CHAINING:
			if(g_tsg_para.service_chaining_sid==0)
			{
				break;
			}
			return POLICY_UPDATE_SERVICE_CHAINING;
		case	TSG_SERVICE_SHAPING:
			if(g_tsg_para.shaping_sid==0)
			{
				break;
			}
			return POLICY_UPDATE_SHAPING;
		case	TSG_SERVICE_INTERCEPT:
			if(g_tsg_para.intercept_sid==0)
			{
				break;
			}
			return POLICY_UPDATE_INTERCEPT;
		default:
			break;
	}

	return p_type;
}

unsigned short session_state_update_segment_sids(struct segment_id_list *segment_ids, enum policy_type p_type)
{
	unsigned short segment_id=0;
	unsigned short tmp_sids[POLICY_UPDATE_MAX]={0};

	switch(p_type)
	{
		case	POLICY_UPDATE_SHAPING:
			segment_id=g_tsg_para.shaping_sid;
			break;
		case	POLICY_UPDATE_INTERCEPT:
			segment_id=g_tsg_para.intercept_sid;
			break;
		case	POLICY_UPDATE_SERVICE_CHAINING:
			segment_id=g_tsg_para.service_chaining_sid;
			break;
		default:
			return 0;
	}
	
	for(size_t i=0; i<segment_ids->sz_sidlist; i++)
	{
		if(segment_ids->sid_list[i]==segment_id || segment_id==0)
		{
			return segment_id;
		}

		if(segment_ids->sid_list[i]==g_tsg_para.intercept_sid)
		{
			tmp_sids[POLICY_UPDATE_INTERCEPT]=segment_ids->sid_list[i];
			continue;
		}

		if(segment_ids->sid_list[i]==g_tsg_para.service_chaining_sid)
		{
			tmp_sids[POLICY_UPDATE_SERVICE_CHAINING]=segment_ids->sid_list[i];
			continue;
		}

		if(segment_ids->sid_list[i]==g_tsg_para.shaping_sid)
		{
			tmp_sids[POLICY_UPDATE_SHAPING]=segment_ids->sid_list[i];
			continue;
		}
	}

	tmp_sids[p_type]=segment_id;
	segment_ids->sz_sidlist=0;
	for(int i=0; i<POLICY_UPDATE_MAX; i++)
	{
		if(tmp_sids[i]!=0)
		{
			segment_ids->sid_list[segment_ids->sz_sidlist++]=tmp_sids[i];
		}
	}
	
	return segment_id;
}

size_t matched_rules_increase_in_activing(const struct matched_policy_rules *matched_rules, struct maat_rule *new_rules, size_t n_new_rules, struct maat_rule *inc_rules, size_t n_inc_rules)
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
	enum policy_type p_type=session_state_get_policy_type(service);
	if(p_type>=POLICY_UPDATE_MAX)
	{
		return 0;
	}

	struct segment_id_list *segment_ids=(struct segment_id_list *)session_control_segment_ids_get(a_stream);
	if(segment_ids==NULL)
	{
		segment_ids=(struct segment_id_list *)dictator_malloc(a_stream->threadnum, sizeof(struct segment_id_list));
		memset(segment_ids, 0, sizeof(struct segment_id_list));
	}

	unsigned short segment_id=session_state_update_segment_sids(segment_ids, p_type);
	if(segment_id==0)
	{
		dictator_free(a_stream->threadnum, (void *)segment_ids);
		return 0;
	}

	MASTER_LOG(g_tsg_para.logger, RLOG_LV_DEBUG, LOG_MODULE_SID, "set in active status , service:%d, sid:%u,session addr:%s", service, segment_id, printaddr(&(a_stream->addr), a_stream->threadnum));

	struct segment_id_list sid_list;
	sid_list.sz_sidlist=1;
	sid_list.sid_list[0]=segment_id;
	MESA_set_stream_opt(a_stream, MSO_STREAM_PREPLEND_SEGMENT_ID_LIST, (void *)&sid_list, sizeof(struct segment_id_list));

	int policy_array_offset=1;
	struct update_policy policy_array[2];
	session_state_update_policy(&(policy_array[0]), inc_rules, n_inc_rules, p_type);
	if(service==TSG_SERVICE_INTERCEPT)
	{
		memset(&policy_array[0].cmsg, 0, sizeof(struct proxy_cmsg));
		tsg_proxy_update_policy_fill(a_stream, &(policy_array[0]), segment_ids);

		struct matched_policy_rules *s_chaining = (struct matched_policy_rules *)session_matched_rules_get(a_stream, TSG_SERVICE_CHAINING);
		if(s_chaining!=NULL)
		{
			policy_array_offset++;
			session_state_update_policy(&(policy_array[1]), s_chaining->rules, s_chaining->n_rules, POLICY_UPDATE_SERVICE_CHAINING);
		}
	}

	tsg_sync_policy_update(a_stream, policy_array, policy_array_offset);

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
	size_t n_inc_results=matched_rules_increase_in_activing(matched_rules, rules, n_rules, inc_rules, MAX_RESULT_NUM-matched_rules->n_rules);
	if(n_inc_results==0)
	{
		return 0;
	}

	memcpy(matched_rules->rules+matched_rules->n_rules, inc_rules, n_inc_results*sizeof(struct maat_rule));
	matched_rules->n_rules+=n_inc_results;
	int ret=session_matched_rules_async(a_stream, service, (void *)matched_rules);
	if(ret<0)
	{
		session_matched_rules_free(a_stream, service, (void *)matched_rules);
		return 0;
	}
	
	ret=session_set_segment_id_in_activing(a_stream, service, inc_rules, n_inc_results);
	if(ret==0)
	{
		return 0;
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

int session_l7_protocol_identify(const struct streaminfo *a_stream, struct session_runtime_process_context *srt_process_context, void *a_packet)
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
			
			{//ssl
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

					if(chello->is_encrypt_sni==1)
					{
						srt_process_context->is_esni=1;
					}
					

					if(chello->is_encrypt_chello==1)
					{
						srt_process_context->is_ech=1;
					}
					
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
				struct quic_info *q_info=quic_protocol_identify(a_stream);
				if(q_info!=NULL)
				{
					srt_process_context->proto=PROTO_QUIC;
					srt_process_context->quic_version=q_info->quic_version;
					
					if(q_info->client_hello==NULL)
					{
						return 1;
					}
					
					if(q_info->client_hello->sni!=NULL)
					{
						srt_process_context->quic_sni=malloc_copy_string(q_info->client_hello->sni, strlen(q_info->client_hello->sni), a_stream->threadnum);
					}

					if(q_info->client_hello->user_agent!=NULL)
					{
						srt_process_context->quic_ua=malloc_copy_string(q_info->client_hello->user_agent, strlen(q_info->client_hello->user_agent), a_stream->threadnum);
					}
					
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

size_t session_app_id_and_properties_scan(const struct streaminfo *a_stream, struct maat_rule *matched_rules, size_t n_matched_rules, struct session_runtime_process_context *srt_process_context, struct app_attributes *app_attribute, char app_attribute_num, APP_IDENTIFY_ORIGIN origin, int thread_seq)
{
	size_t matched_cnt=0;
	int after_n_packets=0;
	unsigned int matched_app_id=0;
	struct maat_rule *p_result, *d_result=NULL;

	for(int i=0; i< app_attribute_num; i++)
	{
		struct app_id_dict *dict=(struct app_id_dict *)matched_rule_cites_app_id_dict(g_tsg_maat_feather, (long long)app_attribute[i].app_id);
		if(dict!=NULL)
		{
			matched_cnt+=tsg_scan_app_properties_policy(a_stream, g_tsg_maat_feather, dict->risk, (int)dict->risk_len, (char *)"risk", 4, (srt_process_context->mid), matched_rules+matched_cnt, n_matched_rules-matched_cnt);
			matched_cnt+=tsg_scan_app_properties_policy(a_stream, g_tsg_maat_feather, dict->category, (int)dict->category_len, (char *)"category", 8, (srt_process_context->mid), matched_rules+matched_cnt, n_matched_rules-matched_cnt);
			matched_cnt+=tsg_scan_app_properties_policy(a_stream, g_tsg_maat_feather, dict->technology, (int)dict->technology_len, (char *)"technology", 10, (srt_process_context->mid), matched_rules+matched_cnt, n_matched_rules-matched_cnt);
			matched_cnt+=tsg_scan_app_properties_policy(a_stream, g_tsg_maat_feather, dict->subcategory, (int)dict->subcategory_len, (char *)"subcategory", 11, (srt_process_context->mid), matched_rules+matched_cnt, n_matched_rules-matched_cnt);
			matched_cnt+=tsg_scan_app_properties_policy(a_stream, g_tsg_maat_feather, dict->characteristics, (int)dict->characteristics_len, (char *)"characteristics", 15, (srt_process_context->mid), matched_rules+matched_cnt, n_matched_rules-matched_cnt);
		
			matched_cnt+=tsg_scan_app_id_policy(a_stream, g_tsg_maat_feather, app_attribute[i].app_id, (srt_process_context->mid), matched_rules+matched_cnt, n_matched_rules-matched_cnt);
			after_n_packets=dict->deny_app_para.after_n_packets;
			
			set_app_timeout(a_stream, dict, &(srt_process_context->timeout));
		}
		else
		{
			matched_cnt+=tsg_scan_app_id_policy(a_stream, g_tsg_maat_feather, app_attribute[i].app_id, (srt_process_context->mid), matched_rules+matched_cnt, n_matched_rules-matched_cnt);
		}

		p_result=tsg_select_deny_rule(matched_rules, matched_cnt);
		if(d_result==NULL)
		{
			d_result=p_result;
			matched_app_id=app_attribute[i].app_id;
			continue;
		}
		
		if(d_result->rule_id!=p_result->rule_id)
		{
			d_result=p_result;
			matched_app_id=app_attribute[i].app_id;
		}
	}	

	if(matched_cnt>0)
	{
		if(origin!=ORIGIN_BASIC_PROTOCOL)
		{
			srt_process_context->matched_app_id=matched_app_id;
			session_app_gather_results_update_matched_app_id(a_stream, matched_app_id);
		}
		
		srt_process_context->hited_para.matched_app_id=matched_app_id;
		srt_process_context->hited_para.after_n_packets=after_n_packets;
	}
	else
	{
		if(origin==ORIGIN_BASIC_PROTOCOL && after_n_packets>0) //for enum TSG_PROTOCOL
		{
			srt_process_context->hited_para.after_n_packets=after_n_packets;
		}
	}

	return matched_cnt;
}

size_t session_app_gather_results_scan(const struct streaminfo *a_stream, struct maat_rule *rules, size_t n_rules, struct session_runtime_process_context *srt_process_context, int thread_seq)
{
	struct gather_app_result *gather_result=(struct gather_app_result *)session_gather_app_results_get(a_stream);
	if(gather_result==NULL)
	{
		return 0;
	}
	
	int matched_cnt=0;
	if(gather_result->unknown_flag==1)
	{
		matched_cnt+=session_app_id_and_properties_scan(a_stream, rules+matched_cnt, n_rules-matched_cnt, srt_process_context, &(gather_result->unknown), 1, ORIGIN_UNKNOWN, thread_seq);
	}
	
	matched_cnt+=session_app_id_and_properties_scan(a_stream, rules+matched_cnt, n_rules-matched_cnt, srt_process_context, gather_result->l7_protocol, gather_result->l7_protocol_num, ORIGIN_BASIC_PROTOCOL, thread_seq);
	matched_cnt+=session_app_id_and_properties_scan(a_stream, rules+matched_cnt, n_rules-matched_cnt, srt_process_context, gather_result->qm_engine, gather_result->qm_engine_num, ORIGIN_QM_ENGINE, thread_seq);
	matched_cnt+=session_app_id_and_properties_scan(a_stream, rules+matched_cnt, n_rules-matched_cnt, srt_process_context, gather_result->built_in, gather_result->built_in_num, ORIGIN_BUILT_IN, thread_seq);
	matched_cnt+=session_app_id_and_properties_scan(a_stream, rules+matched_cnt, n_rules-matched_cnt, srt_process_context, gather_result->user_define, gather_result->user_define_num, ORIGIN_USER_DEFINE, thread_seq);

	return matched_cnt;
}

static unsigned char matched_security_rules_deal(const struct streaminfo *a_stream, struct session_runtime_process_context *srt_process_context, struct maat_rule *security_rules, size_t n_security_rules, const void *a_packet, int thread_seq)
{
	void *user_data=NULL;
	unsigned char state=APP_STATE_GIVEME;
	struct maat_rule *p_rule=matched_rules_decision_criteria(security_rules, n_security_rules);
	if(p_rule->action==TSG_ACTION_SHUNT)
	{
		tsg_set_policy_flow(a_stream, p_rule, a_stream->threadnum);
		srt_action_context_set_rule_method(a_stream, TSG_METHOD_TYPE_SHUNT, a_stream->threadnum);
		return APP_STATE_DROPME|APP_STATE_KILL_OTHER;
	}

	switch(p_rule->action)
	{
		case	TSG_ACTION_DENY:
			if(srt_process_context->proto==PROTO_DNS)	/* deal action of deny in firewall */
			{
				user_data=NULL;
			}
			else
			{
				user_data=(void *)a_packet;
			}
			
			if(is_deny_application(p_rule))
			{
				if(srt_process_context->hited_para.matched_app_id==0)
				{
					srt_process_context->hited_para.matched_app_id=tsg_l7_protocol_name2id(g_tsg_proto_name2id[srt_process_context->proto].name, g_tsg_proto_name2id[srt_process_context->proto].len);
				}

				srt_action_context_set_hitted_app_id(a_stream, srt_process_context->hited_para.matched_app_id, a_stream->threadnum);
				state=tsg_enforing_deny_application(a_stream, p_rule, srt_process_context->proto, srt_process_context->hited_para.matched_app_id, ACTION_RETURN_TYPE_APP, user_data);
			}
			else
			{
				state=tsg_enforing_deny(a_stream, p_rule, srt_process_context->proto, ACTION_RETURN_TYPE_APP, user_data);
			}

			if(is_deny_after_N_packets(p_rule))
			{
				session_matched_rules_notify(a_stream, TSG_SERVICE_SECURITY, p_rule, 1, a_stream->threadnum);
				if(a_stream->type==STREAM_TYPE_TCP)
				{
					break;
				}
			}

			if((srt_process_context->proto==PROTO_HTTP || srt_process_context->proto==PROTO_SSL) && state&APP_STATE_DROPME)
			{
				state|=APP_STATE_KILL_OTHER;
			}

			session_matched_rules_notify(a_stream, TSG_SERVICE_SECURITY, p_rule, 1, a_stream->threadnum);
			break;
		case	TSG_ACTION_BYPASS:
			srt_process_context->is_hitted_allow=1;
			session_matched_rules_notify(a_stream, TSG_SERVICE_SECURITY, p_rule, 1, a_stream->threadnum);

			srt_action_context_set_rule_method(a_stream, TSG_METHOD_TYPE_ALLOW, a_stream->threadnum);
			break;
		default:
			break;
	}

	struct maat_rule monitor_rules[MAX_RESULT_NUM]={0};
	size_t n_monitor_rules=tsg_select_rules_by_action(security_rules, n_security_rules, monitor_rules, MAX_RESULT_NUM, TSG_ACTION_MONITOR);
	if(n_monitor_rules>0)
	{
		session_packet_capture_by_rules_notify(a_stream, monitor_rules, n_monitor_rules, a_stream->threadnum);
		session_matched_rules_notify(a_stream, TSG_SERVICE_SECURITY, monitor_rules, n_monitor_rules, a_stream->threadnum);
	}
	
	return state;
}

int matched_statistics_rules_deal(const struct streaminfo *a_stream, struct maat_rule *statistics_rules, size_t n_statistics_rules, int thread_seq)
{
	struct matched_policy_rules policy;
	policy.n_rules=MIN(MAX_RESULT_NUM, n_statistics_rules);
	memcpy(policy.rules, statistics_rules, (policy.n_rules)*sizeof(struct maat_rule));
	session_dimension_maat_rule_sync(a_stream, &policy);

	srt_action_context_set_rule_method(a_stream, TSG_METHOD_TYPE_UNKNOWN, thread_seq);

	return 0;
}

int matched_shaping_rules_deal(const struct streaminfo *a_stream, struct maat_rule *shaping_rules, size_t n_shaping_rules, int thread_seq)
{
	session_state_sync_in_activing(a_stream, TSG_SERVICE_SHAPING, shaping_rules, n_shaping_rules, thread_seq);
	srt_action_context_set_rule_method(a_stream, TSG_METHOD_TYPE_UNKNOWN, thread_seq);

	return 0;
}

int matched_intercept_rules_deal(const struct streaminfo *a_stream, struct maat_rule *intercept_rules, size_t n_intercept_rules, int thread_seq)
{
	struct maat_rule *p_rule=matched_rules_decision_criteria(intercept_rules, n_intercept_rules);
	session_state_sync_in_activing(a_stream, TSG_SERVICE_INTERCEPT, p_rule, 1, thread_seq);

	srt_action_context_set_rule_method(a_stream, TSG_METHOD_TYPE_UNKNOWN, thread_seq);

	return 0;
}

int matched_service_chaining_rules_deal(const struct streaminfo *a_stream, struct maat_rule *s_chaining_rules, size_t n_s_chaining_rules, int thread_seq)
{
	session_state_sync_in_activing(a_stream, TSG_SERVICE_CHAINING, s_chaining_rules, n_s_chaining_rules, thread_seq);
	srt_action_context_set_rule_method(a_stream, TSG_METHOD_TYPE_UNKNOWN, thread_seq);

	return 0;
}

unsigned char session_matched_rules_deal(const struct streaminfo *a_stream, struct session_runtime_process_context *srt_process_context, struct maat_rule *matched_rules, size_t n_matched_rules, const void *a_packet)
{
	int thread_seq=a_stream->threadnum;
	unsigned char state=APP_STATE_GIVEME;

	struct maat_rule security_rules[MAX_RESULT_NUM]={0};
	size_t n_security_rules=tsg_select_rules_by_service_id(matched_rules, n_matched_rules, security_rules, MAX_RESULT_NUM, TSG_SERVICE_SECURITY);
	if(n_security_rules>0)
	{
		state=matched_security_rules_deal(a_stream, srt_process_context, security_rules, n_security_rules, a_packet,thread_seq);
		if(state&APP_STATE_KILL_OTHER)
		{
			return state;
		}
	}
	
	struct maat_rule s_chaining_rules[MAX_RESULT_NUM]={0};
	size_t n_s_chaining_rules=tsg_select_rules_by_service_id(matched_rules, n_matched_rules, s_chaining_rules, MAX_RESULT_NUM, TSG_SERVICE_CHAINING);
	if(n_s_chaining_rules>0)
	{
		matched_service_chaining_rules_deal(a_stream, s_chaining_rules, n_s_chaining_rules, thread_seq);
	}
	
	struct maat_rule shaping_rules[MAX_RESULT_NUM]={0};
	size_t n_shaping_rules=tsg_select_rules_by_service_id(matched_rules, n_matched_rules, shaping_rules, MAX_RESULT_NUM, TSG_SERVICE_SHAPING);
	if(n_shaping_rules>0)
	{
		matched_shaping_rules_deal(a_stream, shaping_rules, n_shaping_rules, thread_seq);
	}

	struct maat_rule intercept_rules[MAX_RESULT_NUM]={0};
	size_t n_intercept_rules=tsg_select_rules_by_service_id(matched_rules, n_matched_rules, intercept_rules, MAX_RESULT_NUM, TSG_SERVICE_INTERCEPT);
	if(n_intercept_rules>0)
	{
		matched_intercept_rules_deal(a_stream, intercept_rules, n_intercept_rules, thread_seq);
	}

	struct maat_rule statistics_rules[MAX_RESULT_NUM];
	size_t n_statistics_rules=tsg_select_rules_by_service_id(matched_rules, n_matched_rules, statistics_rules, MAX_RESULT_NUM, TSG_SERVICE_STATISTICS);
	if(n_shaping_rules>0)
	{
		matched_statistics_rules_deal(a_stream, statistics_rules, n_statistics_rules, thread_seq);
	}

	return state;
}

int session_app_gather_results_update(struct app_attributes **update_result, char update_result_num, struct app_identify_result *identify_result, int packet_sequence, int thread_seq)
{
	if(identify_result->app_id_num<=0)
	{
		return 0;
	}

	if(*update_result==NULL)
	{
		(*update_result)=(struct app_attributes *)dictator_malloc(thread_seq, sizeof(struct app_attributes)*identify_result->app_id_num);
	}
	else
	{
		if((identify_result->app_id_num) > update_result_num)
		{
			(*update_result)=(struct app_attributes *)dictator_realloc(thread_seq, *update_result, sizeof(struct app_attributes)*identify_result->app_id_num);
		}
	}

	int idx=0;
	unsigned int quic_id=tsg_l7_protocol_name2id(g_tsg_proto_name2id[PROTO_QUIC].name, g_tsg_proto_name2id[PROTO_QUIC].len);
	for(int i=0; i<identify_result->app_id_num; i++)
	{	
		(*update_result)[idx].app_id=identify_result->origin;
		(*update_result)[idx].app_id=identify_result->app_id[i];
		(*update_result)[idx].surrogate_id=identify_result->surrogate_id[i];
		(*update_result)[idx].packet_sequence=packet_sequence;
		idx++;

		if(identify_result->app_id[i]==quic_id && (i+1 < identify_result->app_id_num))
		{
			unsigned int ssl_id=tsg_l7_protocol_name2id(g_tsg_proto_name2id[PROTO_SSL].name, g_tsg_proto_name2id[PROTO_SSL].len);
			if(identify_result->app_id[i+1]==ssl_id)
			{
				i++;
				continue;
			}
		}
	}

	return idx;
}

int session_app_identify_result_cb(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	if(data==NULL || a_stream->opstate==OP_STATE_CLOSE)
	{
		return 0;
	}

	struct session_runtime_process_context *srt_process_context=(struct session_runtime_process_context *)session_runtime_process_context_get(a_stream);
	if(srt_process_context==NULL)
	{
		srt_process_context=(struct session_runtime_process_context *)session_runtime_process_context_new(a_stream);
	}

	struct gather_app_result *gather_result=(struct gather_app_result *)session_gather_app_results_get(a_stream);
	if(gather_result==NULL)
	{
		gather_result=(struct gather_app_result *)dictator_malloc(a_stream->threadnum, sizeof(struct gather_app_result));
		memset(gather_result, 0, sizeof(struct gather_app_result));
		session_gather_app_results_async(a_stream, (void *)gather_result);
	}

	char scan_app_num=0;
	struct app_attributes *scan_app=NULL;
	struct app_identify_result *identify_result=(struct app_identify_result *)data;
	switch(identify_result->origin)
	{
			break;
		case	ORIGIN_QM_ENGINE:
			srt_process_context->is_app_link=FLAG_TRUE;
			tsg_stat_sync_application_update(SYNC_APP_THRID, 1);
			gather_result->qm_engine_num=session_app_gather_results_update(&(gather_result->qm_engine), gather_result->qm_engine_num, identify_result, get_packet_sequence(a_stream), a_stream->threadnum);

			scan_app=gather_result->qm_engine;
			scan_app_num=gather_result->qm_engine_num;
			break;
		case	ORIGIN_USER_DEFINE:
			srt_process_context->is_app_link=FLAG_TRUE;
			tsg_stat_sync_application_update(SYNC_APP_USER_DEFINE, 1);
			gather_result->user_define_num=session_app_gather_results_update(&(gather_result->user_define), gather_result->user_define_num, identify_result, get_packet_sequence(a_stream), a_stream->threadnum);

			scan_app=gather_result->user_define;
			scan_app_num=gather_result->user_define_num;
			break;
		case	ORIGIN_BUILT_IN:
			srt_process_context->is_app_link=FLAG_TRUE;
			tsg_stat_sync_application_update(SYNC_APP_BUILT_IN, 1);
			gather_result->built_in_num=session_app_gather_results_update(&(gather_result->built_in), gather_result->built_in_num, identify_result, get_packet_sequence(a_stream), a_stream->threadnum);

			scan_app=gather_result->built_in;
			scan_app_num=gather_result->built_in_num;
			break;
		case	ORIGIN_BASIC_PROTOCOL:
			srt_process_context->is_app_link=FLAG_TRUE;
			tsg_stat_sync_application_update(SYNC_APP_LPI, 1);
			if(srt_process_context->proto==PROTO_UNKONWN || srt_process_context->proto==PROTO_APP)
			{
				srt_process_context_set_l7_protocol(srt_process_context, identify_result->app_id[identify_result->app_id_num-1]);
			}
			gather_result->l7_protocol_num=session_app_gather_results_update(&(gather_result->l7_protocol), gather_result->l7_protocol_num, identify_result, get_packet_sequence(a_stream), a_stream->threadnum);
			
			scan_app=gather_result->l7_protocol;
			scan_app_num=gather_result->l7_protocol_num;
			break;
		case	ORIGIN_UNKNOWN:
			srt_process_context->is_app_link=FLAG_TRUE;

			gather_result->unknown_flag=1;
			gather_result->unknown.app_id=identify_result->app_id[0];
			gather_result->unknown.surrogate_id=identify_result->surrogate_id[0];
			gather_result->unknown.packet_sequence=get_packet_sequence(a_stream);

			scan_app=&(gather_result->unknown);
			scan_app_num=1;
			break;
		default:
			MASTER_LOG(g_tsg_para.logger, RLOG_LV_FATAL, LOG_MODULE_SYNC_APP, "Unknown type: %d addr: %s", identify_result->origin, printaddr(&(a_stream->addr), a_stream->threadnum));
			return 0;
	}

	char app_full_path[256]={0};
	session_application_full_path_update(a_stream, app_full_path, sizeof(app_full_path));
	if(strlen(app_full_path)>0)
	{
		session_dimension_application_sync(a_stream, app_full_path);
	}
	
	if(srt_process_context->mid==NULL)
	{
		return 0;
	}

	struct maat_rule rules[MAX_MATCHED_RULES_NUM]={0};
	srt_process_context->last_scan_time=tsg_get_current_time_ms();
	size_t matched_cnt=session_app_id_and_properties_scan((struct streaminfo *)a_stream, rules, MAX_MATCHED_RULES_NUM, srt_process_context, scan_app, scan_app_num, identify_result->origin, (int)a_stream->threadnum);

	srt_process_context->sync_cb_state=session_matched_rules_deal(a_stream, srt_process_context, rules, matched_cnt, get_this_layer_header(a_stream));
	return 0;
}

int session_flags_identify_result_cb(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	if(data==NULL || a_stream->opstate==OP_STATE_CLOSE)
	{
		return 0;
	}

	struct session_runtime_process_context *srt_process_context=(struct session_runtime_process_context *)session_runtime_process_context_get(a_stream);
	if(srt_process_context==NULL)
	{
		srt_process_context=(struct session_runtime_process_context *)session_runtime_process_context_new(a_stream);
	}

	srt_process_context->session_flag=*(unsigned long *)(data);
	srt_attribute_set_flags(a_stream, srt_process_context->session_flag);

	if(srt_process_context->mid==NULL)
	{
		return 0;
	}
	
	struct maat_rule rules[MAX_MATCHED_RULES_NUM]={0};
	size_t matched_cnt=tsg_scan_session_flags(a_stream, g_tsg_maat_feather, srt_process_context->session_flag, (srt_process_context->mid), rules, MAX_MATCHED_RULES_NUM);
	srt_process_context->sync_cb_state=session_matched_rules_deal(a_stream, srt_process_context, rules, matched_cnt, get_this_layer_header(a_stream));

	return 0;
}

static int session_ssl_ja3_fingerprint_generate(const struct streaminfo *a_stream)
{
	char ja3_fingerprint[64]={0};
	int ja3_fingerprint_len=tsg_ssl_ja3_fingerprint_generate((unsigned char *)a_stream->ptcpdetail->pdata, (unsigned int)a_stream->ptcpdetail->datalen, ja3_fingerprint, sizeof(ja3_fingerprint), a_stream->threadnum);
	if(ja3_fingerprint_len>0)
	{
		srt_attribute_set_ja3_fingprint(a_stream, ja3_fingerprint, ja3_fingerprint_len);
		return 1;
	}

	return 0;
}

size_t session_pending_state_deal(const struct streaminfo *a_stream, struct session_runtime_process_context *srt_process_context, struct maat_rule *matched_rules, int n_matched_rules, void *a_packet)
{
	size_t matched_cnt=0;
	int ret=session_l7_protocol_identify(a_stream, srt_process_context, a_packet);
	if(ret==1)
	{
		int n_offset=0;
		unsigned int app_id[4]={0,0,0,0};
		unsigned int protocol_id=tsg_l7_protocol_name2id(g_tsg_proto_name2id[srt_process_context->proto].name, g_tsg_proto_name2id[srt_process_context->proto].len);
		if(protocol_id!=0)
		{
			app_id[n_offset++]=protocol_id;
		}
		srt_process_context->is_app_link=FLAG_TRUE;
		srt_attribute_set_protocol(a_stream, srt_process_context->proto);

		if(srt_process_context->proto==PROTO_SSL && g_tsg_para.generate_ja3_fingerprint==1)
		{
			session_ssl_ja3_fingerprint_generate(a_stream);
		}
		
		if(srt_process_context->domain!=NULL)
		{
			int table_idx=tsg_domain_table_idx_get(srt_process_context->proto);
			matched_cnt+=tsg_scan_shared_policy(a_stream, g_tsg_maat_feather, srt_process_context->domain, table_idx, (srt_process_context->mid), matched_rules+matched_cnt, n_matched_rules-matched_cnt);
			
			struct session_runtime_attribute *srt_attribute=(struct session_runtime_attribute *)session_runtime_attribute_new(a_stream);
			srt_attribute->n_fqdn_category_ids=tsg_get_fqdn_category_ids(g_tsg_maat_feather, srt_process_context->domain, srt_attribute->fqdn_category_ids, MAX_CATEGORY_ID_NUM);

			session_dimension_server_fqdn_sync(a_stream, srt_process_context->domain);
			session_dimension_category_id_sync(a_stream, srt_attribute->fqdn_category_ids, srt_attribute->n_fqdn_category_ids);

			table_idx=tsg_fqdn_category_table_idx_get(srt_process_context->proto);
			if(srt_attribute!=NULL && table_idx>=0)
			{
				matched_cnt+=tsg_scan_fqdn_category_id(a_stream,
														g_tsg_maat_feather,
														srt_attribute->fqdn_category_ids,
														srt_attribute->n_fqdn_category_ids,
														table_idx,
														srt_process_context->mid,
														matched_rules+matched_cnt,
														n_matched_rules-matched_cnt
													);
			}
		}

		if(srt_process_context->is_esni)
		{
			protocol_id=tsg_l7_protocol_name2id("ESNI", 4);
			if(protocol_id!=0)
			{
				app_id[n_offset++]=protocol_id;
				matched_cnt+=tsg_scan_app_id_policy(a_stream, g_tsg_maat_feather, protocol_id, (srt_process_context->mid), matched_rules+matched_cnt, n_matched_rules-matched_cnt);
			}
		}
		
		if(srt_process_context->is_ech)
		{
			protocol_id=tsg_l7_protocol_name2id("ECH", 3);
			if(protocol_id!=0)
			{
				app_id[n_offset++]=protocol_id;
				matched_cnt+=tsg_scan_app_id_policy(a_stream, g_tsg_maat_feather, protocol_id, (srt_process_context->mid), matched_rules+matched_cnt, n_matched_rules-matched_cnt);
			}
		}

		if(srt_process_context->proto==PROTO_HTTP && srt_process_context->http_url!=NULL)
		{
			int table_idx=tsg_http_url_table_idx_get();
			matched_cnt+=tsg_scan_shared_policy(a_stream, g_tsg_maat_feather, srt_process_context->http_url, table_idx, (srt_process_context->mid), matched_rules+matched_cnt, n_matched_rules-matched_cnt);
		}

		session_app_gather_results_set_l7_protocol(a_stream, app_id, n_offset);
	}

	ret=tsg_scan_nesting_addr(a_stream, g_tsg_maat_feather, srt_process_context->proto, (srt_process_context->mid), matched_rules+matched_cnt, n_matched_rules-matched_cnt);
	if(ret>0)
	{
		matched_cnt+=ret;
	}

	matched_cnt+=session_app_gather_results_scan(a_stream, matched_rules+matched_cnt, n_matched_rules-matched_cnt, srt_process_context, a_stream->threadnum);
	matched_cnt+=tsg_scan_session_flags(a_stream, g_tsg_maat_feather, srt_process_context->session_flag, (srt_process_context->mid), matched_rules+matched_cnt, n_matched_rules-matched_cnt);
	
	if((is_only_monitor(matched_rules, matched_cnt)) && srt_process_context->proto==PROTO_DNS)	// business deal action of monitor 
	{
		MASTER_LOG(g_tsg_para.logger, RLOG_LV_DEBUG, LOG_MODULE_PENDING, "is_only_monitor, clean hit_num to 0, :%s", printaddr(&(a_stream->addr), a_stream->threadnum));
		matched_cnt=0;
	}

	return matched_cnt;
}

static unsigned char tsg_master_data_entry(const struct streaminfo *a_stream, void **pme, int thread_seq,void *a_packet)
{
	size_t matched_cnt=0;
	unsigned char state=APP_STATE_GIVEME;
	int n_matched_rules=MAX_MATCHED_RULES_NUM;
	struct maat_rule matched_rules[MAX_MATCHED_RULES_NUM];
	struct session_runtime_process_context *srt_process_context=(struct session_runtime_process_context *)*pme;

	if(*pme==NULL)
	{
		srt_process_context=(struct session_runtime_process_context *)session_runtime_process_context_get(a_stream);
		if(srt_process_context==NULL)
		{
			srt_process_context=(struct session_runtime_process_context *)session_runtime_process_context_new(a_stream);
			*pme=(void *)srt_process_context;
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

	if(srt_process_context->first_origin_pkt==0)
	{
		srt_process_context->first_origin_pkt=1;
		
		matched_cnt+=session_pending_state_deal(a_stream, srt_process_context, matched_rules+matched_cnt, n_matched_rules-matched_cnt, a_packet);
		if (a_stream->type == STREAM_TYPE_TCP && a_packet != NULL)
		{
			tsg_proxy_tcp_options_parse(a_stream, a_packet);
		}
		state=session_matched_rules_deal(a_stream, srt_process_context, matched_rules, matched_cnt, a_packet);
		srt_process_context->deal_pkt_num++;

		srt_attribute_free_proxy_tcp_option(a_stream);
	}
	
	switch(a_stream->opstate)
	{
		case	OP_STATE_DATA:
			if(srt_process_context->is_app_link==FLAG_FALSE && (srt_process_context->deal_pkt_num++) == (g_tsg_para.identify_app_max_pkt_num+1))
			{
				struct app_identify_result unknown_result;
				unknown_result.app_id_num=1;
				unknown_result.surrogate_id[0]=0;
				unknown_result.origin=ORIGIN_UNKNOWN;
				unknown_result.app_id[0]=g_tsg_para.unknown_app_id;
		
				session_app_identify_result_cb(a_stream, 0, (void *)&unknown_result);
			}
		
			if(srt_process_context->is_hitted_allow)
			{
				state=APP_STATE_GIVEME;
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
				maat_state_reset(srt_process_context->mid);
			}
			
			srt_process_context->last_scan_time=tsg_get_current_time_ms();
			int ret=tsg_scan_nesting_addr(a_stream, g_tsg_maat_feather, srt_process_context->proto, (srt_process_context->mid), matched_rules+matched_cnt, n_matched_rules-matched_cnt);
			if(ret>0)
			{
				matched_cnt+=ret;
			}
			
			matched_cnt+=session_app_gather_results_scan(a_stream, matched_rules+matched_cnt, n_matched_rules-matched_cnt, srt_process_context, thread_seq);

			if(srt_process_context->session_flag>0)
			{
				matched_cnt+=tsg_scan_session_flags(a_stream, g_tsg_maat_feather, srt_process_context->session_flag, (srt_process_context->mid), matched_rules+matched_cnt, n_matched_rules-matched_cnt);
			}
			
			state=session_matched_rules_deal(a_stream, srt_process_context, matched_rules, matched_cnt, a_packet);
			break;
	}
	
	session_dimension_maat_state_sync(a_stream, srt_process_context->mid);
		
	if((a_stream->opstate==OP_STATE_CLOSE) || (state&APP_STATE_DROPME)==APP_STATE_DROPME)
	{
		// session record sendlog
		//session_runtime_process_context_free(a_stream);

		maat_state_free(srt_process_context->mid);
		srt_process_context->mid=NULL;

		*pme=NULL;
	}

	return state;
}

static unsigned char tsg_master_all_entry(const struct streaminfo *a_stream, unsigned char stream_state, void **pme, int thread_seq, const void *a_packet)
{
	unsigned char state=APP_STATE_GIVEME;
	struct session_runtime_action_context *srt_action_context=(struct session_runtime_action_context *)(*pme);

	if(stream_state==OP_STATE_PENDING && srt_action_context->method_type!=TSG_METHOD_TYPE_SHUNT && !(srt_action_context->udp_data_dropme))
	{
		if(srt_action_context->method_type==TSG_METHOD_TYPE_UNKNOWN)
		{
			srt_action_context->method_type=TSG_METHOD_TYPE_DEFAULT;
			srt_action_context->default_policy_after_n_packets=get_default_para(a_stream);
		}

		if(g_tsg_para.scan_in_pkt_state==0)
		{
			return state;
		}

		struct maat_state *scan_mid=maat_state_new(g_tsg_maat_feather, thread_seq);
		size_t n_matched_rules=MAX_MATCHED_RULES_NUM;
		struct maat_rule matched_rules[MAX_MATCHED_RULES_NUM];
		int matched_cnt=tsg_scan_nesting_addr(a_stream, g_tsg_maat_feather, PROTO_UNKONWN, scan_mid, matched_rules, n_matched_rules);
		if(matched_cnt>0)
		{
			struct maat_rule security_rules[MAX_RESULT_NUM];
			int n_security_rules=tsg_select_rules_by_service_id(matched_rules, matched_cnt, security_rules, MAX_RESULT_NUM, TSG_SERVICE_SECURITY);
			if(n_security_rules>0)
			{
				struct session_runtime_process_context *srt_process_context=(struct session_runtime_process_context *)session_runtime_process_context_new(a_stream);
				state=matched_security_rules_deal(a_stream, srt_process_context, security_rules, n_security_rules, a_packet, thread_seq);
			}
			
			struct maat_rule s_chaining_rules[MAX_RESULT_NUM];
			size_t n_s_chaining_rules=tsg_select_rules_by_service_id(matched_rules, matched_cnt, s_chaining_rules, MAX_RESULT_NUM, TSG_SERVICE_CHAINING);
			if(state==APP_STATE_GIVEME && n_s_chaining_rules>0)
			{
				matched_service_chaining_rules_deal(a_stream, s_chaining_rules, n_s_chaining_rules, thread_seq);
			}

			struct maat_rule shaping_rules[MAX_RESULT_NUM];
			size_t n_shaping_rules=tsg_select_rules_by_service_id(matched_rules, matched_cnt, shaping_rules, MAX_RESULT_NUM, TSG_SERVICE_SHAPING);
			if(state==APP_STATE_GIVEME && n_shaping_rules>0)
			{
				matched_shaping_rules_deal(a_stream, shaping_rules, n_shaping_rules, thread_seq);
			}

			struct maat_rule statistics_rules[MAX_RESULT_NUM];
			size_t n_statistics_rules=tsg_select_rules_by_service_id(matched_rules, matched_cnt, statistics_rules, MAX_RESULT_NUM, TSG_SERVICE_STATISTICS);
			if(state==APP_STATE_GIVEME && n_statistics_rules>0)
			{
				matched_statistics_rules_deal(a_stream, statistics_rules, n_statistics_rules, thread_seq);
			}
		}
		
		session_dimension_maat_state_sync(a_stream, scan_mid);
		maat_state_free(scan_mid);
		scan_mid=NULL;
	}

	switch(srt_action_context->method_type)
	{
		case	TSG_METHOD_TYPE_RATE_LIMIT:
			{
				int eth_rawpkt_len=get_raw_packet_len(a_stream);
				if(eth_rawpkt_len<=0)
				{
					break;
				}

				if((is_permit_pass(eth_rawpkt_len*8, srt_action_context->bucket, thread_seq))==0)
				{
					state|=APP_STATE_GIVEME|APP_STATE_DROPPKT;
				}
			}
			break;
		case    TSG_METHOD_TYPE_TAMPER:
			if(0 == send_tamper_xxx(a_stream, &srt_action_context->tamper_count, a_packet))
			{
				state|=APP_STATE_GIVEME|APP_STATE_DROPPKT;
			}
			break;
		case	TSG_METHOD_TYPE_DEFAULT:
			{
				if(!is_do_default_policy(a_stream, srt_action_context->default_policy_after_n_packets) || stream_state==OP_STATE_CLOSE)
				{
					break;
				}

				struct maat_rule default_rules;
				if(get_default_policy(&default_rules))
				{
					state=tsg_enforing_deny(a_stream, &default_rules, PROTO_UNKONWN, ACTION_RETURN_TYPE_TCPALL, a_packet);
					session_matched_rules_notify(a_stream, TSG_SERVICE_SECURITY, &default_rules, 1, thread_seq);
				}
			}
			break;
		case	TSG_METHOD_TYPE_DROP:
		case	TSG_METHOD_TYPE_APP_DROP:
			{
				// contain hited current packet, platform calls tcp first and tcpall secondary.
				if(((srt_action_context->hited_para.after_n_packets > 0) && a_stream->type==STREAM_TYPE_TCP) ||
					((srt_action_context->hited_para.after_n_packets > 0) && a_stream->type==STREAM_TYPE_UDP)
					|| stream_state==OP_STATE_CLOSE)
				{			
					srt_action_context->hited_para.after_n_packets--;
					break;
				}
					
				struct maat_rule matched_rules;
				int ret=session_matched_rules_copy(a_stream, TSG_SERVICE_SECURITY, &(matched_rules), 1);
				//ret=tsg_pull_policy_result((struct streaminfo *)a_stream,PULL_FW_RESULT, &security_result[0], 1, &tmp_identify_info);
				if(ret<=0 || matched_rules.action!=TSG_ACTION_DENY)
				{
					break;
				}

				if(srt_action_context->hited_para.matched_app_id<=0)
				{
					state=tsg_enforing_deny(a_stream, &matched_rules, srt_action_context->protocol, ACTION_RETURN_TYPE_TCPALL, a_packet);
				}
				else
				{
					state=tsg_enforing_deny_application(a_stream, &matched_rules, srt_action_context->protocol, srt_action_context->hited_para.matched_app_id, ACTION_RETURN_TYPE_TCPALL, a_packet);
				}
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
	int is_ctrl_pkt=session_state_control_packet(a_tcp, a_tcp->pudpdetail->pdata, a_tcp->pudpdetail->datalen);
	if(is_ctrl_pkt==1)
	{
		return APP_STATE_DROPPKT;
	}

	return tsg_master_data_entry(a_tcp, pme, thread_seq, a_packet);
}

extern "C" unsigned char TSG_MASTER_UDP_ENTRY(const struct streaminfo *a_udp, void **pme, int thread_seq,void *a_packet)
{
	unsigned char state1=APP_STATE_GIVEME;
	unsigned char state2=APP_STATE_GIVEME;
	struct udp_session_runtime_context *udp_srt_context=(struct udp_session_runtime_context *)(*pme);

	int is_ctrl_pkt=session_state_control_packet(a_udp, a_udp->pudpdetail->pdata, a_udp->pudpdetail->datalen);
	if(is_ctrl_pkt==1)
	{
		return APP_STATE_DROPPKT;
	}

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

		udp_srt_context->srt_action_context=(struct session_runtime_action_context *)session_runtime_action_context_get(a_udp);
		if(udp_srt_context->srt_action_context==NULL)
		{
			udp_srt_context->srt_action_context=(struct session_runtime_action_context *)session_runtime_action_context_new(a_udp);
		}
		
		udp_srt_context->srt_action_context->last_update_metric_time = tsg_get_current_time_ms();
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
		udp_srt_context->srt_action_context->state=(state1|state2);
		session_application_metrics_update(a_udp, udp_srt_context->srt_action_context, thread_seq);
		dictator_free(thread_seq, *pme);
		*pme=NULL;

		session_state_sync_in_opening_and_closing(a_udp, a_udp->opstate);
	}
	else
	{
		session_application_metrics_update(a_udp, udp_srt_context->srt_action_context, thread_seq);
	}
	
	return (state1|state2);
}

extern "C" unsigned char TSG_MASTER_TCPALL_ENTRY(const struct streaminfo *a_tcp, void **pme, int thread_seq, const void *a_packet)
{
	struct session_runtime_action_context *srt_action_context=(struct session_runtime_action_context *)(*pme);

	int is_ctrl_pkt=session_state_control_packet(a_tcp, a_tcp->ptcpdetail->pdata, a_tcp->ptcpdetail->datalen);
	if(is_ctrl_pkt==1)
	{
		return APP_STATE_DROPPKT;
	}
	
	if(*pme==NULL)
	{
		session_state_sync_in_opening_and_closing(a_tcp, a_tcp->pktstate);
		*pme=(void *)session_runtime_action_context_get(a_tcp);
		if(*pme==NULL)
		{
			srt_action_context=(struct session_runtime_action_context *)session_runtime_action_context_new(a_tcp);
			*pme=(void *)srt_action_context;
		}
		
		srt_action_context->direction=get_direction(a_tcp);
		srt_action_context->last_update_metric_time = tsg_get_current_time_ms();
	}

	if(srt_action_context->set_latency_flag==0)
	{
		srt_action_context->set_latency_flag=session_tcp_establish_latency_ms_set(a_tcp, thread_seq, a_packet);
	}

	if (a_packet!=NULL)
	{
		tsg_proxy_tcp_options_parse(a_tcp, a_packet);
	}
	
	unsigned char state=tsg_master_all_entry(a_tcp, a_tcp->pktstate, pme, thread_seq, a_packet);

	if(state&APP_STATE_DROPME || a_tcp->pktstate==OP_STATE_CLOSE)
	{
		srt_action_context->state=state;
		session_application_metrics_update(a_tcp, srt_action_context, thread_seq);
		session_state_sync_in_opening_and_closing(a_tcp, a_tcp->pktstate);
	}
	else
	{
		session_application_metrics_update(a_tcp, srt_action_context, thread_seq);
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

	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "APP_METRICS_INTERVAL", &g_tsg_para.app_metric_update_interval_ms, 30000);
	
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "FEATURE_TAMPER", &g_tsg_para.feature_tamper, 0);
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "SERVICE_CHAINING_SID", &g_tsg_para.service_chaining_sid, 0);
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "SHAPING_SID", &g_tsg_para.shaping_sid, 0);
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "PROXY_SID", &g_tsg_para.intercept_sid, 0);

	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "SCAN_IN_PACKET_STATE", &g_tsg_para.scan_in_pkt_state, 1);
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "GENERATE_JA3_FINGERPRINT", &g_tsg_para.generate_ja3_fingerprint, 0);

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
		MASTER_LOG(g_tsg_para.logger, RLOG_LV_FATAL, LOG_MODULE_INIT, "Get device SN failed; please check :%s", device_sn_filename);
	}

	ret=device_id_set_telegraf(g_tsg_para.device_sn);
	if(ret<0)
	{
		MASTER_LOG(g_tsg_para.logger, RLOG_LV_FATAL, LOG_MODULE_INIT, "Set device SN(%s) failed; please check :%s", g_tsg_para.device_sn, "/etc/default/telegraf");
	}

	ret=tsg_bridge_init(tsg_conffile);
	if(ret<0)
	{
		return -1;
	}

	init_page_template(tsg_conffile);
	tsg_stat_create(tsg_conffile);
	tsg_stat_init();

	ret=tsg_maat_rule_init(tsg_conffile);
	if(ret<0)
	{
		MASTER_LOG(g_tsg_para.logger, RLOG_LV_FATAL, LOG_MODULE_INIT, "tsg_maat_rule_init failed ...");
		return -1;
	}
	
	g_tsg_log_instance=tsg_sendlog_init(tsg_conffile);
	if(g_tsg_log_instance==NULL)
	{
		MASTER_LOG(g_tsg_para.logger, RLOG_LV_FATAL, LOG_MODULE_INIT, "tsg_sendlog_init failed ...");
		return -1;
	}

	// wait send log topic statistic
	tsg_stat_start();
	
	ret=tsg_metric_init(tsg_conffile, g_tsg_para.logger);
	if(ret<0)
	{MASTER_LOG(g_tsg_para.logger, RLOG_LV_FATAL, LOG_MODULE_INIT, "tsg_metric_init failed ...");
		return -1;
	}

	l7_protocol_mapper_init(tsg_conffile);

	ret=tsg_gtp_signaling_hash_init(tsg_conffile, g_tsg_para.logger);
	if(ret<0)
	{
		MASTER_LOG(g_tsg_para.logger, RLOG_LV_FATAL, LOG_MODULE_INIT, "tsg_gtp_signaling_hash_init failed ...");
		return -1;
	}

	g_tsg_para.send_resetall=0;

	return 0;
}

extern "C" int TSG_MASTER_UNLOAD()
{

		
	ctemplate::Template::ClearCache();
	//delete g_tsg_para.tpl_403;
	//delete g_tsg_para.tpl_404;
	//delete g_tsg_para.tpl_200;
	//delete g_tsg_para.tpl_204;
	tsg_sendlog_destroy(g_tsg_log_instance);
	tsg_metric_destroy();

	free_l7_protocol_mapper();

	tsg_maat_rule_destroy();

	tsg_gtp_signaling_hash_destroy();
	MESA_destroy_runtime_log_handle(g_tsg_para.logger);
	g_tsg_para.logger = NULL;
	return 0;
}
