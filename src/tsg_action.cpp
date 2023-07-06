#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <unistd.h>
#include <netinet/ip6.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <MESA/http.h>
#include <MESA/ftp.h>
#include <MESA/ssl.h>
#include <MESA/mail.h>
#include <MESA/quic.h>
#include "MESA/sip.h"
#include <MESA/stream.h>
#include <MESA/MESA_handle_logger.h>

#include "app_label.h"
#include "tsg_rule.h"
#include "tsg_entry.h"
#include "tsg_statistic.h"
#include "tsg_send_log.h"
#include "tsg_protocol_common.h"

extern "C" int sendpacket_do_checksum(unsigned char *buf, int protocol, int len);

static int replace_policy_variable(const struct streaminfo *a_stream, ctemplate::TemplateDictionary *tpl_dict, int policy_id)
{
	char ip_str[128]={0};
	struct session_attribute_label *attr_label=NULL;
	
	tpl_dict->SetIntValue("tsg_policy_id", policy_id);

	attr_label=(struct session_attribute_label *)project_req_get_struct(a_stream, g_tsg_para.session_attribute_project_id);
	if(attr_label!=NULL && attr_label->client_subscribe_id!=NULL)
	{
		tpl_dict->SetFormattedValue("tsg_subscriber_id", "%s", attr_label->client_subscribe_id->subscribe_id);
	}
	else
	{
		tpl_dict->SetFormattedValue("tsg_subscriber_id", "%s", "");
	}


	switch(a_stream->addr.addrtype)
	{
		case	ADDR_TYPE_IPV4: 			
			inet_ntop(AF_INET, (const void *)&(a_stream->addr.ipv4->saddr), ip_str, sizeof(ip_str));
			tpl_dict->SetFormattedValue("tsg_client_ip", "%s", ip_str);
			break;
		case	ADDR_TYPE_IPV6: 			
			inet_ntop(AF_INET6, (const void *)(a_stream->addr.ipv6->saddr), ip_str, sizeof(ip_str));
			tpl_dict->SetFormattedValue("tsg_client_ip", "%s", ip_str);
			break;
		default:
			tpl_dict->SetFormattedValue("tsg_client_ip", "%s", "");
			break;
	}

	return 0;
}

static int set_drop_stream(const struct streaminfo *a_stream, tsg_protocol_t protocol)
{
	int ret=0, opt_value=1;
	MESA_set_stream_opt(a_stream, MSO_DROP_STREAM, (void *)&opt_value, sizeof(opt_value));
	MESA_set_stream_opt(a_stream, MSO_DROP_CURRENT_PKT, (void *)&opt_value, sizeof(opt_value));

	switch(protocol)
	{
		case	PROTO_MAIL:
		case	PROTO_POP3:
		case	PROTO_SMTP:
		case	PROTO_IMAP:
		case	PROTO_FTP:
				ret=MESA_set_stream_opt(a_stream, MSO_TIMEOUT, (void *)&g_tsg_para.timeout, sizeof(g_tsg_para.timeout));
				if(ret<0)
				{
					FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_SET_TIMOUT_FAILED], 0, FS_OP_ADD, 1); 		
				}
				else
				{
					FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_SET_TIMOUT_SUCCESS], 0, FS_OP_ADD, 1);
				}
			break;
		default:
			break;
	}

	return STATE_DROPME|STATE_DROPPKT;				
}

static int set_dropme_flag(const struct streaminfo *a_stream)
{	
	struct master_context *_context=(struct master_context *)get_struct_project(a_stream, g_tsg_para.context_project_id);
	if(_context!=NULL)
	{
		_context->is_dropme=1;
	}

	return 0;
}

static int get_http_header(char *buff, int len, int code, char *user_define)
{
	int used_len=0;
	
	switch(code)
	{
		case	200:
			used_len=snprintf(buff, len, "HTTP/1.1 %d OK\r\nContent-Type: text/html\r\n\r\n", code);
			break;
		case	204:
			used_len=snprintf(buff, len, "HTTP/1.1 %d No Content\r\nContent-Type: text/html\r\n\r\n", code);
			break;
		case	403:
			used_len=snprintf(buff, len, "HTTP/1.1 %d Forbidden\r\nContent-Type: text/html\r\n\r\n", code);
			break;
		case	404:
			used_len=snprintf(buff, len, "HTTP/1.1 %d Not Found\r\nContent-Type: text/html\r\n\r\n", code);
			break;
		case	302:			
			used_len=snprintf(buff, len, "HTTP/1.1 %d Moved Temporarily\r\nContent-Type: text/html\r\nLocation: %s\r\n\r\n", code, user_define);
			break;
		case	303:			
			used_len=snprintf(buff, len, "HTTP/1.1 %d See Other\r\nLocation: %s\r\n\r\n", code, user_define);
			break;
		default:
			break;
	}

	return used_len;
}

static int get_tcp_mss_option(const struct streaminfo *a_stream, int type, void *out)
{
	int i=0,ret=0;
	int tcp_opt_num=0;
	struct tcp_option *tcp_opt=NULL;
	
	ret=MESA_get_stream_opt(a_stream, MSO_TCP_SYN_OPT, (void *)&tcp_opt, &tcp_opt_num);
	if(ret>0)
	{
		for(i=0; i<tcp_opt_num; i++)
		{
			if(tcp_opt[i].type!=type)
			{
				continue;
			}
			
			switch(tcp_opt[i].type)
			{
				case	TCP_OPT_MSS:
					*(short *)out=tcp_opt[i].short_value;
					return 1;
					break;
				default:
					break;
			}
		}
	}				

	return 0;
}

static void template_generate(const struct streaminfo *a_stream, int status_code, int policy_id, const char* message, char **page_buff, size_t *page_size, int thread_seq)
{
	int used_len=0;
	char *tmp_buff=NULL;
	std::string page_output, msg_output;
	ctemplate::Template *tpl=NULL;
	ctemplate::TemplateDictionary dict("pg_page_dict");	//dict is automatically finalized after function returned.

	if(message!=NULL)
	{		
		ctemplate::Template *tpl_message=ctemplate::Template::StringToTemplate(message, strlen(message), ctemplate::DO_NOT_STRIP);
		if(tpl_message!=NULL)
		{
			ctemplate::TemplateDictionary dict_msg("msg_dict");	//dict is automatically finalized after function returned.

			replace_policy_variable(a_stream, &dict_msg, policy_id);
			
			tpl_message->Expand(&msg_output, &dict_msg);

			used_len=msg_output.length();
			tmp_buff=(char *)dictator_malloc(a_stream->threadnum, (used_len+1)*sizeof(char));
			memcpy(tmp_buff, msg_output.c_str(), used_len);
			tmp_buff[used_len]='\0';

			dict.SetValue("msg", tmp_buff);

			dictator_free(thread_seq, tmp_buff);
			tmp_buff=NULL;

		}
		else
		{
			dict.SetValue("msg", message);
		}
	}
	else
	{
		dict.SetValue("msg", "NULL");
	}	

	switch (status_code)
	{
		case 403:
			tpl = g_tsg_para.tpl_403;
			tpl->Expand(&page_output, &dict);
			break;
		case 404: 
			tpl = g_tsg_para.tpl_404;
			tpl->Expand(&page_output, &dict);
			break;
		case 200: 
			tpl = g_tsg_para.tpl_200;
			tpl->Expand(&page_output, &dict);
			break;
		case 204: 
			tpl = g_tsg_para.tpl_204;
			tpl->Expand(&page_output, &dict);
			break;
		case 303:
			tpl = g_tsg_para.tpl_303;
			tpl->Expand(&page_output, &dict);
			break;
		default: return;
	}
	
	*page_size=page_output.length()+1;
	char *_page_buff=(char *)dictator_malloc(thread_seq, (*page_size)*sizeof(char));
	memcpy(_page_buff, page_output.c_str(), *page_size);
	*page_buff=_page_buff;
	
	return ;
}

static int get_response_pages(const struct streaminfo *a_stream, struct Maat_rule_t *p_result, struct compile_user_region *user_region, char **payload, int thread_seq)
{
	char key[16]={0};
	int payload_len=0;
	struct http_response_pages *res_pages=NULL;

	switch(user_region->deny->type)
	{
		case	TSG_DENY_TYPE_MESSAGE:
			template_generate(a_stream, user_region->deny->code, p_result->config_id, user_region->deny->message, payload, (size_t *)&payload_len, thread_seq);
			return payload_len;
			break;
		case	TSG_DENY_TYPE_PROFILE:
			break;
		default:
			break;
	}

	snprintf(key, sizeof(key), "%d", user_region->deny->profile_id);
	res_pages=(struct http_response_pages *)Maat_plugin_get_EX_data(g_tsg_maat_feather,g_tsg_para.table_id[TABLE_RESPONSE_PAGES], key);
	if(res_pages!=NULL)
	{
		switch(res_pages->format)
		{
			case	HTTP_RESPONSE_FORMAT_HTML:
				*payload=(char *)dictator_malloc(thread_seq, res_pages->content_len);
				memcpy(*payload, res_pages->content, res_pages->content_len);
				payload_len=res_pages->content_len;
				break;
			case	HTTP_RESPONSE_FORMAT_TEMPLATE:
				template_generate(a_stream, user_region->deny->code, p_result->config_id, res_pages->content, payload, (size_t *)&payload_len, thread_seq);
				break;
			default:
				break;
		}

		http_response_pages_free(g_tsg_para.table_id[TABLE_RESPONSE_PAGES], (MAAT_PLUGIN_EX_DATA *)&res_pages, 0, NULL);
	}

	return payload_len;
}

static int set_tcp_rst_flags(char *packet, int ip_tcp_hdr_len)
{	
	struct tcphdr *tcp=(struct tcphdr *)(packet+(ip_tcp_hdr_len-20));  // tcp header=20 bytes

	tcp->rst=1;
	tcp->ack=1;	
	tcp->psh=0;
	tcp->fin=0;

	return 0;
}

static int set_tcp_fin_flags(char *packet, int ip_tcp_hdr_len)
{	
	struct tcphdr *tcp=(struct tcphdr *)(packet+(ip_tcp_hdr_len-20));  // tcp header=20 bytes

	tcp->fin=1;	
	tcp->ack=1;
	tcp->psh=0;
	tcp->rst=0;

	return 0;
}

static int reverse_ip_tcp_header(char *message, int ip_tcp_hdr_len, int v4_or_v6)
{	
	int ip_hdr_len=0;
	struct tcphdr *tcp=NULL;
	struct iphdr *ipv4=NULL;
	struct ip6_hdr *ipv6=NULL;
	struct in6_addr ipv6_addr;
	unsigned short port=0;	
	unsigned int seq=0,addr=0;

	switch(v4_or_v6)
	{
		case	4:
			ipv4=(struct iphdr *)message;
			ip_hdr_len=ipv4->ihl*4;

			addr=ipv4->saddr;
			ipv4->saddr=ipv4->daddr;
			ipv4->daddr=addr;
			break;
		case	6:
			ipv6=(struct ip6_hdr *)message;
			ip_hdr_len=sizeof(struct ip6_hdr);

			memcpy((void *)&ipv6_addr, (void *)&(ipv6->ip6_src), sizeof(struct in6_addr));
			memcpy((void *)&(ipv6->ip6_src), (void *)&(ipv6->ip6_dst), sizeof(struct in6_addr));
			memcpy((void *)&(ipv6->ip6_dst), (void *)&ipv6_addr, sizeof(struct in6_addr));
			break;
		default:
			return -1;
			break;
	}

	tcp=(struct tcphdr *)((char *)message+ip_hdr_len);
	port=tcp->source;
	tcp->source=tcp->dest;
	tcp->dest=port;

	seq=tcp->seq;
	tcp->seq=tcp->ack_seq;
	tcp->ack_seq=seq;

	return 0;
}

static int copy_ip_tcp_header(const struct streaminfo *a_stream, const void *a_packet, char *message, int *ip_tcp_hdr_len, int *v4_or_v6)
{
	int ip_hdr_len=0,tcp_hdr_len=0;
	int tcp_hdr_len_tmp=0;
	unsigned short total_len=0;

	struct iphdr *ipv4=NULL;
	struct ip6_hdr *ipv6=NULL;

	switch(a_stream->addr.addrtype)
	{
		case	ADDR_TYPE_IPV4:
		case	__ADDR_TYPE_IP_PAIR_V4:
			(*v4_or_v6)=4;
			ipv4=(struct iphdr *)a_packet;
			ip_hdr_len=ipv4->ihl*4;
			total_len=ipv4->tot_len;
			break;
		case	ADDR_TYPE_IPV6:
		case	__ADDR_TYPE_IP_PAIR_V6:
			(*v4_or_v6)=6;
			ipv6=(struct ip6_hdr *)a_packet;
			ip_hdr_len=sizeof(struct ip6_hdr);
			total_len=ipv6->ip6_ctlun.ip6_un1.ip6_un1_plen;
			break;
		default:
			return -1;
			break;
	}

	memcpy(message, a_packet, ip_hdr_len);
	
	struct tcphdr * tcp=(struct tcphdr *)((char *)a_packet+ip_hdr_len);
	tcp_hdr_len_tmp=tcp->doff*4;
	tcp_hdr_len=20;

	memcpy(message+ip_hdr_len, (char *)a_packet+ip_hdr_len, tcp_hdr_len);/*skip tcp option*/
	tcp=(struct tcphdr *)((char *)message+ip_hdr_len);
	tcp->doff=5;

	if((*v4_or_v6)==4)
	{
		tcp->seq=(unsigned int)htonl((unsigned int)ntohl(tcp->seq)+ntohs(total_len)-ip_hdr_len-tcp_hdr_len_tmp);	// length of packet payload
	}
	else
	{
		tcp->seq=(unsigned int)htonl((unsigned int)ntohl(tcp->seq)+ntohs(total_len)-tcp_hdr_len_tmp);	// length of packet payload
	}
	
	(*ip_tcp_hdr_len)=ip_hdr_len+tcp_hdr_len;

	return 0;
}

int tsg_send_inject_packet(const struct streaminfo *a_stream, enum sapp_inject_opt sio, char *payload, int payload_len, unsigned char raw_route_dir)
{
	int ret=0;
	if(payload==NULL || payload_len<=0)
	{
		return -1;
	}

	ret=sapp_inject_pkt((struct streaminfo *)a_stream, sio, payload, payload_len, raw_route_dir);
	if(ret<=0)
	{
		FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_INJECT_PKT_FAILED], 0, FS_OP_ADD, 1); 
		return -1;	
	}

	FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_INJECT_PKT_SUCCESS], 0, FS_OP_ADD, 1); 
	
	return 0;
}

static int http_send_reponse_packet(const struct streaminfo *a_stream, char *packet, int payload_len, int v4_or_v6, int ip_tcp_hdr_len, int http_hdr_len)
{
	struct iphdr *ipv4=NULL;
	struct ip6_hdr *ipv6=NULL;
	struct tcphdr *tcp=NULL;
	unsigned char raw_route_dir=0;

	tcp=(struct tcphdr *)(packet+(ip_tcp_hdr_len-20));  // tcp header=20 bytes

	if(v4_or_v6==4)
	{
		ipv4=(struct iphdr *)packet;
		ipv4->tot_len=htons(ip_tcp_hdr_len+http_hdr_len+payload_len);							
		sendpacket_do_checksum((unsigned char *)packet, IPPROTO_TCP, tcp->doff*4 + http_hdr_len+payload_len);
		sendpacket_do_checksum((unsigned char *)packet, IPPROTO_IP, ipv4->ihl*4);
	}
	else
	{
		ipv6=(struct ip6_hdr *)packet;
		ipv6->ip6_ctlun.ip6_un1.ip6_un1_plen=htons(20+http_hdr_len+payload_len);	//tcp_hdr_len=20
		sendpacket_do_checksum((unsigned char *)packet, IPPROTO_TCP, tcp->doff*4 + http_hdr_len+payload_len);
	}
	
	raw_route_dir=(a_stream->curdir==DIR_C2S) ? MESA_dir_reverse(a_stream->routedir) : a_stream->routedir;
	tsg_send_inject_packet(a_stream, SIO_EXCLUDE_THIS_LAYER_HDR, packet, ip_tcp_hdr_len+http_hdr_len+payload_len, raw_route_dir);

	tcp->seq=htonl(ntohl(tcp->seq)+http_hdr_len+payload_len);
	
	return ip_tcp_hdr_len+http_hdr_len+payload_len;
}

static int http_build_response_packet(const struct streaminfo *a_stream, struct Maat_rule_t *p_result, struct compile_user_region *user_region, const void *a_packet)
{
	char *payload=NULL;
	char message[1024*64]={0};
	int v4_or_v6=0;
	int http_hdr_len=0;
	int payload_len=0;
	int ip_tcp_hdr_len=0;
	int i=0,one_payload_len=0;
	int ret=0,send_pkt_len=0;
	short max_segment_size=1400;

	ret=copy_ip_tcp_header(a_stream, a_packet, message, &ip_tcp_hdr_len, &v4_or_v6);
	if(ret!=0)
	{
		return 0;
	}
	
	if(a_stream->curdir==DIR_C2S)
	{
		reverse_ip_tcp_header(message, ip_tcp_hdr_len, v4_or_v6);
	}

	http_hdr_len=get_http_header(message+ip_tcp_hdr_len, sizeof(message)-ip_tcp_hdr_len, user_region->deny->code, NULL);
	payload_len=get_response_pages(a_stream, p_result, user_region, &payload, a_stream->threadnum);

	set_session_attribute_label(a_stream, TSG_ATTRIBUTE_TYPE_HTTP_ACTION_FILESIZE, (void *)&payload_len, sizeof(int), a_stream->threadnum);
	
	get_tcp_mss_option(a_stream, TCP_OPT_MSS, (void *)&max_segment_size);
	
	for(i=0; i<payload_len; i+=one_payload_len)
	{
		one_payload_len=MIN(payload_len-i, max_segment_size-http_hdr_len);
		memcpy((char *)message+ip_tcp_hdr_len+http_hdr_len, payload+i, one_payload_len);
		
		send_pkt_len+=http_send_reponse_packet(a_stream, message, one_payload_len, v4_or_v6, ip_tcp_hdr_len, http_hdr_len);
		http_hdr_len=0;
	}
	
	if(payload!=NULL)
	{
		dictator_free(a_stream->threadnum, payload);
		payload=NULL;
	}

	set_tcp_fin_flags(message, ip_tcp_hdr_len);
	http_send_reponse_packet(a_stream, message, 0, v4_or_v6, ip_tcp_hdr_len, 0); //fin
	
	reverse_ip_tcp_header(message, ip_tcp_hdr_len, v4_or_v6);
	http_send_reponse_packet(a_stream, message, 0, v4_or_v6, ip_tcp_hdr_len, 0); //fin
	
	set_tcp_rst_flags(message, ip_tcp_hdr_len);
	http_send_reponse_packet(a_stream, message, 0, v4_or_v6, ip_tcp_hdr_len, 0); //rst
	
	reverse_ip_tcp_header(message, ip_tcp_hdr_len, v4_or_v6);
	http_send_reponse_packet(a_stream, message, 0, v4_or_v6, ip_tcp_hdr_len, 0); //rst
	
	return send_pkt_len;
}

static int http_get_redirect_url(const struct streaminfo *a_stream, struct Maat_rule_t *p_result, char *url, int code, char *http_hdr, int http_hdr_len)
{
	int used_len=0;
	char *tmp_buff=NULL;
	std::string output;

	ctemplate::Template *tpl_303=ctemplate::Template::StringToTemplate(url, strlen(url), ctemplate::DO_NOT_STRIP);
	if(tpl_303!=NULL)
	{
		ctemplate::TemplateDictionary dict_303("url_dict");	//dict is automatically finalized after function returned.

		replace_policy_variable(a_stream, &dict_303, p_result->config_id);
		
		tpl_303->Expand(&output, &dict_303);

		used_len=output.length();
		tmp_buff=(char *)dictator_malloc(a_stream->threadnum, (used_len+1)*sizeof(char));
		memcpy(tmp_buff, output.c_str(), used_len);
		tmp_buff[used_len]='\0';

		used_len=get_http_header(http_hdr, http_hdr_len, code, tmp_buff);

		dictator_free(a_stream->threadnum, tmp_buff);
		tmp_buff=NULL;
	}
	else
	{
		used_len=get_http_header(http_hdr, http_hdr_len, code, url);
	}
	
	return used_len;
}

static unsigned char do_action_reset(const struct streaminfo *a_stream, Maat_rule_t *p_result, tsg_protocol_t protocol)
{
	int ret=0,opt_value=0;
	struct rst_tcp_para rst_paras={0};

	if(a_stream->type==STREAM_TYPE_TCP)
	{
		rst_paras.rst_pkt_num=g_tsg_para.reset.pkt_num;
		rst_paras.signature_seed1=g_tsg_para.reset.seed1;
		rst_paras.signature_seed2=g_tsg_para.reset.seed2;
		rst_paras.th_flags=g_tsg_para.reset.th_flags;
		rst_paras.__pad_no_use=0;
		rst_paras.dir=g_tsg_para.reset.dir;
		ret=MESA_rst_tcp((struct streaminfo *)a_stream, &rst_paras, sizeof(rst_paras));
		if(ret<0)
		{
			MESA_handle_runtime_log(g_tsg_para.logger,
											RLOG_LV_FATAL,
											"RST_TCP",
											"Send RST failed policy_id: %d service: %d action: %d addr: %s",
											p_result->config_id,
											p_result->service_id,
											(unsigned char)p_result->action,
											PRINTADDR(a_stream, g_tsg_para.level)
										);
		}

		if(g_tsg_para.reset.remedy==1)
		{
			opt_value=1;
			MESA_set_stream_opt(a_stream, MSO_TCP_RST_REMEDY, (void *)&opt_value, sizeof(opt_value));
		}

		set_drop_stream(a_stream, protocol);
	}

	return STATE_DROPPKT|STATE_DROPME;
}


static unsigned char do_action_drop(const struct streaminfo *a_stream, Maat_rule_t *p_result, struct compile_user_region *user_region, tsg_protocol_t protocol, const void *a_packet)
{
    if(user_region!=NULL && user_region->deny!=NULL && user_region->deny->type==TSG_DENY_TYPE_SEND_ICMP)
	{
		send_icmp_unreachable(a_stream);
    }

	switch(protocol)
    {		
		case	PROTO_DNS:
			return STATE_GIVEME|STATE_DROPPKT;
		default:			
			set_drop_stream(a_stream, protocol);
			if(g_tsg_para.deploy_mode==DEPLOY_MODE_MIRROR)
			{
				return do_action_reset(a_stream, p_result, protocol);
			}
			break;
	}
	
	return STATE_DROPME|STATE_DROPPKT;
}

static unsigned char do_action_tamper(const struct streaminfo *a_stream, Maat_rule_t *p_result, struct compile_user_region *user_region, tsg_protocol_t protocol, const void *user_data, enum ACTION_RETURN_TYPE type)
{
	if(g_tsg_para.feature_tamper==0)
	{
		do_action_drop(a_stream, p_result, user_region, protocol, user_data);
		return STATE_DROPME|STATE_DROPPKT;
	}

    struct tcpall_context * _context=(struct tcpall_context *)get_struct_project(a_stream, g_tsg_para.tcpall_project_id);
    if(_context==NULL)
    {
        _context=(struct tcpall_context *)dictator_malloc(a_stream->threadnum, sizeof(struct tcpall_context));
        memset(_context, 0, sizeof(struct tcpall_context));
        set_struct_project(a_stream, g_tsg_para.tcpall_project_id, (void *)_context);
        _context->method_type=TSG_METHOD_TYPE_TAMPER;
        _context->tamper_count = 0;
    }
    else
    {
        _context->method_type = TSG_METHOD_TYPE_TAMPER;
        _context->tamper_count = 0;
    }

    //当前为tsg_master_plug暂时不处理在tsg_master_all_entry处理,防止命中发两�?
    if(ACTION_RETURN_TYPE_APP == type)
    {
        return STATE_GIVEME|STATE_DROPPKT|STATE_KILL_OTHER;
    }

    //TCP这里发送的话，tsg_master_all_entry仍会处理发�?UDP没有这个情况,所以加该判�?
    if(a_stream->type == STREAM_TYPE_UDP) 
    {
        send_tamper_xxx(a_stream, &_context->tamper_count, user_data);
    }
    return STATE_DROPME|STATE_DROPPKT;
}

static unsigned char do_action_default_xxx(const struct streaminfo *a_stream, Maat_rule_t *p_result, struct compile_user_region *user_region, tsg_protocol_t protocol, const void *user_data)
{
	struct deny_user_region *deny_region=NULL;

	if(user_region->session_para==NULL)
	{
		return STATE_DROPME|STATE_DROPPKT;
	}
	
	switch(a_stream->type)
	{
		case	STREAM_TYPE_TCP:
			deny_region=&(user_region->session_para->tcp);
			break;
		case	STREAM_TYPE_UDP:			
			deny_region=&(user_region->session_para->udp);
			break;
		default:
			return STATE_DROPME|STATE_DROPPKT;
			break;
	}

	switch(deny_region->type)
	{
		case	TSG_DENY_TYPE_DEFAULT_RST:
			do_action_reset(a_stream, p_result, protocol);
			break;
		case	TSG_DENY_TYPE_SEND_ICMP:
		case	TSG_DENY_TYPE_DEFAULT_DROP:	
			struct compile_user_region tmp_user_region;
			tmp_user_region.deny=deny_region;
			tmp_user_region.capture.enabled=0;			
			tmp_user_region.capture.depth=0;
			tmp_user_region.method_type=TSG_METHOD_TYPE_DROP;
			do_action_drop(a_stream, p_result, &tmp_user_region, protocol, user_data);
			break;
		default:
			break;
	}
	
	return STATE_DROPME|STATE_DROPPKT;
}

static unsigned char do_action_ratelimit(const struct streaminfo *a_stream, Maat_rule_t *p_result, struct compile_user_region *user_region, enum ACTION_RETURN_TYPE type)
{
	struct tcpall_context *context=NULL;
	struct leaky_bucket *bucket=create_bucket(user_region->deny->action.bps, a_stream->threadnum);

	int ret=tsg_set_bucket_to_tcpall(a_stream, &context, bucket, a_stream->threadnum);
	if(ret==0)
	{
		destroy_bucket(&bucket, a_stream->threadnum);
		bucket=NULL;
	}
	
	set_dropme_flag(a_stream);

	context=NULL;

	if(type==ACTION_RETURN_TYPE_PROT)
	{		
		return STATE_DROPME;
	}

	return STATE_GIVEME|STATE_KILL_OTHER;
}

static unsigned char do_action_block_mail(const struct streaminfo *a_stream, Maat_rule_t *p_result, struct compile_user_region *user_region)
{
	char *payload=NULL;
	unsigned char raw_route_dir=0;

	switch(user_region->deny->code)
	{
		case	550:
			payload=(char *)"550 Mail was identified as spam.\r\n";
			break;
		case	551:
			payload=(char *)"551 User not local; please try <forward-path>\r\n";
			break;
		default:
			break;
	}

	if(payload!=NULL)
	{		
		raw_route_dir=(a_stream->curdir==DIR_C2S) ? MESA_dir_reverse(a_stream->routedir) : a_stream->routedir;
		tsg_send_inject_packet(a_stream, SIO_DEFAULT, payload, strlen(payload), raw_route_dir);
	}
	
	return STATE_DROPME|STATE_DROPPKT;
}

static unsigned char do_action_block_http(const struct streaminfo *a_stream, Maat_rule_t *p_result, struct compile_user_region *user_region, const void *a_packet)
{
	int opt_value=0;
	int send_pkt_len=0;

	switch(user_region->deny->code)
	{
		case	200:
		case	204:
		case	403:
		case	404:
			send_pkt_len=http_build_response_packet(a_stream, p_result, user_region, a_packet);
			tsg_set_statistic_opt(send_pkt_len, ((user_region->method_type==TSG_METHOD_TYPE_ALERT) ? OPT_TYPE_ALERT_BYTES : OPT_TYPE_BLOCK_BYTES), a_stream->threadnum);
			break;
		default:
			break;
	}

	if(g_tsg_para.reset.remedy==1)
	{
		opt_value=1;
		MESA_set_stream_opt(a_stream, MSO_TCP_RST_REMEDY, (void *)&opt_value, sizeof(opt_value));
	}
	
	return STATE_DROPME|STATE_DROPPKT;
}

static unsigned char do_action_block_xxx(const struct streaminfo *a_stream, Maat_rule_t *p_result, struct compile_user_region *user_region, tsg_protocol_t protocol, const void *a_packet)
{
	if(user_region==NULL || user_region->deny==NULL)
	{
		return do_action_drop(a_stream, p_result, user_region, protocol, a_packet);
	}
	
	switch(protocol)
	{
		case	PROTO_HTTP:
			return do_action_block_http(a_stream, p_result, user_region, a_packet);
			break;
		case	PROTO_POP3:
		case	PROTO_IMAP:
		case	PROTO_SMTP:
		case	PROTO_MAIL:
			return do_action_block_mail(a_stream, p_result, user_region);
			break;
		default:
			break;
	}

	set_drop_stream(a_stream, protocol);

	return STATE_DROPME|STATE_DROPPKT;
}

static unsigned char do_action_redirect_http(const struct streaminfo *a_stream, Maat_rule_t *p_result, struct compile_user_region *user_region)
{
	int used_http_hdr_len=0;
	char http_hdr[1024]={0};
	unsigned char raw_route_dir=0;

	switch(user_region->deny->code)
	{
		case	302:
		case	303:			
			used_http_hdr_len=http_get_redirect_url(a_stream, p_result, user_region->deny->redirect_url_to, user_region->deny->code, http_hdr, sizeof(http_hdr));
			break;
		default:
			return STATE_DROPME|STATE_DROPPKT;
			break;
	}
	
	raw_route_dir=(a_stream->curdir==DIR_C2S) ? MESA_dir_reverse(a_stream->routedir) : a_stream->routedir;
	tsg_send_inject_packet( a_stream, SIO_DEFAULT, http_hdr, used_http_hdr_len, raw_route_dir);

	return STATE_DROPME|STATE_DROPPKT;
}

static unsigned char do_action_redirect_xxx(const struct streaminfo *a_stream, Maat_rule_t *p_result, struct compile_user_region *user_region, tsg_protocol_t protocol, const void *user_data)
{
	if(user_region==NULL || user_region->deny==NULL)
	{
        return do_action_drop(a_stream, p_result, user_region, protocol, user_data);
    }

	switch(protocol)
	{
		case	PROTO_DNS:			
			return do_action_redirect_dns(a_stream, p_result, user_region, user_data);
			break;
		case	PROTO_HTTP:
			do_action_redirect_http(a_stream, p_result, user_region);
			set_drop_stream(a_stream, protocol);
			break;
		default:
			break;
	}

	return STATE_DROPME|STATE_DROPPKT;
}

static unsigned char tsg_do_deny_action(const struct streaminfo *a_stream, struct compile_user_region *user_region, Maat_rule_t *p_result, tsg_protocol_t protocol, enum ACTION_RETURN_TYPE type, const void *user_data)
{
	unsigned char local_state=STATE_GIVEME;
	unsigned char state=0;
	int method_type=TSG_METHOD_TYPE_RESET;
	if(user_region!=NULL)
	{
		method_type=user_region->method_type;
	}

	switch(method_type)
	{
		case	TSG_METHOD_TYPE_DROP:
			local_state=do_action_drop(a_stream, p_result, user_region, protocol, user_data);
			if(protocol==PROTO_DNS && type==ACTION_RETURN_TYPE_APP)
			{
				local_state=set_drop_stream(a_stream, protocol);
			}
			break;
		case	TSG_METHOD_TYPE_RST:
		case	TSG_METHOD_TYPE_RESET:
			local_state=do_action_reset(a_stream, p_result, protocol);
			break;
		case	TSG_METHOD_TYPE_BLOCK:
		case	TSG_METHOD_TYPE_ALERT:
			local_state=do_action_block_xxx(a_stream, p_result, user_region, protocol, user_data);
			break;
		case	TSG_METHOD_TYPE_REDIRECTION:
			local_state=do_action_redirect_xxx( a_stream, p_result, user_region, protocol, user_data);
			break;
		case	TSG_METHOD_TYPE_RATE_LIMIT:
			local_state=do_action_ratelimit(a_stream, p_result, user_region, type);
			break;
        case TSG_METHOD_TYPE_TAMPER:
            local_state = do_action_tamper(a_stream, p_result, user_region, protocol, user_data, type);
            break;
		case	TSG_METHOD_TYPE_DEFAULT:
			local_state=do_action_default_xxx(a_stream, p_result, user_region, protocol, user_data);
			break;
		case	TSG_METHOD_TYPE_APP_DROP:
			if((user_region->deny==NULL) || (user_region->deny->type!=TSG_DENY_TYPE_APP_DROP))
			{
				break;
			}
			
			local_state=do_action_drop(a_stream, p_result, user_region, protocol, user_data);
			if(protocol==PROTO_DNS && type==ACTION_RETURN_TYPE_APP)
			{
				local_state=set_drop_stream(a_stream, protocol);
			}
			
			if(user_region->deny->action.send_icmp_enable==1)
			{
				 local_state|=send_icmp_unreachable(a_stream);
			}

			if(user_region->deny->action.send_reset_enable==1)
			{
				 local_state|=do_action_reset(a_stream, p_result, protocol);
			}
			break;
		default:
			break;
	}
	
	tsg_notify_hited_monitor_result(a_stream, p_result, 1, a_stream->threadnum);

	if(method_type!=TSG_METHOD_TYPE_DEFAULT && method_type!=TSG_METHOD_TYPE_APP_DROP)
	{
		struct tcpall_context *context=NULL;
		tsg_set_method_to_tcpall(a_stream, &context, (enum TSG_METHOD_TYPE)method_type, a_stream->threadnum);
	}
	
	state=((type==ACTION_RETURN_TYPE_PROT) ? PROT_STATE_GIVEME : APP_STATE_GIVEME);
	state|=((type==ACTION_RETURN_TYPE_PROT) ? (local_state&STATE_DROPME ? PROT_STATE_DROPME : 0) : (local_state&STATE_DROPME ? APP_STATE_DROPME : 0));	
	state|=((type==ACTION_RETURN_TYPE_PROT) ? (local_state&STATE_GIVEME ? PROT_STATE_GIVEME: 0) : (local_state&STATE_GIVEME ? APP_STATE_GIVEME: 0));
	state|=((type==ACTION_RETURN_TYPE_PROT) ? (local_state&STATE_DROPPKT ? PROT_STATE_DROPPKT : 0) : (local_state&STATE_DROPPKT ? APP_STATE_DROPPKT: 0));
	state|=((type==ACTION_RETURN_TYPE_PROT) ? (0) : (local_state&STATE_KILL_OTHER ? APP_STATE_KILL_OTHER : 0));
	
	return state;
}

unsigned char tsg_deny_application(const struct streaminfo *a_stream, Maat_rule_t *p_result, tsg_protocol_t protocol, int app_id, enum ACTION_RETURN_TYPE type, const void *user_data)
{
	unsigned char state=0;
	char app_id_buff[32]={0};
	struct app_id_dict *dict=NULL;	
	struct compile_user_region app_user_region={0}, *user_region=NULL;
	
	if(protocol==PROTO_DNS && type==ACTION_RETURN_TYPE_APP && user_data==NULL)
	{
		return APP_STATE_GIVEME;
	}

	snprintf(app_id_buff, sizeof(app_id_buff), "%d", app_id);
	dict=(struct app_id_dict *)Maat_plugin_get_EX_data(g_tsg_maat_feather, g_tsg_para.table_id[TABLE_APP_ID_DICT], (const char *)app_id_buff);
	if(dict==NULL || user_data==NULL)
	{
		set_drop_stream(a_stream, protocol);
		return ((type==ACTION_RETURN_TYPE_PROT) ? PROT_STATE_DROPPKT|PROT_STATE_DROPME: APP_STATE_DROPME|APP_STATE_DROPPKT);
	}
	
	user_region=(struct compile_user_region *)Maat_rule_get_ex_data(g_tsg_maat_feather, p_result, g_tsg_para.table_id[TABLE_SECURITY_COMPILE]);
	if(user_region!=NULL)
	{
		app_user_region.capture=user_region->capture;		
		security_compile_free(g_tsg_para.table_id[TABLE_SECURITY_COMPILE], p_result, NULL, (MAAT_RULE_EX_DATA *)&user_region, 0, NULL);
	}

	switch(dict->deny_app_para.type)
	{
		case	TSG_DENY_TYPE_APP_DROP:
			app_user_region.method_type=TSG_METHOD_TYPE_APP_DROP;
			app_user_region.deny=&(dict->deny_app_para);
			break;
		case	TSG_DENY_TYPE_APP_RATELIMIT:
			app_user_region.method_type=TSG_METHOD_TYPE_RATE_LIMIT;
			app_user_region.deny=&(dict->deny_app_para);
			break;
		default:
			break;
	}
	
	state=tsg_do_deny_action(a_stream, &app_user_region, p_result, protocol, type, user_data);
	app_id_dict_free(g_tsg_para.table_id[TABLE_APP_ID_DICT], (MAAT_PLUGIN_EX_DATA *)&dict, 0, NULL);
	
	return state;
}

unsigned char tsg_deal_deny_action(const struct streaminfo *a_stream, Maat_rule_t *p_result, tsg_protocol_t protocol, enum ACTION_RETURN_TYPE type, const void *user_data)
{
	unsigned char state=0;
	struct compile_user_region *user_region=NULL;

	if(p_result->action==TSG_ACTION_BYPASS)
	{
		return ((type==ACTION_RETURN_TYPE_PROT) ? PROT_STATE_DROPME : APP_STATE_GIVEME);
	}

	if(protocol==PROTO_DNS && type==ACTION_RETURN_TYPE_APP && user_data==NULL)
	{
		return APP_STATE_GIVEME;
	}

	user_region=(struct compile_user_region *)Maat_rule_get_ex_data(g_tsg_maat_feather, p_result, g_tsg_para.table_id[TABLE_SECURITY_COMPILE]);
	if(user_region==NULL || user_data==NULL)
	{
		set_drop_stream(a_stream, protocol);
		return ((type==ACTION_RETURN_TYPE_PROT) ? PROT_STATE_DROPPKT|PROT_STATE_DROPME: APP_STATE_DROPME|APP_STATE_DROPPKT);
	}
	
	if(user_region->method_type==TSG_METHOD_TYPE_APP_DROP)
	{
		unsigned int app_id=0;
		
		if(protocol==PROTO_MAIL)
		{
			app_id=tsg_l7_protocol_name2id(g_tsg_proto_name2id[PROTO_SMTP].name);
		}
		else
		{
			app_id=tsg_l7_protocol_name2id(g_tsg_proto_name2id[protocol].name);
		}
		state=tsg_deny_application(a_stream, p_result, protocol, app_id, ACTION_RETURN_TYPE_APP, user_data);
	}
	else
	{
		state=tsg_do_deny_action(a_stream, user_region, p_result, protocol, type, user_data);
	}
	
	security_compile_free(g_tsg_para.table_id[TABLE_SECURITY_COMPILE], p_result, NULL, (MAAT_RULE_EX_DATA *)&user_region, 0, NULL);

	return state;
}

