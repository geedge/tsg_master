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

#include "tsg_stat.h"
#include "tsg_rule.h"
#include "app_label.h"
#include "tsg_entry.h"
#include "tsg_bridge.h"
#include "tsg_statistic.h"
#include "tsg_send_log.h"
#include "tsg_protocol_common.h"
#include "tsg_rule_internal.h"

extern "C" int sendpacket_do_checksum(unsigned char *buf, int protocol, int len);

static int replace_policy_variable(const struct streaminfo *a_stream, ctemplate::TemplateDictionary *tpl_dict, long long policy_id)
{
	char ip_str[128]={0};
	
	tpl_dict->SetIntValue("tsg_policy_id", policy_id);	//TODO

	const struct session_runtime_attribute *srt_attribute=(const struct session_runtime_attribute *)session_runtime_attribute_get(a_stream);
	if(srt_attribute!=NULL && srt_attribute->client_subscribe_id!=NULL)
	{
		tpl_dict->SetFormattedValue("tsg_subscriber_id", "%s", srt_attribute->client_subscribe_id->subscribe_id);
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

static int set_drop_stream(const struct streaminfo *a_stream, enum TSG_PROTOCOL protocol)
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
					tsg_stat_flow_update(STAT_STATUS_FAIL, FLOW_STAT_SET_TIMEOUT, 1);
				}
				else
				{
					tsg_stat_flow_update(STAT_STATUS_SUCCESS, FLOW_STAT_SET_TIMEOUT, 1);
				}
			break;
		default:
			break;
	}

	return STATE_DROPME;
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
	int tcp_opt_num=0;
	struct tcp_option *tcp_opt=NULL;
	
	int ret=MESA_get_stream_opt(a_stream, MSO_TCP_SYN_OPT, (void *)&tcp_opt, &tcp_opt_num);
	if(ret>0)
	{
		for(int i=0; i<tcp_opt_num; i++)
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

static void template_generate(const struct streaminfo *a_stream, int status_code, long long policy_id, const char* message, char **page_buff, size_t *page_size, int thread_seq)
{
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

			int used_len=msg_output.length();
			char *tmp_buff=(char *)dictator_malloc(a_stream->threadnum, (used_len+1)*sizeof(char));
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

static int get_response_pages(const struct streaminfo *a_stream, struct maat_rule *p_result, struct compile_user_region *user_region, char **payload, int thread_seq)
{
	int payload_len=0;

	switch(user_region->deny->type)
	{
		case	TSG_DENY_TYPE_MESSAGE:
			template_generate(a_stream, user_region->deny->code, p_result->rule_id, user_region->deny->message, payload, (size_t *)&payload_len, thread_seq);
			return payload_len;
			break;
		case	TSG_DENY_TYPE_PROFILE:
			break;
		default:
			break;
	}

	struct http_response_pages *response_pages=(struct http_response_pages *)matched_rule_cites_http_response_pages(g_tsg_maat_feather, (long long)user_region->deny->profile_id);
	if(response_pages!=NULL)
	{
		switch(response_pages->format)
		{
			case	HTTP_RESPONSE_FORMAT_HTML:
				*payload=(char *)dictator_malloc(thread_seq, response_pages->content_len);
				memcpy(*payload, response_pages->content, response_pages->content_len);
				payload_len=response_pages->content_len;
				break;
			case	HTTP_RESPONSE_FORMAT_TEMPLATE:
				template_generate(a_stream, user_region->deny->code, p_result->rule_id, response_pages->content, payload, (size_t *)&payload_len, thread_seq);
				break;
			default:
				break;
		}

		plugin_ex_data_http_response_pages_free(response_pages);
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
		tsg_stat_flow_update(STAT_STATUS_FAIL, FLOW_STAT_INJECT, 1);
		return -1;
	}

	ret=sapp_inject_pkt((struct streaminfo *)a_stream, sio, payload, payload_len, raw_route_dir);
	if(ret<=0)
	{
		tsg_stat_flow_update(STAT_STATUS_FAIL, FLOW_STAT_INJECT, 1);
		return -1;
	}

	tsg_stat_flow_update(STAT_STATUS_SUCCESS, FLOW_STAT_INJECT, 1);
	
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

static int http_build_response_packet(const struct streaminfo *a_stream, struct maat_rule *p_result, struct compile_user_region *user_region, const void *a_packet)
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

	srt_attribute_set_reponse_size(a_stream, payload_len);
	
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

static int http_get_redirect_url(const struct streaminfo *a_stream, struct maat_rule *p_result, char *url, int code, char *http_hdr, int http_hdr_len)
{
	int used_len=0;
	char *tmp_buff=NULL;
	std::string output;

	ctemplate::Template *tpl_303=ctemplate::Template::StringToTemplate(url, strlen(url), ctemplate::DO_NOT_STRIP);
	if(tpl_303!=NULL)
	{
		ctemplate::TemplateDictionary dict_303("url_dict");	//dict is automatically finalized after function returned.

		replace_policy_variable(a_stream, &dict_303, p_result->rule_id);
		
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

static unsigned char do_action_reset(const struct streaminfo *a_stream, struct maat_rule *p_result, enum TSG_PROTOCOL protocol)
{
	if(a_stream->type==STREAM_TYPE_TCP)
	{
		struct rst_tcp_para rst_paras={0};
		rst_paras.rst_pkt_num=g_tsg_para.reset.pkt_num;
		rst_paras.signature_seed1=g_tsg_para.reset.seed1;
		rst_paras.signature_seed2=g_tsg_para.reset.seed2;
		rst_paras.th_flags=g_tsg_para.reset.th_flags;
		rst_paras.__pad_no_use=0;
		rst_paras.dir=g_tsg_para.reset.dir;
		int ret=MESA_rst_tcp((struct streaminfo *)a_stream, &rst_paras, sizeof(rst_paras));
		if(ret<0)
		{
			MESA_handle_runtime_log(g_tsg_para.logger,
											RLOG_LV_FATAL,
											"RST_TCP",
											"Send RST failed policy_id: %d service: %d action: %d addr: %s",
											p_result->rule_id,
											p_result->service_id,
											(unsigned char)p_result->action,
											PRINTADDR(a_stream, g_tsg_para.level)
										);
		}

		if(g_tsg_para.reset.remedy==1)
		{
			int opt_value=1;
			MESA_set_stream_opt(a_stream, MSO_TCP_RST_REMEDY, (void *)&opt_value, sizeof(opt_value));
		}

		set_drop_stream(a_stream, protocol);
	}

	return STATE_DROPME;
}

static unsigned char do_action_drop(const struct streaminfo *a_stream, struct maat_rule *p_result, struct compile_user_region *user_region, enum TSG_PROTOCOL protocol, const void *a_packet)
{
	int opt_value=1;

	switch(protocol)
	{
		case	PROTO_DNS:
			MESA_set_stream_opt(a_stream, MSO_DROP_CURRENT_PKT, (void *)&opt_value, sizeof(opt_value));
			return STATE_GIVEME;
		default:
			set_drop_stream(a_stream, protocol);
			break;
	}
	
	return STATE_DROPME;
}

static unsigned char do_action_tamper(const struct streaminfo *a_stream, struct maat_rule *p_result, struct compile_user_region *user_region, enum TSG_PROTOCOL protocol, const void *user_data, enum ACTION_RETURN_TYPE type)
{
	if(g_tsg_para.feature_tamper==0)
	{
		do_action_drop(a_stream, p_result, user_region, protocol, user_data);
		return STATE_DROPME;
	}

	struct session_runtime_action_context * _context=(struct session_runtime_action_context *)session_runtime_action_context_get(a_stream);
	if(_context==NULL)
	{
		_context=(struct session_runtime_action_context *)dictator_malloc(a_stream->threadnum, sizeof(struct session_runtime_action_context));
		memset(_context, 0, sizeof(struct session_runtime_action_context));
		session_runtime_action_context_async(a_stream, (void *)_context);
		_context->method_type=TSG_METHOD_TYPE_TAMPER;
		_context->tamper_count = 0;
	}
	else
	{
		_context->method_type = TSG_METHOD_TYPE_TAMPER;
		_context->tamper_count = 0;
	}

	if(ACTION_RETURN_TYPE_APP == type)
	{
		int opt_value=1;
		MESA_set_stream_opt(a_stream, MSO_DROP_CURRENT_PKT, (void *)&opt_value, sizeof(opt_value));
		return STATE_GIVEME;
	}

	if(a_stream->type == STREAM_TYPE_UDP) 
	{
		send_tamper_xxx(a_stream, &_context->tamper_count, user_data);
	}
	
	return STATE_DROPME;
}

static unsigned char do_action_default_xxx(const struct streaminfo *a_stream, struct maat_rule *p_result, struct compile_user_region *user_region, enum TSG_PROTOCOL protocol, const void *user_data)
{
	int opt_value=1;
	struct deny_user_region *deny_region=NULL;

	if(user_region->session_para==NULL)
	{
		MESA_set_stream_opt(a_stream, MSO_DROP_CURRENT_PKT, (void *)&opt_value, sizeof(opt_value));
		return STATE_DROPME;
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
			MESA_set_stream_opt(a_stream, MSO_DROP_CURRENT_PKT, (void *)&opt_value, sizeof(opt_value));
			return STATE_DROPME;
			break;
	}

	switch(deny_region->type)
	{
		case	TSG_DENY_TYPE_DEFAULT_RST:
			do_action_reset(a_stream, p_result, protocol);
			break;
		case	TSG_DENY_TYPE_DROP:
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
	
	return STATE_DROPME;
}

static unsigned char do_action_ratelimit(const struct streaminfo *a_stream, struct maat_rule *p_result, struct compile_user_region *user_region, enum ACTION_RETURN_TYPE type)
{
	struct leaky_bucket *bucket=create_bucket(user_region->deny->bps, a_stream->threadnum);

	int ret=srt_action_context_set_leaky_bucket(a_stream, bucket, a_stream->threadnum);
	if(ret==0)
	{
		destroy_bucket(&bucket, a_stream->threadnum);
		bucket=NULL;
	}

	if(type==ACTION_RETURN_TYPE_PROT)
	{		
		return STATE_DROPME;
	}

	if(type==ACTION_RETURN_TYPE_APP)
	{		
		return STATE_DROPME;
	}

	return STATE_GIVEME;
}

static unsigned char do_action_block_sip(const struct streaminfo *a_stream, struct maat_rule *p_result, struct compile_user_region *user_region, const void *user_data)
{
	int offset=0;
	int opt_value=1;
	char payload[1024]={0};
	switch(user_region->deny->code)
	{
		case	480:
			//"SIP/2.0 480 Temporarily Unavailable\r\n"
			offset=strlen("SIP/2.0 480 Temporarily Unavailable\r\n");
			memcpy(payload, "SIP/2.0 480 Temporarily Unavailable\r\n", offset);
			break;
		case	500:
			//"SIP/2.0 500 Server Internal Error\r\n",
			offset=strlen("SIP/2.0 500 Server Internal Error\r\n");
			memcpy(payload, "SIP/2.0 500 Server Internal Error\r\n", offset);
			break;
		default:
			MESA_set_stream_opt(a_stream, MSO_DROP_CURRENT_PKT, (void *)&opt_value, sizeof(opt_value));
			return STATE_DROPME;
	}
	
	memcpy(payload+offset, user_data, strlen((const char*)user_data));
	unsigned char raw_route_dir=(a_stream->curdir==DIR_C2S) ? MESA_dir_reverse(a_stream->routedir) : a_stream->routedir;
	tsg_send_inject_packet(a_stream, SIO_DEFAULT, payload, strlen(payload), raw_route_dir);

	MESA_set_stream_opt(a_stream, MSO_DROP_CURRENT_PKT, (void *)&opt_value, sizeof(opt_value));

	return STATE_DROPME;
}

static unsigned char do_action_block_mail(const struct streaminfo *a_stream, struct maat_rule *p_result, struct compile_user_region *user_region)
{
	char *payload=NULL;

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
		unsigned char raw_route_dir=(a_stream->curdir==DIR_C2S) ? MESA_dir_reverse(a_stream->routedir) : a_stream->routedir;
		tsg_send_inject_packet(a_stream, SIO_DEFAULT, payload, strlen(payload), raw_route_dir);
	}

	int opt_value=1;
	MESA_set_stream_opt(a_stream, MSO_DROP_CURRENT_PKT, (void *)&opt_value, sizeof(opt_value));
	
	return STATE_DROPME;
}

static unsigned char do_action_block_http(const struct streaminfo *a_stream, struct maat_rule *p_result, struct compile_user_region *user_region, const void *a_packet)
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

	opt_value=1;
	MESA_set_stream_opt(a_stream, MSO_DROP_CURRENT_PKT, (void *)&opt_value, sizeof(opt_value));

	return STATE_DROPME;
}

static unsigned char do_action_block_xxx(const struct streaminfo *a_stream, struct maat_rule *p_result, struct compile_user_region *user_region, enum TSG_PROTOCOL protocol, const void *user_data)
{
	if(user_region==NULL || user_region->deny==NULL)
	{
		return do_action_drop(a_stream, p_result, user_region, protocol, user_data);
	}
	
	switch(protocol)
	{
		case	PROTO_HTTP:
			return do_action_block_http(a_stream, p_result, user_region, user_data);
			break;
		case	PROTO_POP3:
		case	PROTO_IMAP:
		case	PROTO_SMTP:
		case	PROTO_MAIL:
			return do_action_block_mail(a_stream, p_result, user_region);
			break;
		case	PROTO_SIP:
			return do_action_block_sip(a_stream, p_result, user_region, user_data);
			break;
		default:
			break;
	}

	set_drop_stream(a_stream, protocol);

	return STATE_DROPME;
}

static unsigned char do_action_redirect_http(const struct streaminfo *a_stream, struct maat_rule *p_result, struct compile_user_region *user_region)
{
	int opt_value=1;
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
			MESA_set_stream_opt(a_stream, MSO_DROP_CURRENT_PKT, (void *)&opt_value, sizeof(opt_value));
			return STATE_DROPME;
			break;
	}
	
	raw_route_dir=(a_stream->curdir==DIR_C2S) ? MESA_dir_reverse(a_stream->routedir) : a_stream->routedir;
	tsg_send_inject_packet( a_stream, SIO_DEFAULT, http_hdr, used_http_hdr_len, raw_route_dir);

	MESA_set_stream_opt(a_stream, MSO_DROP_CURRENT_PKT, (void *)&opt_value, sizeof(opt_value));

	return STATE_DROPME;
}

static unsigned char do_action_redirect_xxx(const struct streaminfo *a_stream, struct maat_rule *p_result, struct compile_user_region *user_region, enum TSG_PROTOCOL protocol, const void *user_data)
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

	return STATE_DROPME;
}

static unsigned char tsg_do_deny_action(const struct streaminfo *a_stream, struct compile_user_region *user_region, struct maat_rule *p_result, enum TSG_PROTOCOL protocol, enum ACTION_RETURN_TYPE type, const void *user_data)
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
		case	TSG_METHOD_TYPE_DROP:
		case	TSG_METHOD_TYPE_APP_DROP:
			if(user_region->deny==NULL)
			{
				break;
			}

			if(type!=ACTION_RETURN_TYPE_TCPALL && user_region->deny->after_n_packets>0)
			{
				srt_action_context_set_l7_protocol(a_stream, protocol, a_stream->threadnum);
				srt_action_context_set_rule_method(a_stream, user_region->method_type, a_stream->threadnum);

				if(a_stream->type==STREAM_TYPE_UDP && type!=ACTION_RETURN_TYPE_PROT)
				{
					srt_action_context_set_after_n_packet(a_stream, user_region->deny->after_n_packets+1, a_stream->threadnum);
				}
				else
				{
					srt_action_context_set_after_n_packet(a_stream, user_region->deny->after_n_packets, a_stream->threadnum);
				}
				
				local_state=((type==ACTION_RETURN_TYPE_PROT) ? (STATE_DROPME) : (STATE_DROPME|STATE_KILL_OTHER));
				break;
			}
			
			local_state=do_action_drop(a_stream, p_result, user_region, protocol, user_data);
			if(protocol==PROTO_DNS && type==ACTION_RETURN_TYPE_APP)
			{
				local_state=set_drop_stream(a_stream, protocol);
			}
			
			if(user_region->deny->drop_para.send_icmp_enable==1)
			{
				 local_state|=send_icmp_unreachable(a_stream);
			}

			if(user_region->deny->drop_para.send_reset_enable==1)
			{
				 local_state|=do_action_reset(a_stream, p_result, protocol);
			}
			break;
		default:
			break;
	}
	
	session_packet_capture_by_rules_notify(a_stream, p_result, 1, a_stream->threadnum);

	if(method_type!=TSG_METHOD_TYPE_DEFAULT && method_type!=TSG_METHOD_TYPE_APP_DROP)
	{
		srt_action_context_set_rule_method(a_stream, (enum TSG_METHOD_TYPE)method_type, a_stream->threadnum);
	}
	
	state=((type==ACTION_RETURN_TYPE_PROT) ? PROT_STATE_GIVEME : APP_STATE_GIVEME);
	state|=((type==ACTION_RETURN_TYPE_PROT) ? (local_state&STATE_DROPME ? PROT_STATE_DROPME : 0) : (local_state&STATE_DROPME ? APP_STATE_DROPME : 0));
	state|=((type==ACTION_RETURN_TYPE_PROT) ? (local_state&STATE_GIVEME ? PROT_STATE_GIVEME: 0) : 0);
	//state|=((type==ACTION_RETURN_TYPE_PROT) ? (local_state&STATE_GIVEME ? PROT_STATE_GIVEME: 0) : (local_state&STATE_GIVEME ? APP_STATE_GIVEME: 0));
	state|=((type==ACTION_RETURN_TYPE_PROT) ? (0) : (local_state&STATE_KILL_OTHER ? APP_STATE_KILL_OTHER : 0));

	return state;
}

unsigned char tsg_enforing_deny_application(const struct streaminfo *a_stream, struct maat_rule *p_result, enum TSG_PROTOCOL protocol, int app_id, enum ACTION_RETURN_TYPE type, const void *user_data)
{
	struct app_id_dict *dict=(struct app_id_dict *)matched_rule_cites_app_id_dict(g_tsg_maat_feather, (long long)app_id);
	if(dict==NULL)
	{
		set_drop_stream(a_stream, protocol);
		return ((type==ACTION_RETURN_TYPE_PROT) ? PROT_STATE_DROPPKT|PROT_STATE_DROPME: APP_STATE_DROPME|APP_STATE_DROPPKT);
	}

	unsigned char state=0;
	struct compile_user_region app_user_region;
	
	struct maat_compile *maat_compile=(struct maat_compile *)matched_rule_cites_security_compile(g_tsg_maat_feather, p_result->rule_id);
	if(maat_compile!=NULL && maat_compile->user_region!=NULL)
	{
		app_user_region.capture=maat_compile->user_region->capture;
		plugin_ex_data_security_compile_free(maat_compile);
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
	plugin_ex_data_app_id_dict_free(dict);
	
	return state;
}

unsigned char tsg_enforing_deny(const struct streaminfo *a_stream, struct maat_rule *p_result, enum TSG_PROTOCOL protocol, enum ACTION_RETURN_TYPE type, const void *user_data)
{
	if(p_result->action==TSG_ACTION_BYPASS)
	{
		return ((type==ACTION_RETURN_TYPE_PROT) ? PROT_STATE_DROPME : APP_STATE_GIVEME);
	}

	struct maat_compile *maat_compile=(struct maat_compile *)matched_rule_cites_security_compile(g_tsg_maat_feather, p_result->rule_id);
	if(maat_compile==NULL || maat_compile->user_region==NULL)
	{
		set_drop_stream(a_stream, protocol);
		return ((type==ACTION_RETURN_TYPE_PROT) ? PROT_STATE_DROPPKT|PROT_STATE_DROPME: APP_STATE_DROPME|APP_STATE_DROPPKT);
	}

	unsigned char state=0;

	if(maat_compile->user_region->method_type==TSG_METHOD_TYPE_APP_DROP)
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
		state=tsg_enforing_deny_application(a_stream, p_result, protocol, app_id, ACTION_RETURN_TYPE_APP, user_data);
	}
	else
	{
		state=tsg_do_deny_action(a_stream, maat_compile->user_region, p_result, protocol, type, user_data);
	}
	
	plugin_ex_data_security_compile_free(maat_compile);

	return state;
}

