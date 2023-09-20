#include <MESA/stream.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_log.h"
#include "tsg_rule.h"
#include "tsg_variable.h"
#include "tsg_send_log.h"
#include "tsg_sync_state.h"
#include "tsg_proxy.h"
#include "tsg_bridge.h"

#define DEFAULT_WINSCLE		0
#define DEFAULT_MSS			1460

enum tsg_proxy_ipv4hdr_parse_error{
	TSG_PROXY_IPV4HDR_NULL_PACKET = -1,
};

enum tsg_proxy_ipv6hdr_parse_error{
	TSG_PROXY_IPV6HDR_NULL_PACKET = -1,
	TSG_PROXY_IPV6HDR_NO_TCPHDR = -2,
	TSG_PROXY_IPV6HDR_INVALID_TYPE = -3,
};

int update_segment_sids(struct tcp_sids *d_sids_array, unsigned short *s_sids, unsigned int n_s_sids)
{
	for(unsigned int i=0; i<n_s_sids; i++)
	{
		if(d_sids_array->num>=8)
		{
			break;
		}
		
		d_sids_array->value[d_sids_array->num++]=s_sids[i];
	}

	return 1;
}

int tsg_proxy_ipv6_header_parse(const void *a_packet, struct pkt_info *pktinfo){
	if(a_packet == NULL){
		return TSG_PROXY_IPV6HDR_NULL_PACKET;
	}
	pktinfo->addr_type = ADDR_TYPE_IPV6;
	pktinfo->iphdr.v6 = (struct ip6_hdr*)a_packet;
	pktinfo->ip_totlen = ntohs(pktinfo->iphdr.v6->ip6_ctlun.ip6_un1.ip6_un1_plen) + sizeof(struct ip6_hdr);
	uint8_t next_hdr_type = pktinfo->iphdr.v6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	char *next_hdr_ptr = (char*)pktinfo->iphdr.v6 + sizeof(struct ip6_hdr);
	int skip_len = 0;
	int ret = 0;
	while(true){
		switch(next_hdr_type)
		{
			case IPPROTO_TCP:
				//parse tcphdr
				pktinfo->iphdr_len = next_hdr_ptr - (char*)a_packet;
				pktinfo->tcphdr = (struct tcphdr*)next_hdr_ptr;
				pktinfo->tcphdr_len = pktinfo->tcphdr->doff * 4;
				pktinfo->data = (char*)pktinfo->tcphdr + pktinfo->tcphdr_len;
				pktinfo->data_len = pktinfo->ip_totlen - pktinfo->iphdr_len - pktinfo->tcphdr_len;
				return 0;
			case IPPROTO_HOPOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_AH:
			case IPPROTO_DSTOPTS:
				skip_len = (*(next_hdr_ptr + 1)) * 8 + 8;
				next_hdr_type = *next_hdr_ptr;
				next_hdr_ptr += skip_len;
				break;
			case IPPROTO_NONE:
				ret = TSG_PROXY_IPV6HDR_NO_TCPHDR;
				goto error_out;
			default:
				ret = TSG_PROXY_IPV6HDR_INVALID_TYPE;
				goto error_out;
		}
	}

error_out:
	return ret;
}

int tsg_proxy_ipv4_header_parse(const void *a_packet, struct pkt_info *pktinfo){
	if(a_packet == NULL){
		return TSG_PROXY_IPV4HDR_NULL_PACKET;
	}
	pktinfo->addr_type = ADDR_TYPE_IPV4;
	pktinfo->iphdr.v4 = (struct iphdr*)a_packet;
	pktinfo->iphdr_len = pktinfo->iphdr.v4->ihl * 4;
	pktinfo->ip_totlen = ntohs(pktinfo->iphdr.v4->tot_len);
	pktinfo->tcphdr = (struct tcphdr*)((char*)pktinfo->iphdr.v4 + pktinfo->iphdr_len);
	pktinfo->tcphdr_len = pktinfo->tcphdr->doff * 4;
	pktinfo->data = (char*)pktinfo->tcphdr + pktinfo->tcphdr_len;
	pktinfo->data_len = pktinfo->ip_totlen - pktinfo->iphdr_len - pktinfo->tcphdr_len;
	return 0;
}

static char* tsg_proxy_ipv4_errmsg_get(enum tsg_proxy_ipv4hdr_parse_error _errno){
	switch(_errno){
		case TSG_PROXY_IPV4HDR_NULL_PACKET:
			return (char*)"null packet";
		default:
			return (char*)"unknown error";
	}
}

static char* tsg_proxy_ipv6_errmsg_get(enum tsg_proxy_ipv6hdr_parse_error _errno){
	switch(_errno){
		case TSG_PROXY_IPV6HDR_NULL_PACKET:
			return (char*)"null packet";
		case TSG_PROXY_IPV6HDR_NO_TCPHDR:
			return (char*)"no tcp header";
		case TSG_PROXY_IPV6HDR_INVALID_TYPE:
			return (char*)"invalid header type";
		default:
			return (char*)"unknown error";
	}
}

static void tsg_proxy_ip_header_parse(const void *a_packet, enum addr_type_t addr_type, const struct streaminfo *stream, struct pkt_info *pktinfo){
	if(addr_type == ADDR_TYPE_IPV6){
		int ret = tsg_proxy_ipv6_header_parse(a_packet, pktinfo);
		if(ret < 0)
		{
			pktinfo->parse_failed=1;
			char *errmsg = tsg_proxy_ipv6_errmsg_get((enum tsg_proxy_ipv6hdr_parse_error)ret);
			MASTER_LOG(g_tsg_para.logger, RLOG_LV_INFO, LOG_MODULE_PROXY, "Failed at parse ipv6 header, errmsg = %s, stream treaceid = %llu", errmsg, tsg_get_stream_trace_id(stream));
		}
	}
	else
	{
		int ret = tsg_proxy_ipv4_header_parse(a_packet, pktinfo);
		if(ret < 0)
		{
			pktinfo->parse_failed=1;
			char *errmsg = tsg_proxy_ipv4_errmsg_get((enum tsg_proxy_ipv4hdr_parse_error)ret);
			MASTER_LOG(g_tsg_para.logger, RLOG_LV_INFO, LOG_MODULE_PROXY, "Failed at parse ipv4 header, errmsg = %s, stream treaceid = %llu", errmsg, tsg_get_stream_trace_id(stream));
		}
	}
	return;
}

static void tsg_proxy_tcpopt_get(struct tsg_proxy_tcp_option *tcp_opt, struct tcphdr* tcphdr,int tcphdr_len)
{
	tcp_opt->mss = DEFAULT_MSS;
	tcp_opt->wscale = DEFAULT_WINSCLE;
    tcp_opt->window = ntohs(tcphdr->window);

	const unsigned char *ptr = ((const unsigned char*)tcphdr + 20);
	int length = tcphdr_len - 20;

	while (length > 0){
		int opcode = *ptr++;
		int opsize;
		switch (opcode){
            case TCPOPT_EOL:
                return;
            case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
                length--;
                continue;
            default:
                opsize = *ptr++;
                if (opsize < 2) /* "silly options" */
                    return;
                if (opsize > length)
                    return;	/* don't parse partial options */
                switch (opcode){
                    case TCPOPT_MAXSEG:
                        if (opsize == TCPOLEN_MAXSEG){
                            uint16_t in_mss = *(uint16_t *)ptr;
                            if(in_mss){ 
                                tcp_opt->mss = ntohs(in_mss);
                            }
                        }
                        break;
                        
                    case TCPOPT_WINDOW:
                        if (opsize == TCPOLEN_WINDOW){
                            uint8_t snd_wscale = *(uint8_t *)ptr;
                            // rfc7323 page9: Thus, the shift count MUST be limited to 14 (which allows windows of 2^30 = 1 GiB). 
                            // If a Window Scale option is received with a shift.cnt value larger than 14, 
                            // the TCP SHOULD log the error but MUST use 14 instead of the  specified value.  */
                            tcp_opt->wscale = snd_wscale;
                            if(tcp_opt->wscale > 14){
                                tcp_opt->wscale = 14;
                            }
							tcp_opt->wscale_set = 1;
                            //*wscale_perm=1;
                        }
                        break;
                    case TCPOPT_TIMESTAMP:
                        if (opsize == TCPOLEN_TIMESTAMP){
                            tcp_opt->ts_set = 1;
							tcp_opt->ts_val = *(uint32_t*)ptr;
							tcp_opt->ts_ecr = *(uint32_t*)(ptr + 4);
                        }
                        break;
                    case TCPOPT_SACK_PERMITTED:
                        if (opsize == TCPOLEN_SACK_PERMITTED){
                            tcp_opt->sack = 1;
                        }
                        break;
                }
                ptr += opsize-2;
                length -= opsize;
        }
	}
	return;
}

static int tsg_proxy_rawpkt_info_get(const void *raw_pkt, struct tsg_proxy_tcp_option *tcp_opt, const struct streaminfo *stream)
{
	int ret;
	struct segment_id_list *sids = NULL;

	ret = get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_SID_LIST, &sids);
	if (ret != sizeof(struct segment_id_list))
	{
		MASTER_LOG(g_tsg_para.logger, RLOG_LV_DEBUG, LOG_MODULE_PROXY, "Failed to get sid list, stream treaceid = %llu, %s", tsg_get_stream_trace_id(stream), printaddr(&(stream->addr), stream->threadnum));
		return -1;
	}
	
	memcpy(&tcp_opt->sid_list, sids, sizeof(struct segment_id_list));

	void *route_ctx = NULL;
	ret = get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_ROUTE_CTX, &route_ctx);
	if (ret < 0)
	{
		MASTER_LOG(g_tsg_para.logger, RLOG_LV_DEBUG, LOG_MODULE_PROXY, "Failed to get route ctx, stream treaceid = %llu, %s", tsg_get_stream_trace_id(stream), printaddr(&(stream->addr), stream->threadnum));
		return -1;
	}
	tcp_opt->route_ctx_len = ret;
	memcpy(tcp_opt->route_ctx, route_ctx, ret);

	return 0;
}

void tsg_proxy_tcp_parse(struct tsg_proxy_tcp_attribute *tcp_attr, struct pkt_info *pktinfo, const struct streaminfo *stream)
{
	const void *raw_pkt = get_rawpkt_from_streaminfo(stream);

	if (!raw_pkt)
	{
		return;
	}

	if (pktinfo->tcphdr->syn && !pktinfo->tcphdr->ack)
	{
		tsg_proxy_rawpkt_info_get(raw_pkt, &tcp_attr->tcp_opt_client, stream);
		tsg_proxy_tcpopt_get(&tcp_attr->tcp_opt_client, pktinfo->tcphdr, pktinfo->tcphdr_len);
	}

	if (pktinfo->tcphdr->syn && pktinfo->tcphdr->ack)
	{
		tsg_proxy_rawpkt_info_get(raw_pkt, &tcp_attr->tcp_opt_server, stream);
		tsg_proxy_tcpopt_get(&tcp_attr->tcp_opt_server, pktinfo->tcphdr, pktinfo->tcphdr_len);
	}
}

static struct tsg_proxy_tcp_attribute *tsg_proxy_tcp_attribute_get(const struct streaminfo *stream)
{
	struct session_runtime_attribute *srt_attribute = (struct session_runtime_attribute *)session_runtime_attribute_new(stream);
	if (srt_attribute == NULL)
	{
		MASTER_LOG(g_tsg_para.logger, RLOG_LV_INFO, LOG_MODULE_PROXY, "Failed to get session runtime attribute, stream treaceid = %llu", tsg_get_stream_trace_id(stream));
		return NULL;
	}

	if (srt_attribute->proxy_tcp_attr == NULL)
	{
		srt_attribute->proxy_tcp_attr = (struct tsg_proxy_tcp_attribute *)dictator_malloc(stream->threadnum, sizeof(struct tsg_proxy_tcp_attribute));
		memset(srt_attribute->proxy_tcp_attr, 0, sizeof(struct tsg_proxy_tcp_attribute));
	}

	return srt_attribute->proxy_tcp_attr;
}

void tsg_proxy_first_data_process(const struct streaminfo *stream, struct tsg_proxy_tcp_attribute *tcp_attr, struct pkt_info *pktinfo)
{
	struct tsg_proxy_tcp_option tcp_opt;
	enum TSG_PROTOCOL tcp_protocol;
	const struct session_runtime_process_context *session_context = session_runtime_process_context_get(stream);

	memset(&tcp_opt, 0, sizeof(struct tsg_proxy_tcp_option));
	tcp_protocol = srt_process_context_get_protocol(session_context);
	switch(tcp_protocol)
	{
		case PROTO_SSL:
			tcp_attr->tcp_protocol = 0x1;
			break;
		case PROTO_SSH:
			tcp_attr->tcp_protocol = 0x2;
			break;
		default:
			tcp_attr->tcp_protocol = 0x0;
			break;
	}

	if(tcp_attr->tcp_opt_client.ts_set && tcp_attr->tcp_opt_server.ts_set)
	{
		tsg_proxy_tcpopt_get(&tcp_opt, pktinfo->tcphdr, pktinfo->tcphdr_len);
		if(stream->curdir == DIR_C2S)
		{
			tcp_attr->tcp_opt_client.ts_val = tcp_opt.ts_val;
			tcp_attr->tcp_opt_server.ts_val = tcp_opt.ts_ecr;
		}
		else
		{
			tcp_attr->tcp_opt_client.ts_val = tcp_opt.ts_ecr;
			tcp_attr->tcp_opt_server.ts_val = tcp_opt.ts_val;
		}
	}

	tcp_attr->tcp_info_packet_cur_dir = stream->curdir;
	if (stream->curdir == DIR_C2S)
	{
		tcp_attr->tcp_seq = pktinfo->tcphdr->seq;
		tcp_attr->tcp_ack = pktinfo->tcphdr->ack_seq;
	}
	else
	{
		tcp_attr->tcp_seq = pktinfo->tcphdr->ack_seq;
		tcp_attr->tcp_ack = pktinfo->tcphdr->seq;
	}
	
	return;
}

void tsg_proxy_tcp_options_parse(const struct streaminfo *stream, const void *a_packet)
{
	if(a_packet==NULL || g_tsg_para.intercept_sid<=0)
	{
		return ;
	}
	
	struct pkt_info pktinfo;
	struct tsg_proxy_tcp_attribute *tcp_attr = tsg_proxy_tcp_attribute_get(stream);


	if(tcp_attr == NULL)
	{
		return;
	}

	if(tcp_attr->first_data_pkt_processed)
	{
		return;
	}

	memset(&pktinfo, 0, sizeof(struct pkt_info));
	tsg_proxy_ip_header_parse(a_packet, (enum addr_type_t)stream->addr.addrtype, stream, &pktinfo);
	if (pktinfo.parse_failed)
	{
		MASTER_LOG(g_tsg_para.logger, RLOG_LV_INFO, LOG_MODULE_PROXY, "invalid ip header, bypass pkt");
		return;
	}

	if(stream->ptcpdetail->datalen > 0)
	{
		tsg_proxy_first_data_process(stream, tcp_attr, &pktinfo);
		tcp_attr->first_data_pkt_processed = 1;
		return;
	}

	tsg_proxy_tcp_parse(tcp_attr, &pktinfo, stream);

	return;
}

static void tsg_proxy_cmsg_subscriber_fill(struct session_runtime_attribute *session_attr, struct proxy_cmsg *cmsg)
{
    const char *client_subscribe_id = srt_attribute_get_client_subscriber_id(session_attr);
	const char *server_subscribe_id = srt_attribute_get_server_subscriber_id(session_attr);
    if (client_subscribe_id) {
        cmsg->src_sub_id = (char *)client_subscribe_id;
    }
    if (server_subscribe_id) {
        cmsg->dst_sub_id = (char *)server_subscribe_id;
    }

    return;
}

static void tsg_proxy_cmsg_asn_fill(struct session_runtime_attribute *session_attr, struct proxy_cmsg *cmsg)
{
    const struct asn_info *client_asn = srt_attribute_get_client_ip_asn(session_attr);
	const struct asn_info *server_asn = srt_attribute_get_server_ip_asn(session_attr);
    if (client_asn) {
        if (client_asn->asn_id) {
            cmsg->src_asn = client_asn->asn_id;
        }
        if (client_asn->organization) {
            cmsg->src_organization = client_asn->organization;
        }
    }
    if (server_asn) {
        if (server_asn->asn_id) {
            cmsg->dst_asn = server_asn->asn_id;
        }
        if (server_asn->organization) {
            cmsg->dst_organization = server_asn->organization;
        }
    }

    return;
}

static void tsg_proxy_cmsg_ip_location_fill(struct session_runtime_attribute *session_attr, struct proxy_cmsg *cmsg)
{
    const struct location_info *client_location = srt_attribute_get_client_ip_location(session_attr);
	const struct location_info *server_location = srt_attribute_get_server_ip_location(session_attr);
    if (client_location) {
        if (client_location->full_location && client_location->full_location_len) {
            cmsg->src_ip_full_location = client_location->full_location;
        }
    }
    if (server_location) {
        if (server_location->full_location && server_location->full_location_len) {
            cmsg->dst_ip_full_location = server_location->full_location;
        }
    }
    return;
}

static void tsg_proxy_cmsg_ja3_fingerprint_fill(struct session_runtime_attribute *session_attr, struct proxy_cmsg *cmsg)
{
    const char *ja3_fingerprint = srt_attribute_get_ja3_fingerprint(session_attr);
    if (ja3_fingerprint) {
        cmsg->ssl_client_ja3_fingerprint = (char *)ja3_fingerprint;
    }
    return;
}

static void tsg_proxy_cmsg_fqdn_category_fill(struct session_runtime_attribute *session_attr, struct proxy_cmsg *cmsg)
{
    size_t n_category_ids = 0;
	uint32_t category_ids[8] = {0};
    struct fqdn_cat_id_val *fqdn_cat_ids = &cmsg->fqdn_cat_ids;

    n_category_ids = srt_attribute_get_category_ids(session_attr, category_ids, sizeof(category_ids)/sizeof(category_ids[0]));
    if (n_category_ids > 0 && n_category_ids <= 8) {
        fqdn_cat_ids->num = n_category_ids;
        for (unsigned int i = 0; i < n_category_ids; i++) {
            fqdn_cat_ids->value[i] = category_ids[i];
        }
    }
    return;
}

static void tsg_proxy_cmsg_tcp_is_intercept(const struct streaminfo *stream, struct proxy_cmsg *cmsg)
{
    if (stream->dir == DIR_C2S || stream->dir == DIR_S2C)
    {
        cmsg->tcp_is_intercept |= TCP_IS_INTERCEPT_SINGLE;
    }

    unsigned short tunnel_type=0;
	int tunnel_type_len=sizeof(tunnel_type);
	int ret=MESA_get_stream_opt(stream, MSO_STREAM_UP_LAYER_TUNNEL_TYPE, (void *)&tunnel_type, &tunnel_type_len);
    if(ret==0 && tunnel_type != STREAM_TUNNLE_NON)
	{
        cmsg->tcp_is_intercept |= TCP_IS_INTERCEPT_TUNNEL;
    }

    return;
}

static void tsg_proxy_cmsg_c2s_rpkt_header(const struct streaminfo *stream, struct cmsg_buff *c2s_rpkt_header)
{
    c2s_rpkt_header->len = sizeof(int);
    if (MESA_get_stream_opt(stream, MSO_STREAM_C2S_RAWPKT_HDR, (void *)&c2s_rpkt_header->buff, &c2s_rpkt_header->len) == -1)
    {
        c2s_rpkt_header->len = 0;
    }

    return;
}

static void tsg_proxy_cmsg_s2c_rpkt_header(const struct streaminfo *stream, struct cmsg_buff *s2c_rpkt_header)
{
    s2c_rpkt_header->len = sizeof(int);
    if (MESA_get_stream_opt(stream, MSO_STREAM_S2C_RAWPKT_HDR, (void *)&s2c_rpkt_header->buff, &s2c_rpkt_header->len) == -1)
    {
        s2c_rpkt_header->len = 0;
    }

    return;
}

static void tsg_proxy_tcp_attribute_dump(tsg_proxy_tcp_attribute *tcp_attr, struct proxy_cmsg *cmsg, const struct streaminfo *stream)
{
	struct tsg_proxy_tcp_option *client = &tcp_attr->tcp_opt_client;
	struct tsg_proxy_tcp_option *server = &tcp_attr->tcp_opt_server;
	char client_sids_str[128] = {0};
	char server_sids_str[128] = {0};
	char temp[10] = {0};

	MASTER_LOG(g_tsg_para.logger, RLOG_LV_DEBUG, LOG_MODULE_PROXY, "dump tcp attribute for stream %s, session_id %llu", printaddr(&(stream->addr), stream->threadnum), tsg_get_stream_trace_id(stream));

	MASTER_LOG(g_tsg_para.logger, RLOG_LV_DEBUG, LOG_MODULE_PROXY, "tcp_seq %u, tcp_ack %u, tcp_protocol %u, tcp_info_packet_cur_dir %u\n"\
							"client mss %u, client wscale_set %u, client wscale %u, client sack %u, client ts_set %u, client ts_val %u, client window %u"\
							"server mss %u, server wscale_set %u, server wscale %u, server sack %u, server ts_set %u, server ts_val %u, server window %u",
							tcp_attr->tcp_seq, tcp_attr->tcp_ack, tcp_attr->tcp_protocol, tcp_attr->tcp_info_packet_cur_dir,
							client->mss, client->wscale_set, client->wscale, client->sack, client->ts_set, client->ts_val, client->window,
							server->mss, server->wscale_set, server->wscale, server->sack, server->ts_set, server->ts_val, server->window);
	
    MASTER_LOG(g_tsg_para.logger, RLOG_LV_DEBUG, LOG_MODULE_PROXY, "tcp_seq_route_ctx len %u, tcp_ack_route_ctx len %u\n", client->route_ctx_len, server->route_ctx_len);

    for (unsigned int i = 0; i < client->sid_list.sz_sidlist; i++) {
        snprintf(temp, sizeof(temp), "%u", client->sid_list.sid_list[i]);
        strcat(client_sids_str, temp);
        strcat(client_sids_str, ",");
    }
    for (unsigned int i = 0; i < server->sid_list.sz_sidlist; i++) {
        snprintf(temp, sizeof(temp), "%u", server->sid_list.sid_list[i]);
        strcat(server_sids_str, temp);
        strcat(server_sids_str, ",");
    }
    MASTER_LOG(g_tsg_para.logger, RLOG_LV_DEBUG, LOG_MODULE_PROXY, "tcp_seq_sids num %u, tcp_seq_sids value: %s,  tcp_ack_sids num %u, tcp_seq_sids value: %s",
                                                                        client->sid_list.sz_sidlist, client_sids_str, server->sid_list.sz_sidlist, server_sids_str);
                            
    MASTER_LOG(g_tsg_para.logger, RLOG_LV_DEBUG, LOG_MODULE_PROXY, "client subscribe id: %s\n"\
                                                                       "server subscribe id: %s\n"\
                                                                       "client asn: %s\n"\
                                                                       "server asn: %s\n"\
                                                                       "client orgnization: %s\n"\
                                                                       "server orgnization: %s\n"\
                                                                       "client ip full_location: %s\n"\
                                                                       "server ip full_location: %s\n"\
                                                                       "ssl ja3 fingerprint:%s\n"\
                                                                       "tcp_seq_route_ctx len: %d\n"\
                                                                       "tcp_ack_route_ctx len: %d\n"\
                                                                       "tcp_c2s_rpkt_header len: %d\n"\
                                                                       "tcp_s2c_rpkt_header len: %d\n",
                                                                       cmsg->src_sub_id,
                                                                       cmsg->dst_sub_id,
                                                                       cmsg->src_asn,
                                                                       cmsg->dst_asn,
                                                                       cmsg->src_organization,
                                                                       cmsg->dst_organization,
                                                                       cmsg->src_ip_full_location,
                                                                       cmsg->dst_ip_full_location,
                                                                       cmsg->ssl_client_ja3_fingerprint,
                                                                       cmsg->tcp_seq_route_ctx.len,
                                                                       cmsg->tcp_ack_route_ctx.len,
                                                                       cmsg->tcp_c2s_rpkt_header.len,
                                                                       cmsg->tcp_s2c_rpkt_header.len);
    return;
}

void tsg_proxy_update_policy_fill(const struct streaminfo *stream, struct update_policy *policy, struct segment_id_list *segment_ids)
{
    struct proxy_cmsg *cmsg = &policy->cmsg;
    struct tsg_proxy_tcp_attribute *tcp_attr = tsg_proxy_tcp_attribute_get(stream);
    struct session_runtime_attribute *session_attr = (struct session_runtime_attribute *)session_runtime_attribute_get(stream);

    if (session_attr == NULL || tcp_attr == NULL) {
        return;
    }

    struct tsg_proxy_tcp_option *client = &tcp_attr->tcp_opt_client;
    struct tsg_proxy_tcp_option *server = &tcp_attr->tcp_opt_server;

    cmsg->tcp_seq = tcp_attr->tcp_seq;
    cmsg->tcp_ack = tcp_attr->tcp_ack;
    cmsg->tcp_protocol = tcp_attr->tcp_protocol;
    cmsg->tcp_info_packet_cur_dir = tcp_attr->tcp_info_packet_cur_dir;

    cmsg->tcp_mss_client = client->mss;
    cmsg->tcp_sack_client = client->sack;
    cmsg->tcp_ts_client = client->ts_set;
    cmsg->tcp_window_client = client->window;
    cmsg->tcp_ts_client_val = client->ts_val;

    cmsg->tcp_seq_route_ctx.len = client->route_ctx_len;
    cmsg->tcp_seq_route_ctx.buff = (char *)client->route_ctx;

	update_segment_sids(&cmsg->tcp_seq_sids, segment_ids->sid_list+1, segment_ids->sz_sidlist-1);  // delete intercept sid
	update_segment_sids(&cmsg->tcp_seq_sids, client->sid_list.sid_list, client->sid_list.sz_sidlist);

    cmsg->tcp_mss_server = server->mss;
    cmsg->tcp_sack_server = server->sack;
    cmsg->tcp_ts_server = server->ts_set;
    cmsg->tcp_window_server = server->window;
    cmsg->tcp_ts_server_val = server->ts_val;

    cmsg->tcp_ack_route_ctx.len = server->route_ctx_len;
    cmsg->tcp_ack_route_ctx.buff = (char *)server->route_ctx;

	update_segment_sids(&cmsg->tcp_ack_sids, segment_ids->sid_list+1, segment_ids->sz_sidlist-1);  // delete intercept sid
	update_segment_sids(&cmsg->tcp_ack_sids, server->sid_list.sid_list, server->sid_list.sz_sidlist);

    if (client->wscale_set && server->wscale_set) {
        cmsg->tcp_wsacle_exist = 1;
        cmsg->tcp_wsacle_client = client->wscale;
        cmsg->tcp_wsacle_server = server->wscale;
    }
    
    tsg_proxy_cmsg_subscriber_fill(session_attr, cmsg);
    tsg_proxy_cmsg_asn_fill(session_attr, cmsg);
    tsg_proxy_cmsg_ip_location_fill(session_attr, cmsg);
    tsg_proxy_cmsg_ja3_fingerprint_fill(session_attr, cmsg);
    tsg_proxy_cmsg_fqdn_category_fill(session_attr, cmsg);

    tsg_proxy_cmsg_c2s_rpkt_header(stream, &cmsg->tcp_c2s_rpkt_header);
    tsg_proxy_cmsg_s2c_rpkt_header(stream, &cmsg->tcp_s2c_rpkt_header);

    tsg_proxy_cmsg_tcp_is_intercept(stream, cmsg);

    tsg_proxy_tcp_attribute_dump(tcp_attr, cmsg, stream);

    return;
}
