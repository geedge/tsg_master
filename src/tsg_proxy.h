#pragma once

#include <MESA/stream.h>

struct tsg_proxy_tcp_option
{
	uint16_t mss;
    uint8_t wscale_set;
	uint8_t wscale;
	uint8_t sack;
	uint8_t ts_set;
	uint32_t ts_val;
    uint32_t ts_ecr;
	uint16_t window;
	uint8_t route_ctx_len;
	uint8_t route_ctx[64];//route_ctx is contiguous memory
	struct segment_id_list sid_list;
};

struct tsg_proxy_tcp_attribute
{
    uint8_t first_data_pkt_processed;
    uint8_t ignore;
	uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint8_t tcp_protocol;
    uint8_t tcp_info_packet_cur_dir;
	struct tsg_proxy_tcp_option tcp_opt_client;
	struct tsg_proxy_tcp_option tcp_opt_server;
};

struct pkt_info{
	addr_type_t addr_type;
	union{
		struct iphdr *v4;
		struct ip6_hdr *v6;
	}iphdr;
	uint16_t iphdr_len;
	uint16_t ip_totlen;
	struct tcphdr *tcphdr;
	uint16_t tcphdr_len;
	char *data;
	uint16_t data_len;
	int parse_failed;
};

int tsg_proxy_ipv4_header_parse(const void *a_packet, struct pkt_info *pktinfo);
int tsg_proxy_ipv6_header_parse(const void *a_packet, struct pkt_info *pktinfo);
void tsg_proxy_tcp_parse(struct tsg_proxy_tcp_attribute *tcp_attr, struct pkt_info *pktinfo, const struct streaminfo *pstream);
void tsg_proxy_first_data_process(const struct streaminfo *stream, struct tsg_proxy_tcp_attribute *tcp_attr, struct pkt_info *pktinfo);

void tsg_proxy_tcp_options_parse(const struct streaminfo *stream, const void *a_packet);
void tsg_proxy_update_policy_fill(const struct streaminfo *stream, struct update_policy *policy, struct segment_id_list *segment_ids);