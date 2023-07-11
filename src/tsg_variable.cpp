#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "tsg_label.h"
#include "tsg_variable.h"

struct tsg_rt_para g_tsg_para;

struct id2field_tlv g_tsg_proto_name2id[PROTO_MAX]={{PROTO_UNKONWN, 0, 7, "unknown"}, 
										 {PROTO_IPv4, 	0,	4, "IPV4"},
										 {PROTO_IPv6, 	0,	4, "IPV6"},
										 {PROTO_TCP, 	0, 	3, "TCP"},
										 {PROTO_UDP, 	0, 	3, "UDP"},
										 {PROTO_HTTP, 	0, 	4, "HTTP"},
										 {PROTO_MAIL, 	0, 	4, "MAIL"},
										 {PROTO_DNS, 	0, 	3, "DNS"},
										 {PROTO_FTP, 	0, 	3, "FTP"},
										 {PROTO_SSL, 	0, 	3, "SSL"},
										 {PROTO_SIP, 	0, 	3, "SIP"},
										 {PROTO_BGP, 	0, 	3, "BGP"},
										 {PROTO_STREAMING_MEDIA, 0, 15, "STREAMING_MEDIA"},
										 {PROTO_QUIC, 	0,	4, "QUIC"},
										 {PROTO_SSH, 	0, 	3, "SSH"},
										 {PROTO_SMTP, 	0, 	4, "SMTP"},
										 {PROTO_IMAP, 	0, 	4, "IMAP"},
										 {PROTO_POP3, 	0, 	4, "POP3"},
										 {PROTO_RTP, 	0, 	3, "RTP"},
										 {PROTO_APP, 	0,	4, "BASE"},
										 {PROTO_L2TP, 	0,	4, "L2TP"},
										 {PROTO_PPTP, 	0,	4, "PPTP"},
										 {PROTO_STRATUM, 0,	7, "Stratum"},
										 {PROTO_RDP, 	0,	3, "RDP"},
										 {PROTO_DTLS, 	0,	4, "DTLS"}
										};

const char *tsg_l7_protocol_id2name(unsigned int l7_protocol_id)
{	
	struct l7_protocol *l7_proto=NULL;
	HASH_FIND(hh1, g_tsg_para.name_by_id, &l7_protocol_id, sizeof(l7_protocol_id), l7_proto);
	if(l7_proto!=NULL)
	{
		return (const char *)l7_proto->name;
	}

	return NULL;
}

unsigned int tsg_l7_protocol_name2id(const char *l7_protocol_name, unsigned int l7_protocol_name_len)
{
	struct l7_protocol *l7_proto=NULL;

	HASH_FIND(hh2, g_tsg_para.id_by_name, l7_protocol_name, l7_protocol_name_len, l7_proto);
	if(l7_proto!=NULL)
	{
		return l7_proto->id;
	}

	return 0;
}

long long tsg_get_current_time_ms(void)
{
	return get_timestamp_ms();
}

unsigned long long tsg_get_stream_trace_id(const struct streaminfo * a_stream)
{
	int ret=0;
	int device_id_size=sizeof(unsigned long long);
	unsigned long long device_id=(unsigned long long)g_tsg_para.device_seq_in_dc;

	ret=MESA_get_stream_opt(a_stream, MSO_GLOBAL_STREAM_ID, (void *)&device_id, &device_id_size);
	if(ret==0)
	{
		return device_id;
	}

	return -1;
}

