#ifndef	__TSG_PROTOCOL_COMMON_H__
#define	__TSG_PROTOCOL_COMMON_H__

#include <MESA/stream.h>
#include "tsg_rule.h"
#include "tsg_label.h"

#include <sys/socket.h>
#include <netinet/in.h>

#define	STATE_GIVEME		1
#define	STATE_DROPME		2
#define	STATE_DROPPKT		4
#define	STATE_KILL_OTHER	8

enum TSG_DENY_TYPE
{
	TSG_DENY_TYPE_MESSAGE=0,
	TSG_DENY_TYPE_PROFILE,
	TSG_DENY_TYPE_REDIRECT_TO,
	TSG_DENY_TYPE_REDIRECT_URL,
	TSG_DENY_TYPE_REDIRECT_RECORD,
	TSG_DENY_TYPE_SEND_ICMP,
	TSG_DENY_TYPE_DEFAULT_RST,
	TSG_DENY_TYPE_DEFAULT_DROP,
	TSG_DENY_TYPE_MAX
};

struct selected_record
{
	int profile_id;
	int selected_num;
};

struct dns_record_val
{
	int answer_type;
	int selected_flag;
	int len;
	union
	{
		void *value;
		char *cname;
		struct in_addr v4_addr;
		struct in6_addr v6_addr;
		struct selected_record selected;
	};
};

struct dns_answer_records
{
	int max_ttl;
	int min_ttl;
	struct dns_record_val record_val;
};

struct dns_profile_records
{
	int ref_cnt;
	int record_id;
	int record_num;
	int answer_type;
	struct dns_record_val *record_val;
};

struct dns_user_region
{
	int query_type;	//dns.h
	struct dns_answer_records	*a;
	struct dns_answer_records	*aaaa;
	struct dns_answer_records	*cname;
};

struct packet_capture
{
	int enabled;
	int depth;
};

struct deny_user_region
{
	enum TSG_DENY_TYPE type;
	union
	{
		int code;
		int records_num;
		int after_n_packets;
	};
	union
	{
		char *message;
		char *redirect_url_to;
		struct dns_user_region *records;
		int profile_id;
		int bps;
		int send_icmp_enable;		
		void *para;
	};
};

struct traffic_mirror_profile
{
	int profile_id;
	int ref_cnt;
	struct mirrored_vlan vlan;
};

struct monitor_user_region
{
	int enabled;
	int profile_id;
};

struct default_session_para
{
	struct Maat_rule_t result; 			//XJ default policy
	struct deny_user_region tcp;
	struct deny_user_region udp;
};

struct compile_user_region
{	
	int ref_cnt;
	enum TSG_METHOD_TYPE method_type;
	union	
	{
		struct deny_user_region *deny;		
		struct monitor_user_region *mirror;		
		struct default_session_para *session_para;		
		void *user_region_para;		
	};	
	struct packet_capture capture;
};

int tsg_send_inject_packet(const struct streaminfo *a_stream, enum sapp_inject_opt sio, char *payload, int payload_len, unsigned char raw_route_dir);
unsigned char do_action_redirect_dns(const struct streaminfo *a_stream, Maat_rule_t *p_result, struct compile_user_region *user_region, const void *user_data);

unsigned char send_icmp_unreachable(const struct streaminfo *a_stream);
int send_tamper_xxx(const struct streaminfo *a_stream, long *tamper_count, const void *raw_pkt);

#endif
