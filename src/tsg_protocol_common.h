#ifndef	__TSG_PROTOCOL_COMMON_H__
#define	__TSG_PROTOCOL_COMMON_H__

#include <MESA/stream.h>
#include "tsg_rule.h"

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

struct deny_user_region
{
	enum TSG_DENY_TYPE type;
	union
	{
		int code;
		int records_num;
	};
	union
	{
		char *message;
		char *redirect_url_to;
		struct dns_user_region *records;
		int profile_id;
		int bps;
		void *para;
	};
};

struct monitor_user_region
{
	int enabled;
	int vlan_id;
};

struct compile_user_region
{	
	int ref_cnt;
	enum TSG_METHOD_TYPE method_type;
	union	
	{
		struct deny_user_region *deny;		
		struct monitor_user_region *mirror;		
		struct Maat_rule_t *result;				//XJ default policy
		void *user_region_para;
	};
};

int tsg_send_inject_packet(const struct streaminfo *a_stream, enum sapp_inject_opt sio, char *payload, int payload_len, unsigned char raw_route_dir);
unsigned char do_action_redirect_dns(const struct streaminfo *a_stream, Maat_rule_t *p_result, struct compile_user_region *user_region, const void *user_data);


#endif
