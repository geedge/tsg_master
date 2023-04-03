#pragma once

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include <MESA/dns.h>

#include <MESA/field_stat2.h>

#include "uthash.h"
#include "tsg_rule.h"
#include "app_label.h"
#include "tsg_label.h"
#include "tsg_bridge.h"
#include "tsg_variable.h"
#include "tsg_statistic.h"
#include "tsg_leaky_bucket.h"
#include "tsg_protocol_common.h"
#include "tsg_send_log_internal.h"

#if(__GNUC__ * 100 + __GNUC_MINOR__ * 10 + __GNUC_PATCHLEVEL__ >= 411)
#define atomic_inc(x) __sync_add_and_fetch((x),1)
#define atomic_dec(x) __sync_sub_and_fetch((x),1)
#define atomic_add(x,y) __sync_add_and_fetch((x),(y))
#define atomic_sub(x,y) __sync_sub_and_fetch((x),(y))
typedef int atomic_t;
#define ATOMIC_INIT(i)  { (i) }
#define atomic_read(x) __sync_add_and_fetch((x),0)
#define atomic_set(x,y) __sync_lock_test_and_set((x),y)
#else 
#include <alsa/iatomic.h>
#endif 

#ifndef	TM_FALSE
#define	TM_FALSE	0
#endif

#ifndef	TM_TRUE
#define TM_TRUE	1
#endif


#ifndef	FLAG_FALSE
#define	FLAG_FALSE	0
#endif

#ifndef	FLAG_TRUE
#define FLAG_TRUE	1
#endif

#define	APP_SCAN_FLAG_STOP	0
#define	APP_SCAN_FLAG_CONTINUE	1

enum HTTP_RESPONSE_FORMAT
{
	HTTP_RESPONSE_FORMAT_TEMPLATE=0,
	HTTP_RESPONSE_FORMAT_HTML
};

struct fqdn_category
{
	int ref_cnt;
	unsigned int category_id;
};

struct http_response_pages
{
	int profile_id;
	int content_len;
	int ref_cnt;	
	enum HTTP_RESPONSE_FORMAT format;
	char *content;
};

struct app_id_dict
{
	int ref_cnt;
	int app_id;
	int parent_app_id;
	int continue_scanning;
	unsigned short tcp_timeout;
	unsigned short udp_timeout;
	int tcp_time_wait;
	int tcp_half_close;
	char *risk;
	char *app_name;
	char *parent_app_name;
	char *category;
	char *subcategory;
	char *technology;
	char *characteristics;
	struct deny_user_region deny_app_para;
};

typedef enum tsg_statis_field_id
{
	STATIS_UNKNOWN=0,
	STATIS_ENTRANCE_ID=1,
	STATIS_TOTAL_CON_NUM,
	STATIS_NEW_CON_NUM,
	STATIS_ESTABLISHED_CON_NUM,
	STATIS_CLOSE_CON_NUM,
	STATIS_TOTAL_IN_BYTES,
	STATIS_TOTAL_OUT_BYTES,
	STATIS_TOTAL_IN_PACKETS,
	STATIS_TOTAL_OUT_PACKETS,
	STATIS_DEFAULT_CON_NUM,
	STATIS_DEFAULT_IN_BYTES,
	STATIS_DEFAULT_OUT_BYTES,
	STATIS_DEFAULT_IN_PACKETS,
	STATIS_DEFAULT_OUT_PACKETS,
	STATIS_ALLOW_CON_NUM,
	STATIS_ALLOW_IN_BYTES,
	STATIS_ALLOW_OUT_BYTES,
	STATIS_ALLOW_IN_PACKETS,
	STATIS_ALLOW_OUT_PACKETS,
	STATIS_DENY_CON_NUM,
	STATIS_DENY_IN_BYTES,
	STATIS_DENY_OUT_BYTES,
	STATIS_DENY_IN_PACKETS,
	STATIS_DENY_OUT_PACKETS,
	STATIS_MONITOR_CON_NUM,
	STATIS_MONITOR_IN_BYTES,
	STATIS_MONITOR_OUT_BYTES,
	STATIS_MONITOR_IN_PACKETS,
	STATIS_MONITOR_OUT_PACKETS,
	STATIS_INTERCEPT_CON_NUM,
	STATIS_INTERCEPT_IN_BYTES,
	STATIS_INTERCEPT_OUT_BYTES,
	STATIS_INTERCEPT_IN_PACKETS,
	STATIS_INTERCEPT_OUT_PACKETS,
	STATIS_IPV4_IN_BYTES,
	STATIS_IPV4_OUT_BYTES,
	STATIS_IPV4_IN_PACKETS,
	STATIS_IPV4_OUT_PACKETS,
	STATIS_IPV6_IN_BYTES,
	STATIS_IPV6_OUT_BYTES,
	STATIS_IPV6_IN_PACKETS,
	STATIS_IPV6_OUT_PACKETS,
	STATIS_TCP_NEW_CON_NUM,
	STATIS_TCP_IN_BYTES,
	STATIS_TCP_OUT_BYTES,
	STATIS_TCP_IN_PACKETS,
	STATIS_TCP_OUT_PACKETS,
	STATIS_UDP_NEW_CON_NUM,
	STATIS_UDP_IN_BYTES,
	STATIS_UDP_OUT_BYTES,
	STATIS_UDP_IN_PACKETS,
	STATIS_UDP_OUT_PACKETS,
	STATIS_ALERT_BYTES,
	STATIS_BLOCK_BYTES,
	STATIS_PINNING_NUM,
	STATIS_MAYBE_PINNING_NUM,
	STATIS_NOT_PINNING_NUM,
	STATIS_MAX
}tsg_statis_field_id_t;

int tsg_statistic_init(const char *conffile, void *logger);
void tsg_statistic_destroy(void);

int tsg_gtp_signaling_hash_init(const char* conffile, void *logger);

