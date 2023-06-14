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
	unsigned short app_name_len;
	unsigned short parent_app_name_len;
	char risk_len;
	char category_len;
	char subcategory_len;
	char technology_len;
	char characteristics_len;
	char padding[3];
	int tcp_time_wait;
	int tcp_half_close;
	char *app_name;
	char *parent_app_name;
	char *risk;
	char *category;
	char *subcategory;
	char *technology;
	char *characteristics;
	struct deny_user_region deny_app_para;
};

typedef enum tsg_statis_field_id
{
	STATIS_SESSIONS = 0,
	STATIS_ACTIVE_SESSIONS,
	STATIS_CLOSE_SESSIONS,
	STATIS_IN_BYTES,
	STATIS_OUT_BYTES,
	STATIS_IN_PACKETS,
	STATIS_OUT_PACKETS,
	STATIC_ASYMMETRIC_C2S_FLOWS,
	STATIC_ASYMMETRIC_S2C_FLOWS,
	STATIS_MAX
} tsg_statis_field_id_t;

enum security_metric_columns
{
	COLUMN_HIT_COUNT = 0,
	COLUMN_IN_BYTES,
	COLUMN_OUT_BYTES,
	COLUMN_IN_PKTS,
	COLUMN_OUT_PKTS,
	COLUMN_MAX
};

enum app_metric_columns
{
	TRAFFIC_APP_SESSIONS = 0,
	TRAFFIC_APP_IN_BYTES,
	TRAFFIC_APP_OUT_BYTES,
	TRAFFIC_APP_IN_PKTS,
	TRAFFIC_APP_OUT_PKTS,
	TRAFFIC_APP_C2S_PKTS,
	TRAFFIC_APP_S2C_PKTS,
	TRAFFIC_APP_C2S_BYTES,
	TRAFFIC_APP_S2C_BYTES,
	TRAFFIC_APP_C2S_FRAGMENTS,
	TRAFFIC_APP_S2C_FRAGMENTS,
	TRAFFIC_APP_C2S_LOST_BYTES,
	TRAFFIC_APP_S2C_LOST_BYTES,
	TRAFFIC_APP_C2S_ORDER_PKTS,
	TRAFFIC_APP_S2C_ORDER_PKTS,
	TRAFFIC_APP_C2S_RETRANSMITTED_PKTS,
	TRAFFIC_APP_S2C_RETRANSMITTED_PKTS,
	TRAFFIC_APP_C2S_RETRANSMITTED_BYTES,
	TRAFFIC_APP_S2C_RETRANSMITTED_BYTES,
	TRAFFIC_APP_MAX
};

struct tsg_statistic
{
	int vsystem_id;

	int cycle;
	int thread_alive;
	pthread_t stat_thread_id;
	long long statistic_opt[_OPT_TYPE_MAX];

	int static_table_id;
	int static_column_id[STATIS_MAX];
	struct fieldstat_instance *statistic_handle;

	int metric_cycle;
	int metric_table_id;
	unsigned int security_column_ids[COLUMN_MAX];
	struct fieldstat_dynamic_instance *security_metric_handle;

	int app_metric_cycle;
	int app_metric_table_id;
	unsigned int app_column_ids[TRAFFIC_APP_MAX];
	struct fieldstat_dynamic_instance *app_metric_handle;
};

int tsg_metric_init(const char *conffile, void *logger);
void tsg_metric_destroy(void);

int tsg_gtp_signaling_hash_init(const char* conffile, void *logger);

int session_application_full_path_update(const struct streaminfo *a_stream, char *app_full_path, int app_full_path_len);

