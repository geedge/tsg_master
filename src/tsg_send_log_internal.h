#ifndef	__TSG_SEND_LOG_INTERNAL_H__
#define	__TSG_SEND_LOG_INTERNAL_H__

#include <librdkafka/rdkafka.h>
#include <MESA/cJSON.h>
#include <time.h>



#define	MAX_IPV4_LEN	16
#define	MAX_STRING_LEN	32

enum _SEND_MODE
{
	CLOSE=0,
	KAFKA=1,
};

enum _DO_LOG
{
	LOG_ABORT=0,
	LOG_NOFILE=1,
	LOG_ALL=2
};

typedef enum _tsg_log_field_id
{
	LOG_COMMON_POLICY_ID=1,
	LOG_COMMON_SERVICE,
	LOG_COMMON_ACTION,
	LOG_COMMON_START_TIME,
	LOG_COMMON_END_TIME,
	LOG_COMMON_L4_PROTOCOL,
	LOG_COMMON_ADDRESS_TYPE,
	LOG_COMMON_SERVER_IP,
	LOG_COMMON_CLIENT_IP,
	LOG_COMMON_SERVER_PORT,
	LOG_COMMON_CLIENT_PORT,
	LOG_COMMON_STREAM_DIR,
	LOG_COMMON_ADDRESS_LIST,
	LOG_COMMON_ENTRANCE_ID,
	LOG_COMMON_DEVICE_ID,
	LOG_COMMON_LINK_ID,
	LOG_COMMON_ISP,
	LOG_COMMON_ENCAPSULATION,
	LOG_COMMON_DIRECTION,
	LOG_COMMON_SLED_IP,	
	LOG_COMMON_USER_TAG,
	LOG_COMMON_USER_REGION,
	LOG_COMMON_APP_LABEL,
	LOG_COMMON_APP_ID,
	LOG_COMMON_PROTOCOL_ID,
	LOG_COMMON_C2S_PKT_NUM,
	LOG_COMMON_S2C_PKT_NUM,
	LOG_COMMON_C2S_BYTE_NUM,
	LOG_COMMON_S2C_BYTE_NUM,
	LOG_COMMON_CON_DURATION_MS,
	LOG_COMMON_HAS_DUP_TRAFFIC,
	LOG_COMMON_STREAM_ERROR,
	LOG_COMMON_STREAM_TRACE_ID,
	LOG_COMMON_SCHAME_TYPE,
	LOG_HTTP_HOST,
	LOG_SSL_SNI,
	LOG_COMMON_ESTABLISH_LATENCY_MS,
	LOG_COMMON_SUB_ACTION,
	LOG_COMMON_CLINET_ASN,
	LOG_COMMON_SERVER_ASN,
	LOG_COMMON_CLINET_LOCATION,
	LOG_COMMON_SERVER_LOCATION,
	LOG_QUIC_SNI,
	LOG_SSL_JA3_FINGERPRINT,
	LOG_COMMON_DATA_CENTER,
	LOG_COMMON_L7_PROTOCOL,
	LOG_COMMON_MAX
}tsg_log_field_id_t;

typedef	struct _id2field
{
	TLD_TYPE type;
	int id;
	char name[MAX_STRING_LEN];
}id2field_t;

struct TLD_handle_t
{
	int thread_id;
	cJSON *object;
};

struct tsg_log_instance_t
{
	int mode;
	int level;
	int max_service;	
	int recovery_interval;
	int internal_project_id;
	int tcp_flow_project_id;
	int udp_flow_project_id;
	int *send_log_percent;
	int *fs_status_ids;
	struct timespec *drop_start;
	char log_path[MAX_STRING_LEN*2];
	char tcp_label[MAX_STRING_LEN];
	char udp_label[MAX_STRING_LEN];
	char common_field_file[MAX_STRING_LEN*4];
	char broker_list[MAX_STRING_LEN*4];
	char send_queue_max_msg[MAX_STRING_LEN];
	char require_ack[MAX_STRING_LEN];
	char refresh_interval_ms[MAX_STRING_LEN];
	char local_ip_str[MAX_IPV4_LEN];
	id2field_t id2field[LOG_COMMON_MAX];
	rd_kafka_topic_t **topic_rkt;
	id2field_t *service2topic;	
	void *logger;
};

char *log_field_id2name(struct tsg_log_instance_t *instance, tsg_log_field_id_t id);
struct tsg_log_instance_t *tsg_sendlog_init(const char *filename);

#endif

