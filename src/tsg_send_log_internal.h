#ifndef	__TSG_SEND_LOG_INTERNAL_H__
#define	__TSG_SEND_LOG_INTERNAL_H__

#include <MESA/rdkafka.h>
#include <MESA/cJSON.h>

#include "tsg_types.h"


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

typedef	struct _id2field
{
	TLD_TYPE type;
	int id;
	char name[MAX_STRING_LEN];
}id2field_t;

struct _tld_handle
{
	int thread_id;
	cJSON *object;
};

struct _tsg_log_instance
{
	int mode;
	int max_service;
	void *logger;
	char common_field_file[MAX_STRING_LEN*4];
	char broker_list[MAX_STRING_LEN*4];
	char local_ip_str[MAX_IPV4_LEN];
	id2field_t id2field[LOG_COMMON_MAX];
	rd_kafka_topic_t **topic_rkt;
	id2field_t *service2topic;
};


char *log_field_id2name(tsg_log_instance_t instance, tsg_log_field_id_t id);
tsg_log_instance_t tsg_sendlog_init(const char *filename);

#endif

