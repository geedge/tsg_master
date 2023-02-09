#include <string.h>
#include <librdkafka/rdkafka.h>

#ifndef	MIN
#define	MIN(a,b)	((a)>(b) ? (b) : (a))
#endif

int g_kafka_sendlog_cnt=0;
char g_kafka_sendlog[16][1024]={0,0};

rd_kafka_conf_t *rd_kafka_conf_new(void)
{
	return (rd_kafka_conf_t *)0x1;
}

rd_kafka_conf_res_t rd_kafka_conf_set(rd_kafka_conf_t *conf, const char *name, const char *value, char *errstr, size_t errstr_size)
{
	return (rd_kafka_conf_res_t)0x1;
}

rd_kafka_t *rd_kafka_new(rd_kafka_type_t type, rd_kafka_conf_t *conf, char *errstr, size_t errstr_size)
{
	return (rd_kafka_t *)0x2;
}

rd_kafka_topic_conf_t* rd_kafka_topic_conf_new(void)
{
	return (rd_kafka_topic_conf_t*)0x3;
}

rd_kafka_topic_t* rd_kafka_topic_new(rd_kafka_t *rk, const char *topic, rd_kafka_topic_conf_t *	conf)
{
	return (rd_kafka_topic_t*)0x4;
}

void rd_kafka_topic_destroy (rd_kafka_topic_t *rkt)
{
}

void rd_kafka_destroy (rd_kafka_t *rk)
{
}

rd_kafka_resp_err_t rd_kafka_last_error(void)
{
	return (rd_kafka_resp_err_t)0x5;
}
const char *rd_kafka_err2name(rd_kafka_resp_err_t err)
{
	return "err2name";
}
const char *rd_kafka_err2str(rd_kafka_resp_err_t err)
{
	return "err2str";
}

int rd_kafka_produce(rd_kafka_topic_t *rkt, int32_t partitition, int msgflags, void *payload, size_t len, const void *key, size_t keylen, void *msg_opaque)
{
	int length=MIN(len, sizeof(g_kafka_sendlog[g_kafka_sendlog_cnt]));
	memcpy((void *)(g_kafka_sendlog[g_kafka_sendlog_cnt++]), payload, length);
	return 0;
}

int rd_kafka_get_sendlog_cnt(void)
{
	return g_kafka_sendlog_cnt;
}

const char *rd_kafka_get_sendlog_payload(int idx)
{
	if(idx>g_kafka_sendlog_cnt || idx <0)
	{
		return NULL;
	}
	return (const char *)g_kafka_sendlog[idx];
}
