#ifndef	__TSG_SEND_LOG_H__
#define	__TSG_SEND_LOG_H__

#include <MESA/Maat_rule.h>

#ifndef	PRINTADDR
#define	PRINTADDR(a, b)	((b)<RLOG_LV_FATAL ? printaddr(&(a->addr), a->threadnum) : "")
#endif

typedef	struct _tsg_log
{
	int result_num;
	Maat_rule_t *result;
	struct streaminfo *a_stream;
}tsg_log_t;

typedef enum _tld_type
{
	TLD_TYPE_UNKNOWN=0,
	TLD_TYPE_LONG=1,
	TLD_TYPE_STRING,
	TLD_TYPE_FILE,
	TLD_TYPE_TOPIC,
	TLD_TYPE_CJSON, // TLD_TYPE_CJSON is obsolete, please use TLD_TYPE_OBJECT
	TLD_TYPE_OBJECT,
	TLD_TYPE_MAX
}TLD_TYPE;

struct TLD_handle_t;
struct tsg_log_instance_t;

extern struct tsg_log_instance_t *g_tsg_log_instance;

struct TLD_handle_t *TLD_create(int thread_id);

int TLD_append(struct TLD_handle_t *handle, char *key, void *value, TLD_TYPE type);
int TLD_append_streaminfo(struct tsg_log_instance_t *instance, struct TLD_handle_t *handle, struct streaminfo *a_stream);
int TLD_cancel(struct TLD_handle_t *handle);
struct TLD_handle_t *TLD_duplicate(struct TLD_handle_t *handle);

int tsg_send_log(struct tsg_log_instance_t *instance, struct TLD_handle_t *handle, tsg_log_t *log_msg, int thread_id);

//return topic_id;  return >=0 if success,otherwise return -1;
int tsg_register_topic(struct tsg_log_instance_t *instance, char *topic_name);
int tsg_send_payload(struct tsg_log_instance_t *instance, int topic_id, char *payload, int payload_len, int thread_id);

unsigned long long tsg_get_stream_id(struct streaminfo *a_stream);
char *tsg_l7_protocol_id2name(unsigned int l7_protocol_id);
unsigned int tsg_l7_protocol_name2id(const char *l7_protocol_name);

#endif
