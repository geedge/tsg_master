#pragma once

enum DO_LOG
{
	LOG_ABORT=0,
	LOG_ALL=1,
	LOG_NOFILE=2,
};

enum TLD_TYPE
{
	TLD_TYPE_UNKNOWN=0,
	TLD_TYPE_LONG=1,
	TLD_TYPE_STRING,
	TLD_TYPE_FILE,
	TLD_TYPE_TOPIC,
	TLD_TYPE_CJSON, // TLD_TYPE_CJSON is obsolete, please use TLD_TYPE_OBJECT
	TLD_TYPE_OBJECT,
	TLD_TYPE_MAX
};

enum LOG_TYPE
{
	LOG_TYPE_SECURITY_EVENT=0,
	LOG_TYPE_SESSION_RECORD,
	LOG_TYPE_INTERNAL_RTP_RECORD,
	LOG_TYPE_VOIP_RECORD,
	LOG_TYPE_INTERIM_SESSION_RECORD,
	LOG_TYPE_TRANSACTION_RECORD,
	LOG_TYPE_GTPC_RECORD,
	LOG_TYPE_BGP_RECORD,
	LOG_TYPE_INTERCEPT_EVENT
};

struct TLD_handle_t;
struct tsg_log_instance_t;

extern struct tsg_log_instance_t *g_tsg_log_instance;

struct TLD_handle_t *TLD_create(int thread_id);
int TLD_search(struct TLD_handle_t *handle, char *key);
int TLD_append(struct TLD_handle_t *handle, char *key, void *value, enum TLD_TYPE type);
struct TLD_handle_t *TLD_duplicate(struct TLD_handle_t *handle);
//type only TLD_TYPE_LONG/TLD_TYPE_STRING
int TLD_array_append(struct TLD_handle_t *handle, char *key, void **array, int array_num, enum TLD_TYPE type);
int TLD_append_streaminfo(struct tsg_log_instance_t *instance, struct TLD_handle_t *handle, const struct streaminfo *a_stream);
int TLD_cancel(struct TLD_handle_t *handle);

//return topic_id;  return >=0 if success,otherwise return -1;
int tsg_register_topic(struct tsg_log_instance_t *instance, const char *topic_name);
int tsg_send_payload(struct tsg_log_instance_t *instance, int topic_id, char *payload, int payload_len, int thread_id);
int tsg_send_log(struct tsg_log_instance_t *instance, struct TLD_handle_t *handle, const struct streaminfo *a_stream, enum LOG_TYPE log_type, struct maat_rule *rules, size_t n_rules, int thread_id);

unsigned long long tsg_get_stream_trace_id(const struct streaminfo *a_stream);
const char *tsg_l7_protocol_id2name(unsigned int l7_protocol_id);
unsigned int tsg_l7_protocol_name2id(const char *l7_protocol_name, unsigned int l7_protocol_name_len);

