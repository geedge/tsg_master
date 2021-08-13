#ifndef	__TSG_SEND_LOG_H__
#define	__TSG_SEND_LOG_H__

#include <MESA/Maat_rule.h>

#ifndef	PRINTADDR
#define	PRINTADDR(a, b)	((b)<RLOG_LV_FATAL ? printaddr(&(a->addr), a->threadnum) : "")
#endif

#include "rapidjson/document.h"     // rapidjson's DOM-style API
#include "rapidjson/prettywriter.h" // for stringify JSON
#include "rapidjson/stringbuffer.h"

using namespace rapidjson;
using namespace std;

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

struct TLD_handle_t
{
	int thread_id;
	Document *document;
};

struct tsg_log_instance_t;

extern struct tsg_log_instance_t *g_tsg_log_instance;

struct TLD_handle_t *TLD_create(int thread_id);

/* You can add the same key multiple times without being overwritten
 *
 * Value array(kArrayType);
 * array.PushBack(elem1, handle->document->GetAllocator());
 * array.PushBack(elem2, handle->document->GetAllocator());
 * array.PushBack(elem3, handle->document->GetAllocator());
 * TLD_append(handle, key_string, &val_array, TLD_TYPE_OBJECT);
 *
 * Value object(kObjectType);
 * object.AddMember("key1", val1, handle->document->GetAllocator());
 * object.AddMember("key2", val2, handle->document->GetAllocator());
 * object.AddMember("key3", val2, handle->document->GetAllocator());
 * TLD_append(handle, key_string, &object, TLD_TYPE_OBJECT);
 *
 * TLD_append(handle, key_string, (void *)val_long, TLD_TYPE_LONG);
 * TLD_append(handle, key_string, (void *)val_string, TLD_TYPE_STRING);
 */
int TLD_append(struct TLD_handle_t *handle, char *key, void *value, TLD_TYPE type);
int TLD_append_streaminfo(struct tsg_log_instance_t *instance, struct TLD_handle_t *handle, struct streaminfo *a_stream);
int TLD_cancel(struct TLD_handle_t *handle);

int tsg_send_log(struct tsg_log_instance_t *instance, struct TLD_handle_t *handle, tsg_log_t *log_msg, int thread_id);

unsigned long long tsg_get_stream_id(struct streaminfo *a_stream);
char *tsg_l7_protocol_id2name(unsigned int l7_protocol_id);
unsigned int tsg_l7_protocol_name2id(const char *l7_protocol_name);

#endif
