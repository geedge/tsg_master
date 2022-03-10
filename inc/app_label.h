#ifndef	__APP_LABEL_H__
#define	__APP_LABEL_H__

#define	MAX_APP_ID_NUM	8

struct app_id_label
{
	int app_id_num;
	unsigned int app_id[MAX_APP_ID_NUM];
	unsigned int surrogate_id[MAX_APP_ID_NUM];
};

struct basic_proto_label
{
	int continue_scan_flag;  //0: stop; 1: continue
	int protocol_id_num;
	unsigned short protocol_id[MAX_APP_ID_NUM];
};


enum APP_IDENTIFY_ORIGIN
{
	ORIGIN_BASIC_PROTOCOL=0,
	ORIGIN_USER_DEFINE,
	ORIGIN_DKPT,
	ORIGIN_QM_ENGINE,
	ORIGIN_BUILT_IN,
	ORIGIN_ANALYZE,
	ORIGIN_UNKNOWN,		// unknown app ID=4
	ORIGIN_MAX
};


struct app_identify_result
{
	enum APP_IDENTIFY_ORIGIN origin;
	int app_id_num;
	unsigned int app_id[MAX_APP_ID_NUM];
	unsigned int surrogate_id[MAX_APP_ID_NUM];
};

enum _ATTRIBUTE_TYPE
{
	ATTRIBUTE_TYPE_UNKNOWN,
	ATTRIBUTE_TYPE_IP,
	ATTRIBUTE_TYPE_STRING,
	ATTRIBUTE_TYPE_NUMERIC,
	ATTRIBUTE_TYPE_BOOL,
	_ATTRIBUTE_TYPE_MAX
};

struct attribute_kv
{
	enum _ATTRIBUTE_TYPE type;
	char *name;
	void *value;
};

struct user_defined_attribute_label
{
	int attribute_num;
	struct attribute_kv *attribute;
};

#endif
