#ifndef	__APP_LABEL_H__
#define	__APP_LABEL_H__

struct app_id_label
{
	int surrogate_id;
	int app_id;
};

struct basic_proto_label
{
	unsigned char continue_scan_flag;  //0: stop; 1: continue
	unsigned char pad;
	unsigned short proto_id;
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
