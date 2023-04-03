#pragma once

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
	ORIGIN_HITED_APP,
	ORIGIN_QM_ENGINE,
	ORIGIN_BUILT_IN,
	ORIGIN_ANALYZE,
	ORIGIN_UNKNOWN,		// 0: unknown app ID=4;	1: hited app id; app_num=1
	ORIGIN_QM_ENGINE_L7,
	ORIGIN_MAX
};


struct app_identify_result
{
	enum APP_IDENTIFY_ORIGIN origin;
	int app_id_num;
	unsigned int app_id[MAX_APP_ID_NUM];
	unsigned int surrogate_id[MAX_APP_ID_NUM];
};

enum LUA_ATTRIBUTE_TYPE
{
	LUA_ATTRIBUTE_TYPE_UNKNOWN,
	LUA_ATTRIBUTE_TYPE_IP,
	LUA_ATTRIBUTE_TYPE_STRING,
	LUA_ATTRIBUTE_TYPE_NUMERIC,
	LUA_ATTRIBUTE_TYPE_BOOL,
	LUA_ATTRIBUTE_TYPE_MAX
};

struct attribute_kv
{
	enum LUA_ATTRIBUTE_TYPE type;
	char *name;
	union
	{
		unsigned int number;
		char *ip;
		char *string;
		void *value;
	};
};

struct user_defined_attribute
{
	int n_akv;
	struct attribute_kv *akv;
};

