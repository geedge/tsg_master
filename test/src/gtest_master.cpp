#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "gtest_common.h"
#include "tsg_rule.h"
#include "tsg_entry.h"
#include <gtest/gtest.h>

extern int rd_kafka_get_sendlog_cnt(void);
extern const char *rd_kafka_get_sendlog_payload(int idx);

TEST(TSGMaster, SetAPPIDHttp)
{
	struct streaminfo a_stream={0};
	struct gather_app_result gather_result[ORIGIN_MAX]={0};

	gather_result[ORIGIN_BASIC_PROTOCOL].app_num=1;
	gather_result[ORIGIN_BASIC_PROTOCOL].origin=ORIGIN_BASIC_PROTOCOL;
	gather_result[ORIGIN_BASIC_PROTOCOL].attributes[0].app_id=67;	//HTTP
	
	tsg_set_xxx_to_bridge(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_GATHER_APP_RESULT].id, (void *)gather_result);
	struct gather_app_result *get_result=(struct gather_app_result *)tsg_get_xxx_from_bridge(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_GATHER_APP_RESULT].id);
	EXPECT_NE(nullptr, get_result);
	EXPECT_EQ(1, get_result[ORIGIN_BASIC_PROTOCOL].app_num);
	EXPECT_EQ(67, get_result[ORIGIN_BASIC_PROTOCOL].attributes[0].app_id);
	EXPECT_EQ(0, get_result[ORIGIN_BASIC_PROTOCOL].attributes[0].packet_sequence);
	EXPECT_EQ(0, get_result[ORIGIN_BASIC_PROTOCOL].attributes[0].surrogate_id);
	EXPECT_EQ(ORIGIN_BASIC_PROTOCOL, get_result[ORIGIN_BASIC_PROTOCOL].origin);

	struct TLD_handle_t *handle=TLD_create(0);
	set_app_id(g_tsg_log_instance, handle, (struct streaminfo *)&a_stream);
	char app_ids[256]={0};
	TLD_convert_json(handle, app_ids, sizeof(app_ids));
	EXPECT_STREQ("{\"common_app_full_path\":\"http\",\"common_app_label\":\"http\"}", app_ids);

	
	tsg_set_xxx_to_bridge(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_GATHER_APP_RESULT].id, NULL);
	get_result=(struct gather_app_result *)tsg_get_xxx_from_bridge(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_GATHER_APP_RESULT].id);
	EXPECT_EQ(nullptr, get_result);
}

TEST(TSGMaster, SetAPPIDUnknown)
{
	struct streaminfo a_stream={0};

	struct TLD_handle_t *handle=TLD_create(0);
	set_app_id(g_tsg_log_instance, handle, (struct streaminfo *)&a_stream);
	char app_ids[256]={0};
	TLD_convert_json(handle, app_ids, sizeof(app_ids));
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\"}", app_ids);
}


TEST(TSGMaster, ShapingSetRuleIds)
{
	const struct streaminfo a_stream={0};
	struct Maat_rule_t shaping_result[MAX_RESULT_NUM]={0};

	for(int i=0; i<MAX_RESULT_NUM; i++)
	{
		shaping_result[i].action=TSG_ACTION_SHAPING;
		shaping_result[i].config_id=TSG_ACTION_SHAPING+i;
	}
	
	tsg_notify_hited_shaping_result(&a_stream, shaping_result, MAX_RESULT_NUM, 0);

	struct TLD_handle_t *handle=TLD_create(0);
	set_shaping_rule_ids(g_tsg_log_instance, handle, (struct streaminfo *)&a_stream);
	char shaping_rule_ids[256]={0};
	TLD_convert_json(handle, shaping_rule_ids, sizeof(shaping_rule_ids));
	EXPECT_STREQ("{\"common_shaping_rule_ids\":[32,33,34,35,36,37,38,39]}", shaping_rule_ids);

	struct notify_shaping_policy *shaping_label=(struct notify_shaping_policy *)stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id);
	EXPECT_NE(nullptr, shaping_label);
	EXPECT_EQ(MAX_RESULT_NUM, shaping_label->shaping_result_num);
	for(int i=0; i<shaping_label->shaping_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, shaping_label->shaping_result[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, shaping_label->shaping_result[i].config_id);
	}
	
	free_shaping_result(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id, (void *)shaping_label);
	stream_bridge_async_data_put(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id, NULL);
	EXPECT_EQ(nullptr, stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id));
}

int shaping_policy_notify_cb(const struct streaminfo *stream, int bridge_id, void *data)
{
	struct notify_shaping_policy *shaping_label=(struct notify_shaping_policy *)data;
	EXPECT_NE(nullptr, shaping_label);
	EXPECT_EQ(MAX_RESULT_NUM, shaping_label->shaping_result_num);
	for(int i=0; i<shaping_label->shaping_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, shaping_label->shaping_result[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, shaping_label->shaping_result[i].config_id);
	}
	
	return 0;
}

TEST(TSGMaster, ShapingPolicyNotify)
{
	const struct streaminfo a_stream={0};
	struct Maat_rule_t shaping_result[MAX_RESULT_NUM]={0};

	for(int i=0; i<MAX_RESULT_NUM; i++)
	{
		shaping_result[i].action=TSG_ACTION_SHAPING;
		shaping_result[i].config_id=TSG_ACTION_SHAPING+i;
	}

	stream_bridge_register_data_sync_cb(g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id, shaping_policy_notify_cb);
	
	tsg_notify_hited_shaping_result(&a_stream, shaping_result, MAX_RESULT_NUM, 0);
	int shaping_result_num=tsg_pull_shaping_result((struct streaminfo *)&a_stream, shaping_result, MAX_RESULT_NUM);
	EXPECT_EQ(MAX_RESULT_NUM, shaping_result_num);
	for(int i=0; i<shaping_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, shaping_result[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, shaping_result[i].config_id);
	}
	
	struct notify_shaping_policy *shaping_label=(struct notify_shaping_policy *)stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id);
	EXPECT_NE(nullptr, shaping_label);
	EXPECT_EQ(MAX_RESULT_NUM, shaping_label->shaping_result_num);
	for(int i=0; i<shaping_label->shaping_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, shaping_label->shaping_result[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, shaping_label->shaping_result[i].config_id);
	}

	free_shaping_result(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id, (void *)shaping_label);
	stream_bridge_async_data_put(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id, NULL);
	EXPECT_EQ(nullptr, stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id));
}

int shaping_policy_notify_null_cb(const struct streaminfo *stream, int bridge_id, void *data)
{
	EXPECT_EQ(nullptr, data);
	return 0;
}

TEST(TSGMaster, ShapingPolicyNotifyNULL)
{
	const struct streaminfo a_stream={0};
	struct Maat_rule_t shaping_result[MAX_RESULT_NUM]={0};

	stream_bridge_register_data_sync_cb(g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id, shaping_policy_notify_null_cb);
	
	tsg_notify_hited_shaping_result(&a_stream, shaping_result, 0, 0);
	struct notify_shaping_policy *shaping_label=(struct notify_shaping_policy *)stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id);
	EXPECT_EQ(nullptr, shaping_label);
}

int shaping_duplicate_policy_notify_cb(const struct streaminfo *stream, int bridge_id, void *data)
{
	struct notify_shaping_policy *shaping_label=(struct notify_shaping_policy *)data;
	EXPECT_NE(nullptr, shaping_label);
	EXPECT_EQ(MAX_RESULT_NUM/2, shaping_label->shaping_result_num);
	for(int i=0; i<shaping_label->shaping_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, shaping_label->shaping_result[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, shaping_label->shaping_result[i].config_id);
	}

	return 0;
}

TEST(TSGMaster, ShapingDuplicatePolicyNotify)
{
	const struct streaminfo a_stream={0};
	struct Maat_rule_t shaping_result[MAX_RESULT_NUM]={0};

	for(int i=0; i<MAX_RESULT_NUM; i++)
	{
		shaping_result[i].action=TSG_ACTION_SHAPING;
		shaping_result[i].config_id=TSG_ACTION_SHAPING+(i%4);
	}

	stream_bridge_register_data_sync_cb(g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id, shaping_duplicate_policy_notify_cb);
	
	tsg_notify_hited_shaping_result(&a_stream, shaping_result, MAX_RESULT_NUM, 0);
	int shaping_result_num=tsg_pull_shaping_result((struct streaminfo *)&a_stream, shaping_result, MAX_RESULT_NUM);
	EXPECT_EQ(MAX_RESULT_NUM/2, shaping_result_num);
	for(int i=0; i<shaping_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, shaping_result[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, shaping_result[i].config_id);
	}
	
	struct notify_shaping_policy *shaping_label=(struct notify_shaping_policy *)stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id);
	EXPECT_NE(nullptr, shaping_label);
	EXPECT_EQ(MAX_RESULT_NUM/2, shaping_label->shaping_result_num);
	for(int i=0; i<shaping_label->shaping_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, shaping_label->shaping_result[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, shaping_label->shaping_result[i].config_id);
	}

	free_shaping_result(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id, (void *)shaping_label);
	stream_bridge_async_data_put(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id, NULL);
	EXPECT_EQ(nullptr, stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id));
}

TEST(TSGMaster, ShapingDuplicatePolicyMultipleNotify)
{
	const struct streaminfo a_stream={0};
	struct Maat_rule_t shaping_result[MAX_RESULT_NUM]={0};

	for(int i=0; i<MAX_RESULT_NUM/2; i++)
	{
		shaping_result[i].action=TSG_ACTION_SHAPING;
		shaping_result[i].config_id=TSG_ACTION_SHAPING+i;
	}

	stream_bridge_register_data_sync_cb(g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id, shaping_duplicate_policy_notify_cb);

	// First notify
	tsg_notify_hited_shaping_result(&a_stream, shaping_result, MAX_RESULT_NUM/2, 0);
	int shaping_result_num=tsg_pull_shaping_result((struct streaminfo *)&a_stream, shaping_result, MAX_RESULT_NUM);
	EXPECT_EQ(MAX_RESULT_NUM/2, shaping_result_num);
	for(int i=0; i<shaping_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, shaping_result[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, shaping_result[i].config_id);
	}
	
	struct notify_shaping_policy *shaping_label=(struct notify_shaping_policy *)stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id);
	EXPECT_NE(nullptr, shaping_label);
	EXPECT_EQ(MAX_RESULT_NUM/2, shaping_label->shaping_result_num);
	for(int i=0; i<shaping_label->shaping_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, shaping_label->shaping_result[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, shaping_label->shaping_result[i].config_id);
	}

	// Second notify
	tsg_notify_hited_shaping_result(&a_stream, shaping_result, MAX_RESULT_NUM/2, 0);
	shaping_result_num=tsg_pull_shaping_result((struct streaminfo *)&a_stream, shaping_result, MAX_RESULT_NUM);
	EXPECT_EQ(MAX_RESULT_NUM/2, shaping_result_num);
	for(int i=0; i<shaping_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, shaping_result[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, shaping_result[i].config_id);
	}
	
	shaping_label=(struct notify_shaping_policy *)stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id);
	EXPECT_NE(nullptr, shaping_label);
	EXPECT_EQ(MAX_RESULT_NUM/2, shaping_label->shaping_result_num);
	for(int i=0; i<shaping_label->shaping_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, shaping_label->shaping_result[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, shaping_label->shaping_result[i].config_id);
	}

	free_shaping_result(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id, (void *)shaping_label);
	stream_bridge_async_data_put(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id, NULL);
	EXPECT_EQ(nullptr, stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].id));
}

TEST(TSGMaster, SecurityPolicySendlog)
{
	const struct streaminfo a_stream={0};
	struct Maat_rule_t security_result[MAX_RESULT_NUM]={0};

	for(int i=0; i<MAX_RESULT_NUM; i++)
	{
		security_result[i].do_log=1;
		security_result[i].action=TSG_ACTION_MONITOR;
		security_result[i].config_id=TSG_ACTION_MONITOR+i;
	}

	// First notify
	tsg_notify_hited_security_result(&a_stream, security_result, MAX_RESULT_NUM, 0);
	
	struct policy_priority_label *priority_label=(struct policy_priority_label *)tsg_get_xxx_from_bridge(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id);
	EXPECT_NE(nullptr, priority_label);
	EXPECT_EQ(MAX_RESULT_NUM, priority_label->security_result_num);
	for(int i=0; i<priority_label->security_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_MONITOR, priority_label->security_result[i].action);
		EXPECT_EQ(TSG_ACTION_MONITOR+i, priority_label->security_result[i].config_id);
	}

	struct TLD_handle_t * handle=TLD_create(0);
	struct Maat_rule_t session_record={0, 2, 1, 0, 0, 0, 0, {0}};
	tsg_log_t log_msg={1, &session_record, (struct streaminfo*)&a_stream};
	tsg_send_log(g_tsg_log_instance, handle, &log_msg, 0);

	int sendlog_cnt=rd_kafka_get_sendlog_cnt();
	EXPECT_EQ(8, sendlog_cnt);
	//EXPECT_STREQ("{}", rd_kafka_get_sendlog_payload(0));
	//EXPECT_STREQ("{}", rd_kafka_get_sendlog_payload(1));
	//EXPECT_STREQ("{}", rd_kafka_get_sendlog_payload(2));
	//EXPECT_STREQ("{}", rd_kafka_get_sendlog_payload(3));
	//EXPECT_STREQ("{}", rd_kafka_get_sendlog_payload(4));
	//EXPECT_STREQ("{}", rd_kafka_get_sendlog_payload(5));
	//EXPECT_STREQ("{}", rd_kafka_get_sendlog_payload(6));
	//EXPECT_STREQ("{}", rd_kafka_get_sendlog_payload(7));
	//EXPECT_STREQ("{}", rd_kafka_get_sendlog_payload(8));

	priority_label=(struct policy_priority_label *)tsg_get_xxx_from_bridge(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id);
	EXPECT_EQ(nullptr, priority_label);
}

TEST(TSGMaster, SecurityDuplicatePolicyMultipleNotify)
{
	const struct streaminfo a_stream={0};
	struct Maat_rule_t security_result[MAX_RESULT_NUM]={0};

	for(int i=0; i<MAX_RESULT_NUM/2; i++)
	{
		security_result[i].action=TSG_ACTION_MONITOR;
		security_result[i].config_id=TSG_ACTION_MONITOR+i;
	}

	// First notify
	tsg_notify_hited_security_result(&a_stream, security_result, MAX_RESULT_NUM/2, 0);
	
	struct policy_priority_label *priority_label=(struct policy_priority_label *)tsg_get_xxx_from_bridge(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id);
	EXPECT_NE(nullptr, priority_label);
	EXPECT_EQ(MAX_RESULT_NUM/2, priority_label->security_result_num);
	for(int i=0; i<priority_label->security_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_MONITOR, priority_label->security_result[i].action);
		EXPECT_EQ(TSG_ACTION_MONITOR+i, priority_label->security_result[i].config_id);
	}

	// Second notify
	tsg_notify_hited_security_result(&a_stream, security_result, MAX_RESULT_NUM/2, 0);
	
	priority_label=(struct policy_priority_label *)tsg_get_xxx_from_bridge(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id);
	EXPECT_NE(nullptr, priority_label);
	EXPECT_EQ(MAX_RESULT_NUM/2, priority_label->security_result_num);
	for(int i=0; i<priority_label->security_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_MONITOR, priority_label->security_result[i].action);
		EXPECT_EQ(TSG_ACTION_MONITOR+i, priority_label->security_result[i].config_id);
	}

	free_shaping_result(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id, (void *)priority_label);
	stream_bridge_async_data_put(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id, NULL);
	EXPECT_EQ(nullptr, stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id));
}

extern void set_security_result_to_project(const struct streaminfo *a_stream, struct Maat_rule_t *p_result, int p_result_num, PULL_RESULT_TYPE result_type, int thread_seq);

TEST(TSGMaster, SecurityPolicyIntercept)
{
	const struct streaminfo a_stream={0};
	struct Maat_rule_t security_result[MAX_RESULT_NUM]={0};
	struct identify_info identify_info;

	security_result[1].action=TSG_ACTION_INTERCEPT;
	security_result[1].config_id=TSG_ACTION_INTERCEPT;

	// Set Intercept
	set_security_result_to_project((struct streaminfo *)&a_stream, &security_result[1], 1, PULL_KNI_RESULT, 0);

	int ret=tsg_pull_policy_result((struct streaminfo *)&a_stream, PULL_FW_RESULT, &(security_result[2]), 1, &identify_info);
	EXPECT_EQ(0, ret);

	ret=tsg_pull_policy_result((struct streaminfo *)&a_stream, PULL_KNI_RESULT, &(security_result[2]), 1, &identify_info);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, security_result[2].action);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, security_result[2].config_id);
	
	ret=tsg_pull_policy_result((struct streaminfo *)&a_stream, PULL_ALL_RESULT, &(security_result[2]), 1, &identify_info);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, security_result[2].action);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, security_result[2].config_id);

	struct policy_priority_label *priority_label=(struct policy_priority_label *)tsg_get_xxx_from_bridge(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id);
	EXPECT_NE(nullptr, priority_label);	
	EXPECT_EQ(1, priority_label->security_result_num);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, priority_label->security_result[0].action);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, priority_label->security_result[0].config_id);

	free_policy_label(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id, (void *)priority_label);
	stream_bridge_async_data_put(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id, NULL);
	EXPECT_EQ(nullptr, stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id));
}


TEST(TSGMaster, SecurityMultiplePolicyMonitorToIntercept)
{
	const struct streaminfo a_stream={0};
	struct Maat_rule_t security_result[MAX_RESULT_NUM]={0};
	struct identify_info identify_info;

	security_result[0].action=TSG_ACTION_MONITOR;
	security_result[0].config_id=TSG_ACTION_MONITOR;

	security_result[1].action=TSG_ACTION_INTERCEPT;
	security_result[1].config_id=TSG_ACTION_INTERCEPT;

	// First Monitor, second Intercpt
	tsg_notify_hited_security_result(&a_stream, &security_result[0], 1, 0);

	int ret=tsg_pull_policy_result((struct streaminfo *)&a_stream, PULL_KNI_RESULT, &(security_result[2]), 1, &identify_info);
	EXPECT_EQ(0, ret);
	
	ret=tsg_pull_policy_result((struct streaminfo *)&a_stream, PULL_FW_RESULT, &(security_result[2]), 1, &identify_info);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(TSG_ACTION_MONITOR, security_result[2].action);
	EXPECT_EQ(TSG_ACTION_MONITOR, security_result[2].config_id);

	ret=tsg_pull_policy_result((struct streaminfo *)&a_stream, PULL_ALL_RESULT, &(security_result[2]), 1, &identify_info);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(TSG_ACTION_MONITOR, security_result[2].action);
	EXPECT_EQ(TSG_ACTION_MONITOR, security_result[2].config_id);

	// Set Intercept
	set_security_result_to_project((struct streaminfo *)&a_stream, &security_result[1], 1, PULL_KNI_RESULT, 0);

	ret=tsg_pull_policy_result((struct streaminfo *)&a_stream, PULL_FW_RESULT, &(security_result[2]), 1, &identify_info);
	EXPECT_EQ(0, ret);

	ret=tsg_pull_policy_result((struct streaminfo *)&a_stream, PULL_KNI_RESULT, &(security_result[2]), 1, &identify_info);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, security_result[2].action);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, security_result[2].config_id);
	
	ret=tsg_pull_policy_result((struct streaminfo *)&a_stream, PULL_ALL_RESULT, &(security_result[2]), 1, &identify_info);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, security_result[2].action);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, security_result[2].config_id);

	struct policy_priority_label *priority_label=(struct policy_priority_label *)tsg_get_xxx_from_bridge(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id);
	EXPECT_NE(nullptr, priority_label);	
	EXPECT_EQ(1, priority_label->security_result_num);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, priority_label->security_result[0].action);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, priority_label->security_result[0].config_id);

	free_policy_label(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id, (void *)priority_label);
	stream_bridge_async_data_put(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id, NULL);
	EXPECT_EQ(nullptr, stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].id));
}

int main(int argc, char *argv[])
{
	TSG_MASTER_INIT();
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

