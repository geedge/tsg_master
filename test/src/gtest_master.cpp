#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "gtest_common.h"
#include "tsg_rule.h"
#include "tsg_entry.h"
#include <gtest/gtest.h>

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
	EXPECT_STREQ("{\"common_shaping_rule_ids\":\"32,33,34,35,36,37,38,39\"}", shaping_rule_ids);

	struct notify_shaping_policy *shaping_label=(struct notify_shaping_policy *)stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT]);
	EXPECT_NE(nullptr, shaping_label);
	EXPECT_EQ(MAX_RESULT_NUM, shaping_label->shaping_result_num);
	for(int i=0; i<shaping_label->shaping_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, shaping_label->shaping_result[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, shaping_label->shaping_result[i].config_id);
	}
	
	free_shaping_result(&a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT], (void *)shaping_label);
	stream_bridge_async_data_put(&a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT], NULL);
	EXPECT_EQ(nullptr, stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT]));
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

	stream_bridge_register_data_sync_cb(g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT], shaping_policy_notify_cb);
	
	tsg_notify_hited_shaping_result(&a_stream, shaping_result, MAX_RESULT_NUM, 0);
	int shaping_result_num=tsg_pull_shaping_result((struct streaminfo *)&a_stream, shaping_result, MAX_RESULT_NUM);
	EXPECT_EQ(MAX_RESULT_NUM, shaping_result_num);
	for(int i=0; i<shaping_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, shaping_result[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, shaping_result[i].config_id);
	}
	
	struct notify_shaping_policy *shaping_label=(struct notify_shaping_policy *)stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT]);
	EXPECT_NE(nullptr, shaping_label);
	EXPECT_EQ(MAX_RESULT_NUM, shaping_label->shaping_result_num);
	for(int i=0; i<shaping_label->shaping_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, shaping_label->shaping_result[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, shaping_label->shaping_result[i].config_id);
	}

	free_shaping_result(&a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT], (void *)shaping_label);
	stream_bridge_async_data_put(&a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT], NULL);
	EXPECT_EQ(nullptr, stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT]));
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

	stream_bridge_register_data_sync_cb(g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT], shaping_policy_notify_null_cb);
	
	tsg_notify_hited_shaping_result(&a_stream, shaping_result, 0, 0);
	struct notify_shaping_policy *shaping_label=(struct notify_shaping_policy *)stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT]);
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

	stream_bridge_register_data_sync_cb(g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT], shaping_duplicate_policy_notify_cb);
	
	tsg_notify_hited_shaping_result(&a_stream, shaping_result, MAX_RESULT_NUM, 0);
	int shaping_result_num=tsg_pull_shaping_result((struct streaminfo *)&a_stream, shaping_result, MAX_RESULT_NUM);
	EXPECT_EQ(MAX_RESULT_NUM/2, shaping_result_num);
	for(int i=0; i<shaping_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, shaping_result[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, shaping_result[i].config_id);
	}
	
	struct notify_shaping_policy *shaping_label=(struct notify_shaping_policy *)stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT]);
	EXPECT_NE(nullptr, shaping_label);
	EXPECT_EQ(MAX_RESULT_NUM/2, shaping_label->shaping_result_num);
	for(int i=0; i<shaping_label->shaping_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, shaping_label->shaping_result[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, shaping_label->shaping_result[i].config_id);
	}

	free_shaping_result(&a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT], (void *)shaping_label);
	stream_bridge_async_data_put(&a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT], NULL);
	EXPECT_EQ(nullptr, stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT]));
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

	stream_bridge_register_data_sync_cb(g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT], shaping_duplicate_policy_notify_cb);

	// First notify
	tsg_notify_hited_shaping_result(&a_stream, shaping_result, MAX_RESULT_NUM/2, 0);
	int shaping_result_num=tsg_pull_shaping_result((struct streaminfo *)&a_stream, shaping_result, MAX_RESULT_NUM);
	EXPECT_EQ(MAX_RESULT_NUM/2, shaping_result_num);
	for(int i=0; i<shaping_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, shaping_result[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, shaping_result[i].config_id);
	}
	
	struct notify_shaping_policy *shaping_label=(struct notify_shaping_policy *)stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT]);
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
	
	shaping_label=(struct notify_shaping_policy *)stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT]);
	EXPECT_NE(nullptr, shaping_label);
	EXPECT_EQ(MAX_RESULT_NUM/2, shaping_label->shaping_result_num);
	for(int i=0; i<shaping_label->shaping_result_num; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, shaping_label->shaping_result[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, shaping_label->shaping_result[i].config_id);
	}

	free_shaping_result(&a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT], (void *)shaping_label);
	stream_bridge_async_data_put(&a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT], NULL);
	EXPECT_EQ(nullptr, stream_bridge_async_data_get(&a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT]));
}

int main(int argc, char *argv[])
{
	TSG_MASTER_INIT();
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

