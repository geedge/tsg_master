#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "gtest_common.h"
#include "tsg_entry.h"
#include "tsg_sync_state.h"
#include "tsg_rule_internal.h"
#include <gtest/gtest.h>

extern int rd_kafka_get_sendlog_cnt(void);
extern void rd_kafka_clean_sendlog_cnt(void);
extern const char *rd_kafka_get_sendlog_payload(int idx);
extern int matched_shaping_rules_deal(const struct streaminfo *a_stream, struct maat_rule *shaping_rules, size_t n_shaping_rules, int thread_seq);;
extern int matched_service_chaining_rules_deal(const struct streaminfo *a_stream, struct maat_rule *service_chaining_rules, size_t n_service_chaining_rules, int thread_seq);
extern int matched_intercept_rules_deal(const struct streaminfo * a_stream, struct maat_rule * intercept_rules, size_t n_intercept_rules, int thread_seq);

extern void session_segment_id_free(const struct streaminfo * a_stream, int bridge_id, void * data);

TEST(TSGMaster, SetAPPIDHttp)
{
	const struct streaminfo a_stream={0};
	struct gather_app_result async_gather_result[ORIGIN_MAX]={0};

	async_gather_result[ORIGIN_BASIC_PROTOCOL].app_num=1;
	async_gather_result[ORIGIN_BASIC_PROTOCOL].origin=ORIGIN_BASIC_PROTOCOL;
	async_gather_result[ORIGIN_BASIC_PROTOCOL].attributes[0].app_id=67;	//HTTP
	
	session_gather_app_results_async(&a_stream, (void *)async_gather_result);
	struct gather_app_result *gather_result=(struct gather_app_result *)session_gather_app_results_get(&a_stream);
	EXPECT_NE(nullptr, gather_result);
	EXPECT_EQ(1, gather_result[ORIGIN_BASIC_PROTOCOL].app_num);
	EXPECT_EQ(67, gather_result[ORIGIN_BASIC_PROTOCOL].attributes[0].app_id);
	EXPECT_EQ(0, gather_result[ORIGIN_BASIC_PROTOCOL].attributes[0].packet_sequence);
	EXPECT_EQ(0, gather_result[ORIGIN_BASIC_PROTOCOL].attributes[0].surrogate_id);
	EXPECT_EQ(ORIGIN_BASIC_PROTOCOL, gather_result[ORIGIN_BASIC_PROTOCOL].origin);

	struct TLD_handle_t *handle=TLD_create(0);
	set_app_id(g_tsg_log_instance, handle, (struct streaminfo *)&a_stream);
	char app_ids[256]={0};
	TLD_convert_json(handle, app_ids, sizeof(app_ids));
	EXPECT_STREQ("{\"common_app_full_path\":\"http\",\"common_app_label\":\"http\",\"common_app_id\":{\"LPI_L7\":[{\"app_name\":\"http\",\"app_id\":67,\"surrogate_id\":0,\"packet_sequence\":0}]}}", app_ids);

	
	session_gather_app_results_async(&a_stream, NULL);
	gather_result=(struct gather_app_result *)session_gather_app_results_get(&a_stream);
	EXPECT_EQ(nullptr, gather_result);
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
	struct maat_rule shaping_result[MAX_RESULT_NUM]={0};

	for(int i=0; i<MAX_RESULT_NUM; i++)
	{
		shaping_result[i].action=TSG_ACTION_SHAPING;
		shaping_result[i].rule_id=TSG_ACTION_SHAPING+i;
	}
	
	matched_shaping_rules_deal(&a_stream, shaping_result, MAX_RESULT_NUM, 0);

	struct TLD_handle_t *handle=TLD_create(0);
	set_shaping_rule_ids(g_tsg_log_instance, handle, &a_stream);
	char shaping_rule_ids[256]={0};
	TLD_convert_json(handle, shaping_rule_ids, sizeof(shaping_rule_ids));
	EXPECT_STREQ("{\"common_shaping_rule_ids\":[32,33,34,35,36,37,38,39]}", shaping_rule_ids);

	const struct matched_policy_rules *hited_shaping=session_matched_rules_get(&a_stream, TSG_SERVICE_SHAPING);
	EXPECT_NE(nullptr, hited_shaping);
	EXPECT_EQ(MAX_RESULT_NUM, hited_shaping->n_rules);
	for(size_t i=0; i<hited_shaping->n_rules; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, hited_shaping->rules[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, hited_shaping->rules[i].rule_id);
	}

	struct segment_id_list *segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(1, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.shaping_sid, segment_ids->sid_list[0]);

	session_segment_id_free(&a_stream, 0, (void *)segment_ids);
	session_control_segment_ids_async(&a_stream, NULL);

	session_matched_rules_free(&a_stream, TSG_SERVICE_SHAPING, (void *)hited_shaping);
	session_matched_rules_async(&a_stream, TSG_SERVICE_SHAPING, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_SHAPING));
}

int shaping_policy_notify_cb(const struct streaminfo *stream, int bridge_id, void *data)
{
	struct matched_policy_rules *hited_shaping=(struct matched_policy_rules *)data;
	EXPECT_NE(nullptr, hited_shaping);
	EXPECT_EQ(MAX_RESULT_NUM, hited_shaping->n_rules);
	for(size_t i=0; i<hited_shaping->n_rules; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, hited_shaping->rules[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, hited_shaping->rules[i].rule_id);
	}
	
	return 0;
}

TEST(TSGMaster, ShapingPolicyNotify)
{
	const struct streaminfo a_stream={0};
	struct maat_rule shaping_result[MAX_RESULT_NUM]={0};

	for(int i=0; i<MAX_RESULT_NUM; i++)
	{
		shaping_result[i].action=TSG_ACTION_SHAPING;
		shaping_result[i].rule_id=TSG_ACTION_SHAPING+i;
	}

	stream_bridge_register_data_sync_cb(stream_bridge_build("NOTIFY_SHAPING_RESULT", "w"), shaping_policy_notify_cb);
	
	matched_shaping_rules_deal(&a_stream, shaping_result, MAX_RESULT_NUM, 0);

	const struct matched_policy_rules *hited_shaping=session_matched_rules_get(&a_stream, TSG_SERVICE_SHAPING);
	EXPECT_NE(nullptr, hited_shaping);
	EXPECT_EQ(MAX_RESULT_NUM, hited_shaping->n_rules);
	for(size_t i=0; i<hited_shaping->n_rules; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, hited_shaping->rules[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, hited_shaping->rules[i].rule_id);
	}

	struct segment_id_list *segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(1, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.shaping_sid, segment_ids->sid_list[0]);

	session_segment_id_free(&a_stream, 0, (void *)segment_ids);
	session_control_segment_ids_async(&a_stream, NULL);

	session_matched_rules_free(&a_stream, TSG_SERVICE_SHAPING, (void *)hited_shaping);
	session_matched_rules_async(&a_stream, TSG_SERVICE_SHAPING, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_SHAPING));
}

int shaping_policy_notify_null_cb(const struct streaminfo *stream, int bridge_id, void *data)
{
	EXPECT_EQ(nullptr, data);
	return 0;
}

TEST(TSGMaster, ShapingPolicyNotifyNULL)
{
	const struct streaminfo a_stream={0};
	struct maat_rule shaping_result[MAX_RESULT_NUM]={0};

	stream_bridge_register_data_sync_cb(stream_bridge_build("NOTIFY_SHAPING_RESULT", "w"), shaping_policy_notify_cb);
	
	matched_shaping_rules_deal(&a_stream, shaping_result, 0, 0);
	const struct matched_policy_rules *hited_shaping=session_matched_rules_get(&a_stream, TSG_SERVICE_SHAPING);
	EXPECT_EQ(nullptr, hited_shaping);
}

int shaping_duplicate_policy_notify_cb(const struct streaminfo *stream, int bridge_id, void *data)
{
	struct matched_policy_rules *hited_shaping=(struct matched_policy_rules *)data;
	EXPECT_NE(nullptr, hited_shaping);
	EXPECT_EQ(MAX_RESULT_NUM/2, hited_shaping->n_rules);
	for(size_t i=0; i<hited_shaping->n_rules; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, hited_shaping->rules[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, hited_shaping->rules[i].rule_id);
	}

	return 0;
}

TEST(TSGMaster, ShapingDuplicatePolicyNotify)
{
	const struct streaminfo a_stream={0};
	struct maat_rule shaping_result[MAX_RESULT_NUM]={0};

	for(int i=0; i<MAX_RESULT_NUM; i++)
	{
		shaping_result[i].action=TSG_ACTION_SHAPING;
		shaping_result[i].rule_id=TSG_ACTION_SHAPING+(i%4);
	}

	stream_bridge_register_data_sync_cb(stream_bridge_build("NOTIFY_SHAPING_RESULT", "w"), shaping_policy_notify_cb);
	
	matched_shaping_rules_deal(&a_stream, shaping_result, MAX_RESULT_NUM, 0);
	
	const struct matched_policy_rules *hited_shaping=session_matched_rules_get(&a_stream, TSG_SERVICE_SHAPING);
	EXPECT_NE(nullptr, hited_shaping);
	EXPECT_EQ(MAX_RESULT_NUM/2, hited_shaping->n_rules);
	for(size_t i=0; i<hited_shaping->n_rules; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, hited_shaping->rules[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, hited_shaping->rules[i].rule_id);
	}
	
	struct segment_id_list *segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(1, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.shaping_sid, segment_ids->sid_list[0]);

	session_segment_id_free(&a_stream, 0, (void *)segment_ids);
	session_control_segment_ids_async(&a_stream, NULL);

	session_matched_rules_free(&a_stream, TSG_SERVICE_SHAPING, (void *)hited_shaping);
	session_matched_rules_async(&a_stream, TSG_SERVICE_SHAPING, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_SHAPING));
}

TEST(TSGMaster, ShapingDuplicatePolicyMultipleNotify)
{
	const struct streaminfo a_stream={0};
	struct maat_rule shaping_result[MAX_RESULT_NUM]={0};

	for(int i=0; i<MAX_RESULT_NUM/2; i++)
	{
		shaping_result[i].action=TSG_ACTION_SHAPING;
		shaping_result[i].rule_id=TSG_ACTION_SHAPING+i;
	}

	stream_bridge_register_data_sync_cb(stream_bridge_build("NOTIFY_SHAPING_RESULT", "w"), shaping_policy_notify_cb);

	// First notify
	matched_shaping_rules_deal(&a_stream, shaping_result, MAX_RESULT_NUM/2, 0);
	
	const struct matched_policy_rules *hited_shaping=session_matched_rules_get(&a_stream, TSG_SERVICE_SHAPING);
	EXPECT_NE(nullptr, hited_shaping);
	EXPECT_EQ(MAX_RESULT_NUM/2, hited_shaping->n_rules);
	for(size_t i=0; i<hited_shaping->n_rules; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, hited_shaping->rules[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, hited_shaping->rules[i].rule_id);
	}

	// Second notify
	matched_shaping_rules_deal(&a_stream, shaping_result, MAX_RESULT_NUM/2, 0);

	hited_shaping=session_matched_rules_get(&a_stream, TSG_SERVICE_SHAPING);
	EXPECT_NE(nullptr, hited_shaping);
	EXPECT_EQ(MAX_RESULT_NUM/2, hited_shaping->n_rules);
	for(size_t i=0; i<hited_shaping->n_rules; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, hited_shaping->rules[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, hited_shaping->rules[i].rule_id);
	}

	struct segment_id_list *segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(1, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.shaping_sid, segment_ids->sid_list[0]);

	session_segment_id_free(&a_stream, 0, (void *)segment_ids);
	session_control_segment_ids_async(&a_stream, NULL);

	session_matched_rules_free(&a_stream, TSG_SERVICE_SHAPING, (void *)hited_shaping);
	session_matched_rules_async(&a_stream, TSG_SERVICE_SHAPING, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_SHAPING));
}

TEST(TSGMaster, SecurityPolicySendlog)
{
	const struct streaminfo a_stream={0};
	struct maat_rule matched_policy[MAX_RESULT_NUM]={0};

	for(int i=0; i<MAX_RESULT_NUM; i++)
	{
		matched_policy[i].do_log=1;
		matched_policy[i].action=TSG_ACTION_MONITOR;
		matched_policy[i].rule_id=TSG_ACTION_MONITOR+i;
	}

	// First notify
	session_matched_rules_notify(&a_stream, TSG_SERVICE_SECURITY, matched_policy, MAX_RESULT_NUM, 0);
	
	const struct matched_policy_rules *hited_security=session_matched_rules_get(&a_stream, TSG_SERVICE_SECURITY);
	EXPECT_NE(nullptr, hited_security);
	EXPECT_EQ(MAX_RESULT_NUM, hited_security->n_rules);
	for(size_t i=0; i<hited_security->n_rules; i++)
	{	
		EXPECT_EQ(TSG_ACTION_MONITOR, hited_security->rules[i].action);
		EXPECT_EQ(TSG_ACTION_MONITOR+i, hited_security->rules[i].rule_id);
	}

	struct TLD_handle_t * handle=TLD_create(0);
	struct maat_rule session_record={0, 0, 2, 1, 0};
	tsg_send_log(g_tsg_log_instance, handle, &a_stream, LOG_TYPE_SESSION_RECORD, &session_record, 1, 0);

	int sendlog_cnt=rd_kafka_get_sendlog_cnt();
	EXPECT_EQ(9, sendlog_cnt);
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_policy_id\":1,\"common_service\":0,\"common_vsys_id\":0,\"common_action\":1}", rd_kafka_get_sendlog_payload(0));
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_policy_id\":2,\"common_service\":0,\"common_vsys_id\":0,\"common_action\":1}", rd_kafka_get_sendlog_payload(1));
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_policy_id\":3,\"common_service\":0,\"common_vsys_id\":0,\"common_action\":1}", rd_kafka_get_sendlog_payload(2));
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_policy_id\":4,\"common_service\":0,\"common_vsys_id\":0,\"common_action\":1}", rd_kafka_get_sendlog_payload(3));
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_policy_id\":5,\"common_service\":0,\"common_vsys_id\":0,\"common_action\":1}", rd_kafka_get_sendlog_payload(4));
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_policy_id\":6,\"common_service\":0,\"common_vsys_id\":0,\"common_action\":1}", rd_kafka_get_sendlog_payload(5));
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_policy_id\":7,\"common_service\":0,\"common_vsys_id\":0,\"common_action\":1}", rd_kafka_get_sendlog_payload(6));
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_policy_id\":8,\"common_service\":0,\"common_vsys_id\":0,\"common_action\":1}", rd_kafka_get_sendlog_payload(7));
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_vsys_id\":1}", rd_kafka_get_sendlog_payload(8));

	rd_kafka_clean_sendlog_cnt();

	hited_security=session_matched_rules_get(&a_stream, TSG_SERVICE_SECURITY);
	EXPECT_EQ(nullptr, hited_security);
}

TEST(TSGMaster, ServiceChainingPolicyNotify)
{
	const struct streaminfo a_stream={0};
	struct maat_rule s_chaining_result[MAX_RESULT_NUM]={0};
	
	for(int i=0; i<MAX_RESULT_NUM/2; i++)
	{
		s_chaining_result[i].action=TSG_ACTION_S_CHAINING;
		s_chaining_result[i].rule_id=TSG_ACTION_S_CHAINING+i;
	}
	
	matched_service_chaining_rules_deal(&a_stream, s_chaining_result, MAX_RESULT_NUM/2, 0);
	const struct matched_policy_rules *hited_s_chaining=session_matched_rules_get(&a_stream, TSG_SERVICE_CHAINING);
	EXPECT_NE(nullptr, hited_s_chaining);
	EXPECT_EQ(MAX_RESULT_NUM/2, hited_s_chaining->n_rules);
	for(size_t i=0; i<hited_s_chaining->n_rules; i++)
	{	
		EXPECT_EQ(TSG_ACTION_S_CHAINING, hited_s_chaining->rules[i].action);
		EXPECT_EQ(TSG_ACTION_S_CHAINING+i, hited_s_chaining->rules[i].rule_id);
	}

	struct segment_id_list *segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(1, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.service_chaining_sid, segment_ids->sid_list[0]);

	session_segment_id_free(&a_stream, 0, (void *)segment_ids);
	session_control_segment_ids_async(&a_stream, NULL);

	session_matched_rules_free(&a_stream, TSG_SERVICE_CHAINING, (void *)hited_s_chaining);
	session_matched_rules_async(&a_stream, TSG_SERVICE_CHAINING, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_CHAINING));
}

TEST(TSGMaster, ServiceChainingDuplicatePolicyMultipleNotify)
{
	const struct streaminfo a_stream={0};
	struct maat_rule s_chaining_result[MAX_RESULT_NUM]={0};

	// first
	for(int i=0; i<MAX_RESULT_NUM/2; i++)
	{
		s_chaining_result[i].action=TSG_ACTION_S_CHAINING;
		s_chaining_result[i].rule_id=TSG_ACTION_S_CHAINING+i;
	}
	
	matched_service_chaining_rules_deal(&a_stream, s_chaining_result, MAX_RESULT_NUM/2, 0);
	const struct matched_policy_rules *hited_s_chaining=session_matched_rules_get(&a_stream, TSG_SERVICE_CHAINING);
	EXPECT_NE(nullptr, hited_s_chaining);
	EXPECT_EQ(MAX_RESULT_NUM/2, hited_s_chaining->n_rules);
	for(size_t i=0; i<hited_s_chaining->n_rules; i++)
	{	
		EXPECT_EQ(TSG_ACTION_S_CHAINING, hited_s_chaining->rules[i].action);
		EXPECT_EQ(TSG_ACTION_S_CHAINING+i, hited_s_chaining->rules[i].rule_id);
	}

	// second
	for(int i=0; i<MAX_RESULT_NUM/2; i++)
	{
		s_chaining_result[i].action=TSG_ACTION_S_CHAINING;
		s_chaining_result[i].rule_id=TSG_ACTION_S_CHAINING+i;
	}
	
	matched_service_chaining_rules_deal(&a_stream, s_chaining_result, MAX_RESULT_NUM/2, 0);
	hited_s_chaining=session_matched_rules_get(&a_stream, TSG_SERVICE_CHAINING);
	EXPECT_NE(nullptr, hited_s_chaining);
	EXPECT_EQ(MAX_RESULT_NUM/2, hited_s_chaining->n_rules);
	for(size_t i=0; i<hited_s_chaining->n_rules; i++)
	{	
		EXPECT_EQ(TSG_ACTION_S_CHAINING, hited_s_chaining->rules[i].action);
		EXPECT_EQ(TSG_ACTION_S_CHAINING+i, hited_s_chaining->rules[i].rule_id);
	}

	struct segment_id_list *segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(1, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.service_chaining_sid, segment_ids->sid_list[0]);

	session_segment_id_free(&a_stream, 0, (void *)segment_ids);
	session_control_segment_ids_async(&a_stream, NULL);

	session_matched_rules_free(&a_stream, TSG_SERVICE_CHAINING, (void *)hited_s_chaining);
	session_matched_rules_async(&a_stream, TSG_SERVICE_CHAINING, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_CHAINING));
}

TEST(TSGMaster, ServiceChainingPolicyMultipleNotify)
{
	const struct streaminfo a_stream={0};
	struct maat_rule s_chaining_result[MAX_RESULT_NUM]={0};

	// first
	for(int i=0; i<MAX_RESULT_NUM/2; i++)
	{
		s_chaining_result[i].action=TSG_ACTION_S_CHAINING;
		s_chaining_result[i].rule_id=TSG_ACTION_S_CHAINING+i;
	}
	
	matched_service_chaining_rules_deal(&a_stream, s_chaining_result, MAX_RESULT_NUM/2, 0);
	const struct matched_policy_rules *hited_s_chaining=session_matched_rules_get(&a_stream, TSG_SERVICE_CHAINING);
	EXPECT_NE(nullptr, hited_s_chaining);
	EXPECT_EQ(MAX_RESULT_NUM/2, hited_s_chaining->n_rules);
	for(size_t i=0; i<hited_s_chaining->n_rules; i++)
	{	
		EXPECT_EQ(TSG_ACTION_S_CHAINING, hited_s_chaining->rules[i].action);
		EXPECT_EQ(TSG_ACTION_S_CHAINING+i, hited_s_chaining->rules[i].rule_id);
	}

	// second
	for(int i=MAX_RESULT_NUM/2; i<MAX_RESULT_NUM; i++)
	{
		s_chaining_result[i].action=TSG_ACTION_S_CHAINING;
		s_chaining_result[i].rule_id=TSG_ACTION_S_CHAINING+i;
	}

	matched_service_chaining_rules_deal(&a_stream, s_chaining_result, MAX_RESULT_NUM/2, 0);
	hited_s_chaining=session_matched_rules_get(&a_stream, TSG_SERVICE_CHAINING);
	EXPECT_NE(nullptr, hited_s_chaining);
	EXPECT_EQ(MAX_RESULT_NUM/2, hited_s_chaining->n_rules);
	for(size_t i=0; i<hited_s_chaining->n_rules; i++)
	{	
		EXPECT_EQ(TSG_ACTION_S_CHAINING, hited_s_chaining->rules[i].action);
		EXPECT_EQ(TSG_ACTION_S_CHAINING+i, hited_s_chaining->rules[i].rule_id);
	}

	struct segment_id_list *segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(1, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.service_chaining_sid, segment_ids->sid_list[0]);

	session_segment_id_free(&a_stream, 0, (void *)segment_ids);
	session_control_segment_ids_async(&a_stream, NULL);

	session_matched_rules_free(&a_stream, TSG_SERVICE_CHAINING, (void *)hited_s_chaining);
	session_matched_rules_async(&a_stream, TSG_SERVICE_CHAINING, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_CHAINING));
}

TEST(TSGMaster, SecurityDuplicatePolicyMultipleNotify)
{
	const struct streaminfo a_stream={0};
	struct maat_rule matched_policy[MAX_RESULT_NUM]={0};

	for(int i=0; i<MAX_RESULT_NUM/2; i++)
	{
		matched_policy[i].action=TSG_ACTION_MONITOR;
		matched_policy[i].rule_id=TSG_ACTION_MONITOR+i;
	}

	// First notify
	session_matched_rules_notify(&a_stream, TSG_SERVICE_SECURITY, matched_policy, MAX_RESULT_NUM/2, 0);
	
	const struct matched_policy_rules *hited_security=session_matched_rules_get(&a_stream, TSG_SERVICE_SECURITY);
	EXPECT_NE(nullptr, hited_security);
	EXPECT_EQ(MAX_RESULT_NUM/2, hited_security->n_rules);
	for(size_t i=0; i<hited_security->n_rules; i++)
	{	
		EXPECT_EQ(TSG_ACTION_MONITOR, hited_security->rules[i].action);
		EXPECT_EQ(TSG_ACTION_MONITOR+i, hited_security->rules[i].rule_id);
	}

	// Second notify
	session_matched_rules_notify(&a_stream, TSG_SERVICE_SECURITY, matched_policy, MAX_RESULT_NUM/2, 0);
	
	hited_security=session_matched_rules_get(&a_stream, TSG_SERVICE_SECURITY);
	EXPECT_NE(nullptr, hited_security);
	EXPECT_EQ(MAX_RESULT_NUM/2, hited_security->n_rules);
	for(size_t i=0; i<hited_security->n_rules; i++)
	{	
		EXPECT_EQ(TSG_ACTION_MONITOR, hited_security->rules[i].action);
		EXPECT_EQ(TSG_ACTION_MONITOR+i, hited_security->rules[i].rule_id);
	}

	session_matched_rules_free(&a_stream, TSG_SERVICE_SECURITY, (void *)hited_security);
	session_matched_rules_async(&a_stream, TSG_SERVICE_SECURITY, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_SECURITY));
}

extern int session_packet_capture_by_rules_notify(const struct streaminfo *a_stream, struct maat_rule *rules, size_t n_rules, int thread_seq);

TEST(TSGMaster, InterceptPolicyNotify)
{
	const struct streaminfo a_stream={0};
	struct maat_rule matched_policy[MAX_RESULT_NUM]={0};

	matched_policy[1].action=TSG_ACTION_INTERCEPT;
	matched_policy[1].rule_id=TSG_ACTION_INTERCEPT;
	matched_policy[1].service_id=TSG_SERVICE_INTERCEPT;

	// Set Intercept
	matched_intercept_rules_deal(&a_stream, &matched_policy[1], 1, 0);

	const struct matched_policy_rules *hited_intercept=session_matched_rules_get(&a_stream, TSG_SERVICE_INTERCEPT);
	EXPECT_NE(nullptr, hited_intercept);
	EXPECT_EQ(1, hited_intercept->n_rules);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, hited_intercept->rules[0].action);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, hited_intercept->rules[0].rule_id);
	EXPECT_EQ(TSG_SERVICE_INTERCEPT, hited_intercept->rules[0].service_id);

	struct segment_id_list *segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(1, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.intercept_sid, segment_ids->sid_list[0]);

	session_segment_id_free(&a_stream, 0, (void *)segment_ids);
	session_control_segment_ids_async(&a_stream, NULL);

	session_matched_rules_free(&a_stream, TSG_SERVICE_INTERCEPT, (void *)hited_intercept);
	session_matched_rules_async(&a_stream, TSG_SERVICE_INTERCEPT, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_INTERCEPT));
}

TEST(TSGMaster, SecurityMultiplePolicyMonitorToIntercept)
{
	const struct streaminfo a_stream={0};
	struct maat_rule matched_policy[MAX_RESULT_NUM]={0};

	matched_policy[0].action=TSG_ACTION_MONITOR;
	matched_policy[0].rule_id=TSG_ACTION_MONITOR;
	matched_policy[0].service_id=TSG_SERVICE_SECURITY;

	matched_policy[1].action=TSG_ACTION_INTERCEPT;
	matched_policy[1].rule_id=TSG_ACTION_INTERCEPT;
	matched_policy[1].service_id=TSG_SERVICE_INTERCEPT;

	// First Monitor, second Intercpt
	session_matched_rules_notify(&a_stream, TSG_SERVICE_SECURITY, &matched_policy[0], 1, 0);

	int ret=session_matched_rules_copy(&a_stream, TSG_SERVICE_INTERCEPT, &(matched_policy[2]), 1);
	EXPECT_EQ(0, ret);
	
	ret=session_matched_rules_copy(&a_stream, TSG_SERVICE_SECURITY, &(matched_policy[2]), 1);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(TSG_ACTION_MONITOR, matched_policy[2].action);
	EXPECT_EQ(TSG_ACTION_MONITOR, matched_policy[2].rule_id);

	const struct matched_policy_rules *hited_security=session_matched_rules_get(&a_stream, TSG_SERVICE_SECURITY);
	EXPECT_NE(nullptr, hited_security);
	EXPECT_EQ(1, hited_security->n_rules);
	EXPECT_EQ(TSG_ACTION_MONITOR, hited_security->rules[0].action);
	EXPECT_EQ(TSG_ACTION_MONITOR, hited_security->rules[0].rule_id);

	session_matched_rules_free(&a_stream, TSG_SERVICE_SECURITY, (void *)hited_security);
	session_matched_rules_async(&a_stream, TSG_SERVICE_SECURITY, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_SECURITY));

	// Set Intercept
	matched_intercept_rules_deal(&a_stream, &matched_policy[1], 1, 0);

	ret=session_matched_rules_copy(&a_stream, TSG_SERVICE_INTERCEPT, &(matched_policy[2]), 1);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, matched_policy[2].action);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, matched_policy[2].rule_id);
	EXPECT_EQ(TSG_SERVICE_INTERCEPT,  matched_policy[2].service_id);
	
	ret=session_matched_rules_copy(&a_stream, TSG_SERVICE_INTERCEPT, &(matched_policy[2]), 1);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, matched_policy[2].action);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, matched_policy[2].rule_id);

	const struct matched_policy_rules *hited_intercept=session_matched_rules_get(&a_stream, TSG_SERVICE_INTERCEPT);
	EXPECT_NE(nullptr, hited_intercept);
	EXPECT_EQ(1, hited_intercept->n_rules);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, hited_intercept->rules[0].action);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, hited_intercept->rules[0].rule_id);

	struct segment_id_list *segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(1, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.intercept_sid, segment_ids->sid_list[0]);
	
	session_segment_id_free(&a_stream, 0, (void *)segment_ids);
	session_control_segment_ids_async(&a_stream, NULL);

	session_matched_rules_free(&a_stream, TSG_SERVICE_INTERCEPT, (void *)hited_intercept);
	session_matched_rules_async(&a_stream, TSG_SERVICE_INTERCEPT, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_INTERCEPT));
}

TEST(TSGMaster, ShapingAndServiceChainingPolicyNotify)
{
	const struct streaminfo a_stream={0};

	// service chaining notify
	struct maat_rule service_chaining_result[MAX_RESULT_NUM]={0};
	for(int i=0; i<MAX_RESULT_NUM/2; i++)
	{
		service_chaining_result[i].action=TSG_ACTION_S_CHAINING;
		service_chaining_result[i].rule_id=TSG_ACTION_S_CHAINING+i;
	}
	matched_service_chaining_rules_deal(&a_stream, service_chaining_result, MAX_RESULT_NUM/2, 0);

	const struct matched_policy_rules *hitted_service_chaining=session_matched_rules_get(&a_stream, TSG_SERVICE_CHAINING);
	EXPECT_NE(nullptr, hitted_service_chaining);
	EXPECT_EQ(MAX_RESULT_NUM/2, hitted_service_chaining->n_rules);
	for(size_t i=0; i<hitted_service_chaining->n_rules; i++)
	{	
		EXPECT_EQ(TSG_ACTION_S_CHAINING, hitted_service_chaining->rules[i].action);
		EXPECT_EQ(TSG_ACTION_S_CHAINING+i, hitted_service_chaining->rules[i].rule_id);
	}

	// shping notify
	struct maat_rule shaping_result[MAX_RESULT_NUM]={0};
	for(int i=0; i<MAX_RESULT_NUM/2; i++)
	{
		shaping_result[i].action=TSG_ACTION_SHAPING;
		shaping_result[i].rule_id=TSG_ACTION_SHAPING+i;
	}
	
	matched_shaping_rules_deal(&a_stream, shaping_result, MAX_RESULT_NUM/2, 0);
	const struct matched_policy_rules *hitted_shaping=session_matched_rules_get(&a_stream, TSG_SERVICE_SHAPING);
	EXPECT_NE(nullptr, hitted_shaping);
	EXPECT_EQ(MAX_RESULT_NUM/2, hitted_shaping->n_rules);
	for(size_t i=0; i<hitted_shaping->n_rules; i++)
	{	
		EXPECT_EQ(TSG_ACTION_SHAPING, hitted_shaping->rules[i].action);
		EXPECT_EQ(TSG_ACTION_SHAPING+i, hitted_shaping->rules[i].rule_id);
	}

	struct segment_id_list *segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(2, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.service_chaining_sid, segment_ids->sid_list[0]);
	EXPECT_EQ(g_tsg_para.shaping_sid, segment_ids->sid_list[1]);

	session_segment_id_free(&a_stream, 0, (void *)segment_ids);
	session_control_segment_ids_async(&a_stream, NULL);

	session_matched_rules_free(&a_stream, TSG_SERVICE_SHAPING, (void *)hitted_shaping);
	session_matched_rules_async(&a_stream, TSG_SERVICE_SHAPING, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_SHAPING));

	session_matched_rules_free(&a_stream, TSG_SERVICE_CHAINING, (void *)hitted_service_chaining);
	session_matched_rules_async(&a_stream, TSG_SERVICE_CHAINING, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_CHAINING));
}

TEST(TSGMaster, InterceptAndNOInterceptPolicy)
{
	const struct streaminfo a_stream={0};
	struct maat_rule matched_policy[MAX_RESULT_NUM]={0};

	matched_policy[0].action=TSG_ACTION_NO_INTERCEPT;
	matched_policy[0].rule_id=TSG_ACTION_NO_INTERCEPT;
	matched_policy[0].service_id=TSG_SERVICE_INTERCEPT;

	matched_policy[1].action=TSG_ACTION_INTERCEPT;
	matched_policy[1].rule_id=TSG_ACTION_INTERCEPT;
	matched_policy[1].service_id=TSG_SERVICE_INTERCEPT;

	// Set Intercept And NO Intercept
	matched_intercept_rules_deal(&a_stream, matched_policy, 2, 0);
	const struct matched_policy_rules *hited_intercept=session_matched_rules_get(&a_stream, TSG_SERVICE_INTERCEPT);
	EXPECT_NE(nullptr, hited_intercept);
	EXPECT_EQ(1, hited_intercept->n_rules);
	EXPECT_EQ(TSG_ACTION_NO_INTERCEPT, hited_intercept->rules[0].action);
	EXPECT_EQ(TSG_ACTION_NO_INTERCEPT, hited_intercept->rules[0].rule_id);
	EXPECT_EQ(TSG_SERVICE_INTERCEPT, hited_intercept->rules[0].service_id);

	struct segment_id_list *segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(1, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.intercept_sid, segment_ids->sid_list[0]);
	
	session_segment_id_free(&a_stream, 0, (void *)segment_ids);
	session_control_segment_ids_async(&a_stream, NULL);

	session_matched_rules_free(&a_stream, TSG_SERVICE_INTERCEPT, (void *)hited_intercept);
	session_matched_rules_async(&a_stream, TSG_SERVICE_INTERCEPT, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_INTERCEPT));
}

TEST(TSGMaster, ServiceChainingAndInterceptPolicy)
{
	const struct streaminfo a_stream={0};
	struct maat_rule matched_policy[MAX_RESULT_NUM]={0};

	matched_policy[0].action=TSG_ACTION_S_CHAINING;
	matched_policy[0].rule_id=TSG_ACTION_S_CHAINING;

	// Set Service chaining
	matched_service_chaining_rules_deal(&a_stream, &matched_policy[0], 1, 0);
	const struct matched_policy_rules *hited_s_chaining=session_matched_rules_get(&a_stream, TSG_SERVICE_CHAINING);
	EXPECT_NE(nullptr, hited_s_chaining);
	EXPECT_EQ(1, hited_s_chaining->n_rules);
	EXPECT_EQ(TSG_ACTION_S_CHAINING, hited_s_chaining->rules[0].action);
	EXPECT_EQ(TSG_ACTION_S_CHAINING, hited_s_chaining->rules[0].rule_id);

	struct segment_id_list *segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(1, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.service_chaining_sid, segment_ids->sid_list[0]);

	// Set Intercept
	matched_policy[1].action=TSG_ACTION_INTERCEPT;
	matched_policy[1].rule_id=TSG_ACTION_INTERCEPT;
	matched_policy[1].service_id=TSG_SERVICE_INTERCEPT;
	
	matched_intercept_rules_deal(&a_stream, &matched_policy[1], 1, 0);
	const struct matched_policy_rules *hited_intercept=session_matched_rules_get(&a_stream, TSG_SERVICE_INTERCEPT);
	EXPECT_NE(nullptr, hited_intercept);
	EXPECT_EQ(1, hited_intercept->n_rules);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, hited_intercept->rules[0].action);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, hited_intercept->rules[0].rule_id);
	EXPECT_EQ(TSG_SERVICE_INTERCEPT, hited_intercept->rules[0].service_id);

	segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(2, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.intercept_sid, segment_ids->sid_list[0]);
	EXPECT_EQ(g_tsg_para.service_chaining_sid, segment_ids->sid_list[1]);
		
	session_segment_id_free(&a_stream, 0, (void *)segment_ids);
	session_control_segment_ids_async(&a_stream, NULL);

	session_matched_rules_free(&a_stream, TSG_SERVICE_CHAINING, (void *)hited_s_chaining);
	session_matched_rules_async(&a_stream, TSG_SERVICE_CHAINING, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_CHAINING));

	session_matched_rules_free(&a_stream, TSG_SERVICE_INTERCEPT, (void *)hited_intercept);
	session_matched_rules_async(&a_stream, TSG_SERVICE_INTERCEPT, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_INTERCEPT));
}

TEST(TSGMaster, ServiceChainingAndShapingAndInterceptPolicy)
{
	const struct streaminfo a_stream={0};
	struct maat_rule matched_policy[MAX_RESULT_NUM]={0};

	// Set Shaping
	matched_policy[0].action=TSG_ACTION_SHAPING;
	matched_policy[0].rule_id=TSG_ACTION_SHAPING;
	
	matched_shaping_rules_deal(&a_stream, &matched_policy[0], 1, 0);
	const struct matched_policy_rules *hited_shaping=session_matched_rules_get(&a_stream, TSG_SERVICE_SHAPING);
	EXPECT_NE(nullptr, hited_shaping);
	EXPECT_EQ(1, hited_shaping->n_rules);
	EXPECT_EQ(TSG_ACTION_SHAPING, hited_shaping->rules[0].action);
	EXPECT_EQ(TSG_ACTION_SHAPING, hited_shaping->rules[0].rule_id);

	struct segment_id_list *segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(1, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.shaping_sid, segment_ids->sid_list[0]);

	// Set Service chaining
	matched_policy[0].action=TSG_ACTION_S_CHAINING;
	matched_policy[0].rule_id=TSG_ACTION_S_CHAINING;
	
	matched_service_chaining_rules_deal(&a_stream, &matched_policy[0], 1, 0);
	const struct matched_policy_rules *hited_s_chaining=session_matched_rules_get(&a_stream, TSG_SERVICE_CHAINING);
	EXPECT_NE(nullptr, hited_s_chaining);
	EXPECT_EQ(1, hited_s_chaining->n_rules);
	EXPECT_EQ(TSG_ACTION_S_CHAINING, hited_s_chaining->rules[0].action);
	EXPECT_EQ(TSG_ACTION_S_CHAINING, hited_s_chaining->rules[0].rule_id);

	segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(2, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.service_chaining_sid, segment_ids->sid_list[0]);
	EXPECT_EQ(g_tsg_para.shaping_sid, segment_ids->sid_list[1]);
	
	// Set Intercept
	matched_policy[1].action=TSG_ACTION_INTERCEPT;
	matched_policy[1].rule_id=TSG_ACTION_INTERCEPT;
	matched_policy[1].service_id=TSG_SERVICE_INTERCEPT;
	
	matched_intercept_rules_deal(&a_stream, &matched_policy[1], 1, 0);
	const struct matched_policy_rules *hited_intercept=session_matched_rules_get(&a_stream, TSG_SERVICE_INTERCEPT);
	EXPECT_NE(nullptr, hited_intercept);
	EXPECT_EQ(1, hited_intercept->n_rules);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, hited_intercept->rules[0].action);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, hited_intercept->rules[0].rule_id);
	EXPECT_EQ(TSG_SERVICE_INTERCEPT, hited_intercept->rules[0].service_id);

	segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(3, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.intercept_sid, segment_ids->sid_list[0]);
	EXPECT_EQ(g_tsg_para.service_chaining_sid, segment_ids->sid_list[1]);
	EXPECT_EQ(g_tsg_para.shaping_sid, segment_ids->sid_list[2]);
	
	session_segment_id_free(&a_stream, 0, (void *)segment_ids);
	session_control_segment_ids_async(&a_stream, NULL);

	session_matched_rules_free(&a_stream, TSG_SERVICE_SHAPING, (void *)hited_shaping);
	session_matched_rules_async(&a_stream, TSG_SERVICE_SHAPING, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_SHAPING));

	session_matched_rules_free(&a_stream, TSG_SERVICE_CHAINING, (void *)hited_s_chaining);
	session_matched_rules_async(&a_stream, TSG_SERVICE_CHAINING, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_CHAINING));

	session_matched_rules_free(&a_stream, TSG_SERVICE_INTERCEPT, (void *)hited_intercept);
	session_matched_rules_async(&a_stream, TSG_SERVICE_INTERCEPT, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_INTERCEPT));
}

TEST(TSGMaster, InterceptPolicySendLog)
{
	const struct streaminfo a_stream={0};
	struct maat_rule matched_policy[MAX_RESULT_NUM]={0};
	
	matched_policy[1].do_log=1;
	matched_policy[1].action=TSG_ACTION_INTERCEPT;
	matched_policy[1].rule_id=TSG_ACTION_INTERCEPT;
	matched_policy[1].service_id=TSG_SERVICE_INTERCEPT;

	// Set Intercept
	matched_intercept_rules_deal(&a_stream, &matched_policy[1], 1, 0);
	const struct matched_policy_rules *hited_intercept=session_matched_rules_get(&a_stream, TSG_SERVICE_INTERCEPT);
	EXPECT_NE(nullptr, hited_intercept);
	EXPECT_EQ(1, hited_intercept->n_rules);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, hited_intercept->rules[0].action);
	EXPECT_EQ(TSG_ACTION_INTERCEPT, hited_intercept->rules[0].rule_id);
	EXPECT_EQ(TSG_SERVICE_INTERCEPT, hited_intercept->rules[0].service_id);

	struct segment_id_list *segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(1, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.intercept_sid, segment_ids->sid_list[0]);

	session_segment_id_free(&a_stream, 0, (void *)segment_ids);
	session_control_segment_ids_async(&a_stream, NULL);

	struct proxy_log_update proxy={0, 1, 1, 10, 20, (char*)"upstream_version", (char*)"downstream_version", (char*)"error", (char*)"passthrough_reason"};
	session_log_update_data_put(&a_stream, TSG_SERVICE_INTERCEPT, (void *)&proxy);

	struct TLD_handle_t *handle=TLD_create(0);
	matched_policy[0].action=0;
	matched_policy[0].rule_id=0;
	matched_policy[0].service_id=0;
	tsg_send_log(g_tsg_log_instance, handle, &a_stream, LOG_TYPE_SESSION_RECORD, &(matched_policy[0]), 1, 0);

	int sendlog_cnt=rd_kafka_get_sendlog_cnt();
	EXPECT_EQ(2, sendlog_cnt);
	// intercept
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"intercept_pinning_status\":0,\"intercept_cert_verify\":1,\"intercept_status\":1,\"intercept_server_side_latency\":10,\"intercept_client_side_latency\":20,\"intercept_server_side_version\":\"upstream_version\",\"intercept_client_side_version\":\"downstream_version\",\"intercept_error\":\"error\",\"intercept_passthrough_reason\":\"passthrough_reason\",\"common_vsys_id\":1}", rd_kafka_get_sendlog_payload(1));
	// session record
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"intercept_pinning_status\":0,\"intercept_cert_verify\":1,\"intercept_status\":1,\"intercept_server_side_latency\":10,\"intercept_client_side_latency\":20,\"intercept_server_side_version\":\"upstream_version\",\"intercept_client_side_version\":\"downstream_version\",\"intercept_error\":\"error\",\"intercept_passthrough_reason\":\"passthrough_reason\",\"common_policy_id\":2,\"common_service\":3,\"common_vsys_id\":0,\"common_action\":2}", rd_kafka_get_sendlog_payload(0));

	session_log_update_data_put(&a_stream, TSG_SERVICE_INTERCEPT, NULL);
	rd_kafka_clean_sendlog_cnt();

	hited_intercept=session_matched_rules_get(&a_stream, TSG_SERVICE_INTERCEPT);
	EXPECT_EQ(nullptr, hited_intercept);
}

TEST(TSGMaster, ServiceChainingPolicySendLog)
{
	const struct streaminfo a_stream={0};
	struct maat_rule matched_policy[MAX_RESULT_NUM]={0};
	
	matched_policy[1].do_log=1;
	matched_policy[1].action=TSG_ACTION_S_CHAINING;
	matched_policy[1].rule_id=TSG_ACTION_S_CHAINING;
	matched_policy[1].service_id=TSG_SERVICE_CHAINING;

	// Set Intercept
	matched_service_chaining_rules_deal(&a_stream, &matched_policy[1], 1, 0);
	const struct matched_policy_rules *hited_s_chaining=session_matched_rules_get(&a_stream, TSG_SERVICE_CHAINING);
	EXPECT_NE(nullptr, hited_s_chaining);
	EXPECT_EQ(1, hited_s_chaining->n_rules);
	EXPECT_EQ(TSG_ACTION_S_CHAINING, hited_s_chaining->rules[0].action);
	EXPECT_EQ(TSG_ACTION_S_CHAINING, hited_s_chaining->rules[0].rule_id);
	EXPECT_EQ(TSG_SERVICE_CHAINING, hited_s_chaining->rules[0].service_id);

	struct segment_id_list *segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(1, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.service_chaining_sid, segment_ids->sid_list[0]);

	session_segment_id_free(&a_stream, 0, (void *)segment_ids);
	session_control_segment_ids_async(&a_stream, NULL);

	struct sce_log_update sce={8, {1,2,3,4,5,6,7,8}};
	session_log_update_data_put(&a_stream, TSG_SERVICE_CHAINING, (void *)&sce);

	struct TLD_handle_t *handle=TLD_create(0);
	matched_policy[0].action=0;
	matched_policy[0].rule_id=0;
	matched_policy[0].service_id=0;
	tsg_send_log(g_tsg_log_instance, handle, &a_stream, LOG_TYPE_SESSION_RECORD, &(matched_policy[0]), 1, 0);

	int sendlog_cnt=rd_kafka_get_sendlog_cnt();
	EXPECT_EQ(1, sendlog_cnt);
	// session record
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_vsys_id\":1,\"sce_profile_ids\":[1,2,3,4,5,6,7,8]}", rd_kafka_get_sendlog_payload(0));

	session_log_update_data_put(&a_stream, TSG_SERVICE_CHAINING, NULL);
	rd_kafka_clean_sendlog_cnt();

	session_matched_rules_free(&a_stream, TSG_SERVICE_CHAINING, (void *)hited_s_chaining);
	session_matched_rules_async(&a_stream, TSG_SERVICE_CHAINING, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_CHAINING));

	hited_s_chaining=session_matched_rules_get(&a_stream, TSG_SERVICE_CHAINING);
	EXPECT_EQ(nullptr, hited_s_chaining);
}

TEST(TSGMaster, ShapingPolicySendLog)
{
	const struct streaminfo a_stream={0};
	struct maat_rule matched_policy[MAX_RESULT_NUM]={0};
	
	matched_policy[1].do_log=1;
	matched_policy[1].action=TSG_ACTION_SHAPING;
	matched_policy[1].rule_id=TSG_ACTION_SHAPING;
	matched_policy[1].service_id=TSG_SERVICE_SHAPING;

	// Set Intercept
	matched_shaping_rules_deal(&a_stream, &matched_policy[1], 1, 0);
	const struct matched_policy_rules *hited_shaping=session_matched_rules_get(&a_stream, TSG_SERVICE_SHAPING);
	EXPECT_NE(nullptr, hited_shaping);
	EXPECT_EQ(1, hited_shaping->n_rules);
	EXPECT_EQ(TSG_ACTION_SHAPING, hited_shaping->rules[0].action);
	EXPECT_EQ(TSG_ACTION_SHAPING, hited_shaping->rules[0].rule_id);
	EXPECT_EQ(TSG_SERVICE_SHAPING, hited_shaping->rules[0].service_id);

	struct segment_id_list *segment_ids=(struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_NE(nullptr, segment_ids);
	EXPECT_EQ(1, segment_ids->sz_sidlist);
	EXPECT_EQ(g_tsg_para.shaping_sid, segment_ids->sid_list[0]);

	session_segment_id_free(&a_stream, 0, (void *)segment_ids);
	session_control_segment_ids_async(&a_stream, NULL);

	struct shaper_log_update shaping={1, {TSG_ACTION_SHAPING, 8, {1,2,3,4,5,6,7,8}}};
	session_log_update_data_put(&a_stream, TSG_SERVICE_SHAPING, (void *)&shaping);

	struct TLD_handle_t *handle=TLD_create(0);
	matched_policy[0].action=0;
	matched_policy[0].rule_id=0;
	matched_policy[0].service_id=0;
	tsg_send_log(g_tsg_log_instance, handle, &a_stream, LOG_TYPE_SESSION_RECORD, &(matched_policy[0]), 1, 0);

	int sendlog_cnt=rd_kafka_get_sendlog_cnt();
	EXPECT_EQ(1, sendlog_cnt);
	// session record
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_vsys_id\":1,\"shaping_profile_ids\":[{\"rule_id\":32,\"profile_ids\":[1,2,3,4,5,6,7,8]}],\"common_shaping_rule_ids\":[32]}", rd_kafka_get_sendlog_payload(0));

	session_log_update_data_put(&a_stream, TSG_SERVICE_SHAPING, NULL);
	rd_kafka_clean_sendlog_cnt();

	session_matched_rules_free(&a_stream, TSG_SERVICE_SHAPING, (void *)hited_shaping);
	session_matched_rules_async(&a_stream, TSG_SERVICE_SHAPING, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_SHAPING));

	hited_shaping=session_matched_rules_get(&a_stream, TSG_SERVICE_SHAPING);
	EXPECT_EQ(nullptr, hited_shaping);
}

extern size_t session_pending_state_deal(const struct streaminfo *a_stream, struct session_runtime_process_context *srt_process_context, struct maat_rule *results, int n_results, void *a_packet);

TEST(TSGMaster, SessionDealStatePending)
{
	struct streaminfo a_stream={0};
	struct tcpdetail pdetail={0};
	a_stream.type=STREAM_TYPE_TCP;
	a_stream.ptcpdetail=&pdetail;
	
	struct maat_rule matched_rules[MAX_RESULT_NUM]={0};
	struct session_runtime_process_context srt_process_context={0};

	gtest_set_ftp_data_flag();

	size_t n_matched_rules=session_pending_state_deal((const struct streaminfo *)&a_stream, &srt_process_context, matched_rules, MAX_RESULT_NUM, NULL);
	EXPECT_EQ(0, n_matched_rules);
	EXPECT_EQ(PROTO_FTP, srt_process_context.proto);

	struct gather_app_result *gather_result=(struct gather_app_result *)session_gather_app_results_get(&a_stream);
	EXPECT_NE(nullptr, gather_result);
	
	EXPECT_EQ(1, gather_result[ORIGIN_BASIC_PROTOCOL].app_num);
	EXPECT_EQ(45, gather_result[ORIGIN_BASIC_PROTOCOL].attributes[0].app_id);
	EXPECT_EQ(0, gather_result[ORIGIN_BASIC_PROTOCOL].attributes[0].surrogate_id);

	free(gather_result);
	session_gather_app_results_async(&a_stream, NULL);
	EXPECT_EQ(nullptr, session_gather_app_results_get(&a_stream));

	gtest_clean_ftp_data_flag();
	EXPECT_EQ(0, ftp_data_identify(&a_stream));

}

TEST(TSGMaster, SessionApplicationMetrics)
{

}


int main(int argc, char *argv[])
{
	TSG_MASTER_INIT();
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

