#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <MESA/quic.h>

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
	struct gather_app_result *gather_result_in=(struct gather_app_result *)dictator_malloc(0, sizeof(struct gather_app_result));
	memset(gather_result_in, 0, sizeof(struct gather_app_result));
	
	gather_result_in->l7_protocol_num=1;
	gather_result_in->l7_protocol=(struct app_attributes *)dictator_malloc(0, sizeof(struct app_attributes));
	gather_result_in->l7_protocol[0].app_id=67;	//HTTP
	gather_result_in->l7_protocol[0].surrogate_id=0;	//HTTP
	gather_result_in->l7_protocol[0].packet_sequence=1;	//HTTP
	
	session_gather_app_results_async(&a_stream, (void *)gather_result_in);
	struct gather_app_result *gather_result_out=(struct gather_app_result *)session_gather_app_results_get(&a_stream);
	EXPECT_NE(nullptr, gather_result_out);
	EXPECT_EQ(1, gather_result_out->l7_protocol_num);
	EXPECT_EQ(67, gather_result_out->l7_protocol[0].app_id);
	EXPECT_EQ(0, gather_result_out->l7_protocol[0].surrogate_id);
	EXPECT_EQ(1, gather_result_out->l7_protocol[0].packet_sequence);

	struct TLD_handle_t *handle=TLD_create(0);
	set_app_id(g_tsg_log_instance, handle, (struct streaminfo *)&a_stream);
	char app_ids[256]={0};
	TLD_convert_json(handle, app_ids, sizeof(app_ids));
	EXPECT_STREQ("{\"common_app_full_path\":\"http\",\"common_app_label\":\"http\",\"common_app_id\":{\"LPI_L7\":[{\"app_name\":\"http\",\"app_id\":67,\"surrogate_id\":0,\"packet_sequence\":1}]}}", app_ids);

	dictator_free(0, gather_result_out);
	session_gather_app_results_async(&a_stream, NULL);
	EXPECT_EQ(nullptr, session_gather_app_results_get(&a_stream));
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
	for(size_t i=hited_security->n_rules, j=0; i>0; i--)
	{	
		EXPECT_EQ(TSG_ACTION_MONITOR, hited_security->rules[i-1].action);
		EXPECT_EQ(TSG_ACTION_MONITOR+j++, hited_security->rules[i-1].rule_id);
	}

	struct TLD_handle_t * handle=TLD_create(0);
	struct maat_rule session_record={0, 0, 2, 1, 0};
	tsg_send_log(g_tsg_log_instance, handle, &a_stream, LOG_TYPE_SESSION_RECORD, &session_record, 1, 0);

	int sendlog_cnt=rd_kafka_get_sendlog_cnt();
	EXPECT_EQ(9, sendlog_cnt);
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_policy_id\":8,\"common_service\":0,\"common_vsys_id\":0,\"common_action\":1}", rd_kafka_get_sendlog_payload(0));
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_policy_id\":7,\"common_service\":0,\"common_vsys_id\":0,\"common_action\":1}", rd_kafka_get_sendlog_payload(1));
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_policy_id\":6,\"common_service\":0,\"common_vsys_id\":0,\"common_action\":1}", rd_kafka_get_sendlog_payload(2));
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_policy_id\":5,\"common_service\":0,\"common_vsys_id\":0,\"common_action\":1}", rd_kafka_get_sendlog_payload(3));
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_policy_id\":4,\"common_service\":0,\"common_vsys_id\":0,\"common_action\":1}", rd_kafka_get_sendlog_payload(4));
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_policy_id\":3,\"common_service\":0,\"common_vsys_id\":0,\"common_action\":1}", rd_kafka_get_sendlog_payload(5));
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_policy_id\":2,\"common_service\":0,\"common_vsys_id\":0,\"common_action\":1}", rd_kafka_get_sendlog_payload(6));
	EXPECT_STREQ("{\"common_app_full_path\":\"unknown\",\"common_app_label\":\"unknown\",\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_con_duration_ms\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_device_tag\":\"{\\\"tags\\\":[{\\\"tag\\\":\\\"device_id\\\",\\\"value\\\":\\\"device_1\\\"}]}\",\"common_t_vsys_id\":1,\"common_policy_id\":1,\"common_service\":0,\"common_vsys_id\":0,\"common_action\":1}", rd_kafka_get_sendlog_payload(7));
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

	for(size_t i=hited_security->n_rules, j=0; i>0; i--)
	{	
		EXPECT_EQ(TSG_ACTION_MONITOR, hited_security->rules[i-1].action);
		EXPECT_EQ(TSG_ACTION_MONITOR+j++, hited_security->rules[i-1].rule_id);
	}

	// Second notify
	session_matched_rules_notify(&a_stream, TSG_SERVICE_SECURITY, matched_policy, MAX_RESULT_NUM/2, 0);
	
	hited_security=session_matched_rules_get(&a_stream, TSG_SERVICE_SECURITY);
	EXPECT_NE(nullptr, hited_security);
	EXPECT_EQ(MAX_RESULT_NUM/2, hited_security->n_rules);
	for(size_t i=hited_security->n_rules, j=0; i>0; i--)
	{	
		EXPECT_EQ(TSG_ACTION_MONITOR, hited_security->rules[i-1].action);
		EXPECT_EQ(TSG_ACTION_MONITOR+j++, hited_security->rules[i-1].rule_id);
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
	
	EXPECT_EQ(1, gather_result->l7_protocol_num);
	EXPECT_EQ(45,  gather_result->l7_protocol[0].app_id);
	EXPECT_EQ(0,  gather_result->l7_protocol[0].surrogate_id);

	dictator_free(0, gather_result);
	session_gather_app_results_async(&a_stream, NULL);
	EXPECT_EQ(nullptr, session_gather_app_results_get(&a_stream));

	gtest_clean_ftp_data_flag();
	EXPECT_EQ(0, ftp_data_identify(&a_stream));

}

TEST(TSGMaster, SessionApplicationMetrics)
{

}

extern int session_app_gather_results_set_l7_protocol(const struct streaminfo *a_stream, unsigned int *app_id, int n_app_id);
TEST(TSGMaster, SessionApplicationFullPathTSG15779_HTTP)
{
	const struct streaminfo a_stream={0};
	char out_full_path[256]={0};
	int out_full_path_len=sizeof(out_full_path);
	struct gather_app_result *gather_result=(struct gather_app_result *)calloc(1, sizeof(struct gather_app_result));

	gather_result->l7_protocol_num=1;
	gather_result->l7_protocol=(struct app_attributes *)calloc(1, sizeof(struct app_attributes));
	gather_result->l7_protocol->app_id=67;
	gather_result->l7_protocol->surrogate_id=0;
	gather_result->l7_protocol->packet_sequence=4;
	session_gather_app_results_async(&a_stream, (void *)gather_result);

	int n_app_id=1;
	unsigned int app_id[1]={67};
	session_app_gather_results_set_l7_protocol(&a_stream, app_id, n_app_id);
	
	session_application_full_path_update(&a_stream, out_full_path, out_full_path_len);
	EXPECT_STREQ("http", out_full_path);

	free(gather_result->l7_protocol);
	free(gather_result->qm_engine);
	free(gather_result);
	session_gather_app_results_async(&a_stream, NULL);
}

TEST(TSGMaster, SessionApplicationFullPathTSG15779_SSL)
{
	const struct streaminfo a_stream={0};
	char out_full_path[256]={0};
	int out_full_path_len=sizeof(out_full_path);
	struct gather_app_result *gather_result=(struct gather_app_result *)calloc(1, sizeof(struct gather_app_result));

	gather_result->l7_protocol_num=1;
	gather_result->l7_protocol=(struct app_attributes *)calloc(1, sizeof(struct app_attributes));
	gather_result->l7_protocol->app_id=68;
	gather_result->l7_protocol->surrogate_id=0;
	gather_result->l7_protocol->packet_sequence=4;
	session_gather_app_results_async(&a_stream, (void *)gather_result);

	int n_app_id=1;
	unsigned int app_id[1]={199};
	session_app_gather_results_set_l7_protocol(&a_stream, app_id, n_app_id);
	
	session_application_full_path_update(&a_stream, out_full_path, out_full_path_len);
	EXPECT_STREQ("ssl.https", out_full_path);

	free(gather_result->l7_protocol);
	free(gather_result->qm_engine);
	free(gather_result);
	session_gather_app_results_async(&a_stream, NULL);
}

TEST(TSGMaster, SessionApplicationFullPathTSG15779_ECH)
{
	const struct streaminfo a_stream={0};
	char out_full_path[256]={0};
	int out_full_path_len=sizeof(out_full_path);
	struct gather_app_result *gather_result=(struct gather_app_result *)calloc(1, sizeof(struct gather_app_result));

	gather_result->l7_protocol_num=1;
	gather_result->l7_protocol=(struct app_attributes *)calloc(1, sizeof(struct app_attributes));
	gather_result->l7_protocol->app_id=68;
	gather_result->l7_protocol->surrogate_id=0;
	gather_result->l7_protocol->packet_sequence=4;
	session_gather_app_results_async(&a_stream, (void *)gather_result);

	int n_app_id=2;
	unsigned int app_id[2]={199, 8173};
	session_app_gather_results_set_l7_protocol(&a_stream, app_id, n_app_id);
	
	session_application_full_path_update(&a_stream, out_full_path, out_full_path_len);
	EXPECT_STREQ("ssl.SSL with ECH.https", out_full_path);

	free(gather_result->l7_protocol);
	free(gather_result->qm_engine);
	free(gather_result);
	session_gather_app_results_async(&a_stream, NULL);
}

TEST(TSGMaster, SessionApplicationFullPathTSG15779_ESNI)
{
	const struct streaminfo a_stream={0};
	char out_full_path[256]={0};
	int out_full_path_len=sizeof(out_full_path);
	struct gather_app_result *gather_result=(struct gather_app_result *)calloc(1, sizeof(struct gather_app_result));

	gather_result->l7_protocol_num=1;
	gather_result->l7_protocol=(struct app_attributes *)calloc(1, sizeof(struct app_attributes));
	gather_result->l7_protocol->app_id=68;
	gather_result->l7_protocol->surrogate_id=0;
	gather_result->l7_protocol->packet_sequence=4;
	session_gather_app_results_async(&a_stream, (void *)gather_result);

	int n_app_id=2;
	unsigned int app_id[2]={199, 8008};
	session_app_gather_results_set_l7_protocol(&a_stream, app_id, n_app_id);
	
	session_application_full_path_update(&a_stream, out_full_path, out_full_path_len);
	EXPECT_STREQ("ssl.SSL with ESNI.https", out_full_path);

	free(gather_result->l7_protocol);
	free(gather_result->qm_engine);
	free(gather_result);
	session_gather_app_results_async(&a_stream, NULL);
}

extern int session_application_full_path_update(const struct streaminfo *a_stream, char *app_full_path, int app_full_path_len);

TEST(TSGMaster, SessionApplicationFullPathTSG15999)
{
	const struct streaminfo a_stream={0};
	char out_full_path[256]={0};
	int out_full_path_len=sizeof(out_full_path);
	struct gather_app_result *gather_result=(struct gather_app_result *)calloc(1, sizeof(struct gather_app_result));

	gather_result->l7_protocol_num=1;
	gather_result->l7_protocol=(struct app_attributes *)calloc(1, sizeof(struct app_attributes));
	gather_result->l7_protocol->app_id=68;
	gather_result->l7_protocol->surrogate_id=0;
	gather_result->l7_protocol->packet_sequence=4;

	gather_result->qm_engine_num=2;
	gather_result->qm_engine=(struct app_attributes *)calloc(1, sizeof(struct app_attributes)*2);
	gather_result->qm_engine[0].app_id=199;
	gather_result->qm_engine[0].surrogate_id=0;
	gather_result->qm_engine[0].packet_sequence=6;
	gather_result->qm_engine[1].app_id=68;
	gather_result->qm_engine[1].surrogate_id=0;
	gather_result->qm_engine[1].packet_sequence=4;

	session_gather_app_results_async(&a_stream, (void *)gather_result);
	session_application_full_path_update(&a_stream, out_full_path, out_full_path_len);
	EXPECT_STREQ("ssl.https", out_full_path);

	free(gather_result->l7_protocol);
	free(gather_result->qm_engine);
	free(gather_result);
	session_gather_app_results_async(&a_stream, NULL);
}



size_t session_app_id_and_properties_scan(const struct streaminfo *a_stream, struct maat_rule *matched_rules, size_t n_matched_rules, struct session_runtime_process_context *srt_process_context, struct app_attributes *app_attribute, char app_attribute_num, APP_IDENTIFY_ORIGIN origin, int thread_seq);
TEST(TSGMaster, SessionApplicationFullPathTSG15999_MatchedRuleQM)
{
	const struct streaminfo a_stream={0};
	char out_full_path[256]={0};
	int out_full_path_len=sizeof(out_full_path);
	struct gather_app_result *gather_result=(struct gather_app_result *)calloc(1, sizeof(struct gather_app_result));

	gather_result->l7_protocol_num=1;
	gather_result->l7_protocol=(struct app_attributes *)calloc(1, sizeof(struct app_attributes));
	gather_result->l7_protocol->app_id=68;
	gather_result->l7_protocol->surrogate_id=0;
	gather_result->l7_protocol->packet_sequence=4;

	gather_result->qm_engine_num=2;
	gather_result->qm_engine=(struct app_attributes *)calloc(1, sizeof(struct app_attributes)*2);
	gather_result->qm_engine[0].app_id=199;
	gather_result->qm_engine[0].surrogate_id=0;
	gather_result->qm_engine[0].packet_sequence=6;
	gather_result->qm_engine[1].app_id=68;
	gather_result->qm_engine[1].surrogate_id=0;
	gather_result->qm_engine[1].packet_sequence=4;
	session_gather_app_results_async(&a_stream, (void *)gather_result);
	
	struct maat_rule matched_rules[8]={0};
	struct session_runtime_process_context srt_process_context={0};
	srt_process_context.mid=maat_state_new(g_tsg_maat_feather, 0);

	session_app_id_and_properties_scan(&a_stream, matched_rules, 8, &srt_process_context, gather_result->qm_engine, gather_result->qm_engine_num, ORIGIN_QM_ENGINE, 0);
	session_app_id_and_properties_scan(&a_stream, matched_rules, 8, &srt_process_context, gather_result->l7_protocol, gather_result->l7_protocol_num, ORIGIN_BASIC_PROTOCOL, 0);
	maat_state_free(srt_process_context.mid);

	session_application_full_path_update(&a_stream, out_full_path, out_full_path_len);
	EXPECT_STREQ("ssl.https", out_full_path);

	free(gather_result->l7_protocol);
	free(gather_result->qm_engine);
	free(gather_result);
	session_gather_app_results_async(&a_stream, NULL);
}

int session_app_gather_results_update(struct app_attributes **update_result, char update_result_num, struct app_identify_result *identify_result, int packet_sequence, int thread_seq);

TEST(TSGMaster, SessionApplicationFullPathTSG13811)
{
	const struct streaminfo a_stream={0};
	char out_full_path[256]={0};
	int out_full_path_len=sizeof(out_full_path);
	struct gather_app_result *gather_result=(struct gather_app_result *)calloc(1, sizeof(struct gather_app_result));

	gather_result->l7_protocol_num=1;
	gather_result->l7_protocol=(struct app_attributes *)calloc(1, sizeof(struct app_attributes));
	gather_result->l7_protocol->app_id=2521;
	gather_result->l7_protocol->surrogate_id=0;
	gather_result->l7_protocol->packet_sequence=1;
	
	struct app_identify_result identify_result={ORIGIN_QM_ENGINE, 3, {2521, 199, 240}, {0, 0, 0}};
	gather_result->qm_engine_num=session_app_gather_results_update(&(gather_result->qm_engine), gather_result->qm_engine_num, &identify_result, 1, 0);
	EXPECT_EQ(2, gather_result->qm_engine_num);
	EXPECT_EQ(2521, gather_result->qm_engine[0].app_id);
	EXPECT_EQ(240, gather_result->qm_engine[1].app_id);

	session_gather_app_results_async(&a_stream, (void *)gather_result);
	session_application_full_path_update(&a_stream, out_full_path, out_full_path_len);
	EXPECT_STREQ("quic.youtube", out_full_path);

	free(gather_result->l7_protocol);
	free(gather_result->qm_engine);
	free(gather_result);
	session_gather_app_results_async(&a_stream, NULL);
}

extern int session_application_full_path_combine(struct gather_app_result * gather_result, char * out_full_path, int out_full_path_len);

TEST(TSGMaster, SessionApplicationFullPath)
{
	char out_full_path[256]={0};
	int out_full_path_len=sizeof(out_full_path);
	struct gather_app_result gather_result={0};

	gather_result.l7_protocol_num=1;
	struct app_attributes l7_protocol={68, 0, 4};
	gather_result.l7_protocol=&l7_protocol;

	gather_result.qm_engine_num=3;
	gather_result.l7_qm_engine_num=2;
	struct app_attributes qm_engine[3]={{199, 0, 6}, {68, 0, 4}, {240, 0, 6}};
	gather_result.qm_engine=qm_engine;

	int offset=session_application_full_path_combine(&gather_result, out_full_path, out_full_path_len);
	EXPECT_NE(0, offset);
	EXPECT_STREQ("ssl.https.youtube", out_full_path);

	// l7 protocol is empty
	gather_result.l7_protocol_num=0;
	gather_result.l7_protocol=NULL;

	gather_result.qm_engine_num=3;
	gather_result.l7_qm_engine_num=0;
	struct app_attributes qm_engine2[3]={{199, 0, 6}, {68, 0, 4}, {240, 0, 6}};
	gather_result.qm_engine=qm_engine2;

	offset=session_application_full_path_combine(&gather_result, out_full_path, out_full_path_len);
	EXPECT_NE(0, offset);
	EXPECT_STREQ("ssl.https.youtube", out_full_path);

	// matched application
	gather_result.l7_protocol_num=1;
	struct app_attributes l7_protocol_3={68, 0, 4};
	gather_result.l7_protocol=&l7_protocol_3;

	gather_result.qm_engine_num=3;
	gather_result.l7_qm_engine_num=2;
	struct app_attributes qm_engine3[3]={{199, 0, 6}, {68, 0, 4}, {240, 0, 6}};
	gather_result.qm_engine=qm_engine3;

	gather_result.matched_app_flag=1;
	gather_result.matched_app={240, 0, 6};

	struct app_attributes user_define_3={15009, 0, 4};
	gather_result.user_define_num=1;
	gather_result.user_define=&user_define_3;
	
	offset=session_application_full_path_combine(&gather_result, out_full_path, out_full_path_len);
	EXPECT_NE(0, offset);
	EXPECT_STREQ("ssl.https.youtube", out_full_path);

	//userdefine application
	gather_result.l7_protocol_num=1;
	struct app_attributes l7_protocol_4={68, 0, 4};
	gather_result.l7_protocol=&l7_protocol_4;

	gather_result.qm_engine_num=3;
	gather_result.l7_qm_engine_num=2;
	struct app_attributes qm_engine4[3]={{199, 0, 6}, {68, 0, 4}, {240, 0, 6}};
	gather_result.qm_engine=qm_engine4;

	gather_result.matched_app_flag=0;

	struct app_attributes user_define_4={15009, 0, 4};
	gather_result.user_define_num=1;
	gather_result.user_define=&user_define_4;
	
	offset=session_application_full_path_combine(&gather_result, out_full_path, out_full_path_len);
	EXPECT_NE(0, offset);
	EXPECT_STREQ("ssl.https.user_define_youtube", out_full_path);

	// built in application
	gather_result.l7_protocol_num=1;
	struct app_attributes l7_protocol_5={68, 0, 4};
	gather_result.l7_protocol=&l7_protocol_5;

	gather_result.qm_engine_num=3;
	gather_result.l7_qm_engine_num=2;
	struct app_attributes qm_engine5[3]={{199, 0, 6}, {68, 0, 4}, {240, 0, 6}};
	gather_result.qm_engine=qm_engine5;

	gather_result.matched_app_flag=0;

	struct app_attributes user_define_5={1500, 0, 4};
	gather_result.user_define_num=1;
	gather_result.user_define=&user_define_5;
	
	offset=session_application_full_path_combine(&gather_result, out_full_path, out_full_path_len);
	EXPECT_NE(0, offset);
	EXPECT_STREQ("ssl.https.built_in_youtube", out_full_path);
}

extern struct quic_info *g_test_quic_info;
extern int session_l7_protocol_identify(const struct streaminfo * a_stream, struct session_runtime_process_context * srt_process_context, void * a_packet);

TEST(TSGMaster, SessionQuicIdentify)
{
	struct streaminfo a_stream={0};
	struct tcpdetail pdetail={0};
	a_stream.type=STREAM_TYPE_UDP;
	a_stream.ptcpdetail=&pdetail;
	struct session_runtime_process_context srt_process_context={0};

	int ret=session_l7_protocol_identify((const struct streaminfo *)&a_stream, &srt_process_context, NULL);
	EXPECT_EQ(0, ret);
	
	struct quic_info quic_info_1;
	quic_info_1.client_hello=NULL;
	quic_info_1.quic_version=0x00000001;
	g_test_quic_info=&quic_info_1;
	ret=session_l7_protocol_identify((const struct streaminfo *)&a_stream, &srt_process_context, NULL);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(0x00000001, srt_process_context.quic_version);
	g_test_quic_info=NULL;
	
	struct quic_info quic_info_2;
	struct quic_client_hello chello_2={(char *)"google.com", NULL};
	quic_info_2.client_hello=&chello_2;
	quic_info_2.quic_version=0x00000001;
	g_test_quic_info=&quic_info_2;
	ret=session_l7_protocol_identify((const struct streaminfo *)&a_stream, &srt_process_context, NULL);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(0x00000001, srt_process_context.quic_version);
	EXPECT_STREQ("google.com", srt_process_context.quic_sni);
	dictator_free(0, (void *)srt_process_context.quic_sni);
	srt_process_context.quic_sni=NULL;
	EXPECT_EQ(nullptr, srt_process_context.quic_ua);
	g_test_quic_info=NULL;

	
	struct quic_info quic_info_3;
	struct quic_client_hello chello_3={(char *)"google.com", (char *)"Android"};
	quic_info_3.client_hello=&chello_3;
	quic_info_3.quic_version=0x00000001;
	g_test_quic_info=&quic_info_3;
	ret=session_l7_protocol_identify((const struct streaminfo *)&a_stream, &srt_process_context, NULL);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(0x00000001, srt_process_context.quic_version);
	EXPECT_STREQ("google.com", srt_process_context.quic_sni);
	dictator_free(0, (void *)srt_process_context.quic_sni);
	srt_process_context.quic_sni=NULL;
	
	EXPECT_STREQ("Android", srt_process_context.quic_ua);
	dictator_free(0, (void *)srt_process_context.quic_ua);
	srt_process_context.quic_ua=NULL;

	g_test_quic_info=NULL;
}

TEST(TSGMaster, SecurityMultipleRuleSortDenyMonitor)
{
	const struct streaminfo a_stream={0};
	struct maat_rule matched_policy[MAX_RESULT_NUM]={0};

	matched_policy[0].action=TSG_ACTION_MONITOR;
	matched_policy[0].rule_id=TSG_ACTION_MONITOR;
	matched_policy[0].service_id=TSG_SERVICE_SECURITY;

	matched_policy[1].action=TSG_ACTION_DENY;
	matched_policy[1].rule_id=TSG_ACTION_DENY;
	matched_policy[1].service_id=TSG_SERVICE_SECURITY;

	matched_policy[2].action=TSG_ACTION_MONITOR;
	matched_policy[2].rule_id=TSG_ACTION_MONITOR+1;
	matched_policy[2].service_id=TSG_SERVICE_SECURITY;

	matched_policy[3].action=TSG_ACTION_DENY;
	matched_policy[3].rule_id=TSG_ACTION_DENY+1;
	matched_policy[3].service_id=TSG_SERVICE_SECURITY;

	// First Monitor, second Intercpt
	session_matched_rules_notify(&a_stream, TSG_SERVICE_SECURITY, &matched_policy[0], 4, 0);
	
	struct maat_rule sorted_matched_policy[MAX_RESULT_NUM]={0};
	int ret=session_matched_rules_copy(&a_stream, TSG_SERVICE_SECURITY, sorted_matched_policy, 8);
	EXPECT_EQ(4, ret);

	EXPECT_EQ(TSG_ACTION_DENY, sorted_matched_policy[0].action);
	EXPECT_EQ(TSG_ACTION_DENY+1, sorted_matched_policy[0].rule_id);
	
	EXPECT_EQ(TSG_ACTION_DENY, sorted_matched_policy[1].action);
	EXPECT_EQ(TSG_ACTION_DENY, sorted_matched_policy[1].rule_id);
	
	EXPECT_EQ(TSG_ACTION_MONITOR, sorted_matched_policy[2].action);
	EXPECT_EQ(TSG_ACTION_MONITOR+1, sorted_matched_policy[2].rule_id);

	EXPECT_EQ(TSG_ACTION_MONITOR, sorted_matched_policy[3].action);
	EXPECT_EQ(TSG_ACTION_MONITOR, sorted_matched_policy[3].rule_id);

	const struct matched_policy_rules *hited_security=session_matched_rules_get(&a_stream, TSG_SERVICE_SECURITY);
	session_matched_rules_free(&a_stream, TSG_SERVICE_SECURITY, (void *)hited_security);
	session_matched_rules_async(&a_stream, TSG_SERVICE_SECURITY, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_SECURITY));
}

TEST(TSGMaster, SecurityMultipleRuleSortShuntAllowDenyMonitor)
{
	const struct streaminfo a_stream={0};
	struct maat_rule matched_policy[MAX_RESULT_NUM]={0};

	matched_policy[0].action=TSG_ACTION_MONITOR;
	matched_policy[0].rule_id=TSG_ACTION_MONITOR;
	matched_policy[0].service_id=TSG_SERVICE_SECURITY;

	matched_policy[1].action=TSG_ACTION_DENY;
	matched_policy[1].rule_id=TSG_ACTION_DENY;
	matched_policy[1].service_id=TSG_SERVICE_SECURITY;

	matched_policy[2].action=TSG_ACTION_MONITOR;
	matched_policy[2].rule_id=TSG_ACTION_MONITOR+1;
	matched_policy[2].service_id=TSG_SERVICE_SECURITY;

	matched_policy[3].action=TSG_ACTION_DENY;
	matched_policy[3].rule_id=TSG_ACTION_DENY+1;
	matched_policy[3].service_id=TSG_SERVICE_SECURITY;

	matched_policy[4].action=TSG_ACTION_BYPASS;
	matched_policy[4].rule_id=TSG_ACTION_BYPASS+1;
	matched_policy[4].service_id=TSG_SERVICE_SECURITY;

	matched_policy[5].action=TSG_ACTION_SHUNT;
	matched_policy[5].rule_id=TSG_ACTION_SHUNT+1;
	matched_policy[5].service_id=TSG_SERVICE_SECURITY;

	matched_policy[6].action=TSG_ACTION_BYPASS;
	matched_policy[6].rule_id=TSG_ACTION_BYPASS;
	matched_policy[6].service_id=TSG_SERVICE_SECURITY;

	matched_policy[7].action=TSG_ACTION_SHUNT;
	matched_policy[7].rule_id=TSG_ACTION_SHUNT;
	matched_policy[7].service_id=TSG_SERVICE_SECURITY;

	// First Monitor, second Intercpt
	session_matched_rules_notify(&a_stream, TSG_SERVICE_SECURITY, &matched_policy[0], 8, 0);
	
	struct maat_rule sorted_matched_policy[MAX_RESULT_NUM]={0};
	int ret=session_matched_rules_copy(&a_stream, TSG_SERVICE_SECURITY, sorted_matched_policy, 8);
	EXPECT_EQ(7, ret);

	EXPECT_EQ(TSG_ACTION_SHUNT, sorted_matched_policy[0].action);
	EXPECT_EQ(TSG_ACTION_SHUNT+1, sorted_matched_policy[0].rule_id);

	EXPECT_EQ(TSG_ACTION_SHUNT, sorted_matched_policy[1].action);
	EXPECT_EQ(TSG_ACTION_SHUNT, sorted_matched_policy[1].rule_id);
	
	EXPECT_EQ(TSG_ACTION_BYPASS, sorted_matched_policy[2].action);
	EXPECT_EQ(TSG_ACTION_BYPASS+1, sorted_matched_policy[2].rule_id);
	
	EXPECT_EQ(TSG_ACTION_DENY, sorted_matched_policy[3].action);
	EXPECT_EQ(TSG_ACTION_DENY+1, sorted_matched_policy[3].rule_id);

	EXPECT_EQ(TSG_ACTION_DENY, sorted_matched_policy[4].action);
	EXPECT_EQ(TSG_ACTION_DENY, sorted_matched_policy[4].rule_id);

	EXPECT_EQ(TSG_ACTION_MONITOR, sorted_matched_policy[5].action);
	EXPECT_EQ(TSG_ACTION_MONITOR+1, sorted_matched_policy[5].rule_id);

	EXPECT_EQ(TSG_ACTION_MONITOR, sorted_matched_policy[6].action);
	EXPECT_EQ(TSG_ACTION_MONITOR, sorted_matched_policy[6].rule_id);

	const struct matched_policy_rules *hited_security=session_matched_rules_get(&a_stream, TSG_SERVICE_SECURITY);
	EXPECT_EQ(7, hited_security->n_rules);

	EXPECT_EQ(TSG_ACTION_SHUNT, hited_security->rules[0].action);
	EXPECT_EQ(TSG_ACTION_SHUNT+1, hited_security->rules[0].rule_id);

	EXPECT_EQ(TSG_ACTION_SHUNT, hited_security->rules[1].action);
	EXPECT_EQ(TSG_ACTION_SHUNT, hited_security->rules[1].rule_id);
	
	EXPECT_EQ(TSG_ACTION_BYPASS, hited_security->rules[2].action);
	EXPECT_EQ(TSG_ACTION_BYPASS+1, hited_security->rules[2].rule_id);
	
	EXPECT_EQ(TSG_ACTION_DENY, hited_security->rules[3].action);
	EXPECT_EQ(TSG_ACTION_DENY+1, hited_security->rules[3].rule_id);

	EXPECT_EQ(TSG_ACTION_DENY, hited_security->rules[4].action);
	EXPECT_EQ(TSG_ACTION_DENY, hited_security->rules[4].rule_id);

	EXPECT_EQ(TSG_ACTION_MONITOR, hited_security->rules[5].action);
	EXPECT_EQ(TSG_ACTION_MONITOR+1, hited_security->rules[5].rule_id);

	EXPECT_EQ(TSG_ACTION_MONITOR, hited_security->rules[6].action);
	EXPECT_EQ(TSG_ACTION_MONITOR, hited_security->rules[6].rule_id);

	session_matched_rules_free(&a_stream, TSG_SERVICE_SECURITY, (void *)hited_security);
	session_matched_rules_async(&a_stream, TSG_SERVICE_SECURITY, NULL);
	EXPECT_EQ(nullptr, session_matched_rules_get(&a_stream, TSG_SERVICE_SECURITY));
}

int main(int argc, char *argv[])
{
	TSG_MASTER_INIT();
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}