#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <MESA/field_stat2.h>
#include <MESA/stream.h>

#include "tsg_rule.h"
#include "tsg_send_log.h"
#include "tsg_send_log_internal.h"

#include "gtest_common.h"
#include "gtest_kafka.h"

#include <gtest/gtest.h>

struct maat *g_tsg_maat_feather;

extern struct tsg_log_instance_t *tsg_sendlog_init(const char * conffile, screen_stat_handle_t fs2_handle);

char *tsg_device_tag_get(void)
{
	return NULL;
}

char *tsg_data_center_get(void)
{
	return NULL;
}

int tsg_location_type_get(void)
{
	return 0;
}

int tsg_session_record_switch_get(void)
{
	return 1;
}

void *session_mac_linkinfo_get(const struct streaminfo * a_stream)
{
	return NULL;
}
void *session_log_update_data_get(const struct streaminfo *a_stream, enum TSG_SERVICE service)
{
	return NULL;
}

void *session_gather_app_results_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *session_conn_sketch_notify_data_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *session_business_data_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *session_session_flags_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *session_application_behavior_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *session_mirrored_and_capture_packets_exec_result_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *session_lua_user_defined_attribute_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *session_nat_c2s_linkinfo_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *session_nat_s2c_linkinfo_get(const struct streaminfo * a_stream)
{
	return NULL;
}

int session_matched_rules_async(const struct streaminfo * a_stream, TSG_SERVICE service, void * data)
{
	return 0;
}

const struct matched_policy_rules *session_matched_rules_get(const struct streaminfo *a_stream, enum TSG_SERVICE service)
{
	return 0;
}

void session_matched_rules_free(const struct streaminfo * a_stream, TSG_SERVICE service, void * data)
{
}

char srt_action_context_get_direction(const struct streaminfo * a_stream)
{
	return 0;
}

int tsg_get_app_name_by_id(struct maat *feahter, int app_id, char * app_name, int app_name_len, int is_joint_parent)
{
	return 0;
}

const struct session_runtime_attribute *session_runtime_attribute_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *matched_rule_cites_security_compile(struct maat * feather, long long compile_id)
{
	return NULL;
}

void plugin_ex_data_security_compile_free(struct maat_compile * maat_compile)
{
}

int tsg_set_policy_flow(const struct streaminfo * a_stream, struct maat_rule * p_result, int thread_seq)
{
	return 0;
}

TEST(Master, SendInterimRecord)
{
	struct streaminfo a_stream={0};
	struct tcpdetail pdetail={NULL, 0, 0, 3, 50, 3, 50, 0, 1};
	a_stream.ptcpdetail=&pdetail;
	a_stream.type=STREAM_TYPE_TCP;

	struct maat_rule rules={0, 0, 0, 2, 0, 1};

	struct TLD_handle_t * handle=TLD_create(0);
	tsg_send_log(g_tsg_log_instance, handle, &a_stream, LOG_TYPE_INTERIM_SESSION_RECORD, &rules, 1, 0);
	int sendlog_cnt=rd_kafka_get_sendlog_cnt();
	EXPECT_EQ(1, sendlog_cnt);
	EXPECT_STREQ("{\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_t_vsys_id\":1,\"common_vsys_id\":1}",rd_kafka_get_sendlog_payload(0));
	rd_kafka_clean_sendlog_cnt();
	EXPECT_EQ(0, rd_kafka_get_sendlog_cnt());

	g_tsg_log_instance->send_interim_log=0;
	handle=TLD_create(0);
	tsg_send_log(g_tsg_log_instance, handle, &a_stream, LOG_TYPE_INTERIM_SESSION_RECORD, &rules, 1, 0);
	sendlog_cnt=rd_kafka_get_sendlog_cnt();
	EXPECT_EQ(0, sendlog_cnt);
}

TEST(Master, SendTranscationRecord)
{
	struct streaminfo a_stream={0};
	struct tcpdetail pdetail={NULL, 0, 0, 3, 50, 3, 50, 0, 1};
	a_stream.ptcpdetail=&pdetail;
	a_stream.type=STREAM_TYPE_TCP;

	struct maat_rule rules={0, 0, 0, 2, 0, 1};

	struct TLD_handle_t * handle=TLD_create(0);
	tsg_send_log(g_tsg_log_instance, handle, &a_stream, LOG_TYPE_TRANSACTION_RECORD, &rules, 1, 0);
	int sendlog_cnt=rd_kafka_get_sendlog_cnt();
	EXPECT_EQ(1, sendlog_cnt);
	EXPECT_STREQ("{\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_t_vsys_id\":1,\"common_vsys_id\":1}",rd_kafka_get_sendlog_payload(0));
	rd_kafka_clean_sendlog_cnt();
	EXPECT_EQ(0, rd_kafka_get_sendlog_cnt());

	g_tsg_log_instance->send_transcation_log=0;
	handle=TLD_create(0);
	tsg_send_log(g_tsg_log_instance, handle, &a_stream, LOG_TYPE_TRANSACTION_RECORD, &rules, 1, 0);
	sendlog_cnt=rd_kafka_get_sendlog_cnt();
	EXPECT_EQ(0, sendlog_cnt);
}

TEST(Master, SendSessionRecord)
{
	struct streaminfo a_stream={0};
	struct tcpdetail pdetail={NULL, 0, 0, 3, 50, 3, 50, 0, 1};
	a_stream.ptcpdetail=&pdetail;
	a_stream.type=STREAM_TYPE_TCP;

	struct maat_rule rules={0, 0, 0, 2, 0, 1};

	struct TLD_handle_t * handle=TLD_create(0);
	tsg_send_log(g_tsg_log_instance, handle, &a_stream, LOG_TYPE_SESSION_RECORD, &rules, 1, 0);
	int sendlog_cnt=rd_kafka_get_sendlog_cnt();
	EXPECT_EQ(1, sendlog_cnt);
	EXPECT_STREQ("{\"common_server_port\":0,\"common_client_port\":0,\"common_stream_dir\":0,\"common_address_type\":0,\"common_stream_trace_id\":\"5\",\"common_sled_ip\":\"0.0.0.0\",\"common_t_vsys_id\":1,\"common_vsys_id\":1}",rd_kafka_get_sendlog_payload(0));
	rd_kafka_clean_sendlog_cnt();
	EXPECT_EQ(0, rd_kafka_get_sendlog_cnt());

	//pkts=3, bytes=0
	pdetail={NULL, 0, 0, 0, 0, 3, 0, 0, 1};
	a_stream.ptcpdetail=&pdetail;
	a_stream.type=STREAM_TYPE_TCP;
	handle=TLD_create(0);
	tsg_send_log(g_tsg_log_instance, handle, &a_stream, LOG_TYPE_SESSION_RECORD, &rules, 1, 0);
	sendlog_cnt=rd_kafka_get_sendlog_cnt();
	EXPECT_EQ(0, sendlog_cnt);

	//pkts=2, bytes=1500
	pdetail={NULL, 0, 0, 0, 0, 2, 1500, 0, 1};
	a_stream.ptcpdetail=&pdetail;
	a_stream.type=STREAM_TYPE_TCP;
	handle=TLD_create(0);
	tsg_send_log(g_tsg_log_instance, handle, &a_stream, LOG_TYPE_SESSION_RECORD, &rules, 1, 0);
	sendlog_cnt=rd_kafka_get_sendlog_cnt();
	EXPECT_EQ(0, sendlog_cnt);
}

int main(int argc, char *argv[])
{
	screen_stat_handle_t fs2_handle=FS_create_handle();

	int value=0,cycle=30;
	value=1;//Rewrite
	FS_set_para(fs2_handle, PRINT_MODE, &value, sizeof(value));
	value=1;//Do not create stat thread
	FS_set_para(fs2_handle, CREATE_THREAD, &value, sizeof(value));
	FS_set_para(fs2_handle, STAT_CYCLE, &cycle, sizeof(cycle));
	FS_set_para(fs2_handle, APP_NAME, (char *)"test", strlen((char *)"test")+1);

	value=FS_OUTPUT_INFLUX_LINE;
	FS_set_para(fs2_handle, STATS_FORMAT, &value, sizeof(value));

	g_tsg_log_instance=tsg_sendlog_init("./tsgconf/main.conf", fs2_handle);
	FS_start(fs2_handle);
	
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

