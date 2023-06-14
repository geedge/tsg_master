#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "tsg_rule.h"
#include "tsg_label.h"
#include "tsg_entry.h"
#include "tsg_variable.h"
#include "tsg_rule_internal.h"
#include "tsg_protocol_common.h"
#include "tsg_sync_state.h"
#include "tsg_proxy.h"

#include <gtest/gtest.h>

void tsg_maat_state_free(struct maat_state *state)
{
	
}

void destroy_bucket(struct leaky_bucket **bucket, int thread_seq)
{
	
}

void plugin_ex_data_gtp_c_free(struct umts_user_info *user_info)
{
	if (user_info != NULL)
	{
		free(user_info);
		user_info = NULL;
	}
}

void plugin_ex_data_asn_number_free(struct asn_info *asn)
{
	if (asn != NULL)
	{
		free(asn);
		asn = NULL;
	}
}

void plugin_ex_data_location_free(struct location_info *location)
{
	if (location != NULL)
	{
		free(location);
		location = NULL;
	}
}

void plugin_ex_data_subscriber_id_free(struct subscribe_id_info *subscriber)
{
	if (subscriber != NULL)
	{
		free(subscriber);
		subscriber = NULL;
	}
}

void plugin_ex_data_tunnel_endpoint_free(struct tunnel_endpoint *t_enpoint)
{
	if (t_enpoint != NULL)
	{
		free(t_enpoint);
		t_enpoint = NULL;
	}
}

int srt_attribute_set_ip_asn(const struct streaminfo * a_stream, struct maat *feather, struct asn_info **client_asn, struct asn_info **server_asn)
{
	return 0;
}

int  srt_attribute_set_ip_location(const struct streaminfo * a_stream, struct maat *feather, struct location_info **client_location, struct location_info **server_location)
{
	return 0;
}

int srt_attribute_set_subscriber_id(const struct streaminfo *a_stream, struct maat *feather, struct subscribe_id_info **client_subscribe_id, struct subscribe_id_info **server_subscribe_id)
{
	return 0;
}

int session_runtine_attribute_get_umts_user_info(const struct streaminfo *a_stream, struct umts_user_info **user_info)
{
	return 0;
}

struct umts_user_info *tsg_get_umts_user_info_form_redis(struct maat *feather, unsigned int teid)
{
	return NULL;
}

int SyncAppIdentifyResult_test_data_after = 0;
int session_app_identify_result_cb(const struct streaminfo * a_stream, int bridge_id, void * data)
{
	SyncAppIdentifyResult_test_data_after = *((int *)data);
	return 0;
}

int SyncSessionFlags_test_data_after = 0;
int session_flags_identify_result_cb(const struct streaminfo * a_stream, int bridge_id, void * data)
{
	SyncSessionFlags_test_data_after = *((int *)data);
	return 0;
}

int tsg_sync_policy_update(const struct streaminfo *a_stream, struct update_policy *policy_update)
{
	return 0;
}

int matched_service_chaining_rules_deal(const struct streaminfo *a_stream, struct maat_rule *s_chaining_rules, size_t n_s_chaining_rules, int thread_seq)
{
	return 0;
}

int matched_shaping_rules_deal(const struct streaminfo * a_stream, struct maat_rule * shaping_results, size_t n_shaping_results, int thread_seq)
{
	return 0;
}

int session_packet_capture_by_rules_notify(const struct streaminfo * a_stream, struct maat_rule * rules, size_t n_rules, int thread_seq)
{
	return 0;
}

struct bridge_info
{
	int id;
	char name[MAX_BRIDGE_NAME_LEN];
	stream_bridge_free_cb_t *free_cb;
	stream_bridge_sync_cb_t *sync_cb;
};
extern struct bridge_info g_tsg_bridge_para[BRIDGE_TYPE_MAX];

TEST(TSGBridge, SyncAppIdentifyResultSync)
{
	const struct streaminfo a_stream = {0};
	int SyncAppIdentifyResult_test_data_before = 10;
	stream_bridge_sync_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_SYNC_APP_IDENTIFY_RESULT].id, (void *)&SyncAppIdentifyResult_test_data_before);
	EXPECT_EQ(10, SyncAppIdentifyResult_test_data_after);
	SyncAppIdentifyResult_test_data_after = 0;
}

TEST(TSGBridge, RecvConnSketchDataAsync)
{
	const struct streaminfo a_stream = {0};
	struct tsg_conn_sketch_notify_data RecvConnSketchData_test_data_before;
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_RECV_CONN_SKETCH_DATA].id, (void *)&RecvConnSketchData_test_data_before);
	struct tsg_conn_sketch_notify_data *RecvConnSketchData_test_data_after = (struct tsg_conn_sketch_notify_data *)session_conn_sketch_notify_data_get(&a_stream);
	EXPECT_EQ(&RecvConnSketchData_test_data_before, RecvConnSketchData_test_data_after);
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_RECV_CONN_SKETCH_DATA].id, NULL);
}

struct tsg_notify_data notify_data_for_test = {0};
int send_conn_sketch_data_sync_cb(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	memcpy(&notify_data_for_test, data, sizeof(struct tsg_notify_data));
	return 0;
}
TEST(TSGBridge, SendConnSketchDataMirrorSync)
{
	stream_bridge_register_data_sync_cb(g_tsg_bridge_para[BRIDGE_TYPE_SEND_CONN_SKETCH_DATA].id, send_conn_sketch_data_sync_cb);

	const struct streaminfo a_stream = {0};
	struct maat_rule rules = {0};
	rules.rule_id = 1001;
	struct mirrored_vlan vlan = {0};
	session_mirror_packets_sync(&a_stream, &rules, &vlan);
	EXPECT_EQ(notify_data_for_test.compile_id, 1001);
	EXPECT_EQ(notify_data_for_test.type, NOTIFY_TYPE_MIRRORED);
	EXPECT_EQ(notify_data_for_test.vlan, &vlan);
	memset(&notify_data_for_test, 0, sizeof(struct tsg_notify_data));
}

TEST(TSGBridge, SendConnSketchDataCaptureSync)
{
	stream_bridge_register_data_sync_cb(g_tsg_bridge_para[BRIDGE_TYPE_SEND_CONN_SKETCH_DATA].id, send_conn_sketch_data_sync_cb);

	const struct streaminfo a_stream = {0};
	struct maat_rule rules = {0};
	rules.rule_id = 1002;
	session_capture_packets_sync(&a_stream, &rules, 10);
	EXPECT_EQ(notify_data_for_test.compile_id, 1002);
	EXPECT_EQ(notify_data_for_test.type, NOTIFY_TYPE_CAPTURE);
	EXPECT_EQ(notify_data_for_test.capture_depth, 10);
	memset(&notify_data_for_test, 0, sizeof(struct tsg_notify_data));
}

TEST(TSGBridge, SessionFlagsSync)
{
	const struct streaminfo a_stream = {0};
	int SyncSessionFlags_test_data_before = 20;
	stream_bridge_sync_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_SYNC_SESSION_FLAGS].id, (void *)&SyncSessionFlags_test_data_before);
	EXPECT_EQ(20, SyncSessionFlags_test_data_after);
	SyncSessionFlags_test_data_after = 0;
}

struct session_marker_notify_ctx
{
	uint64_t flags;
	char *identify_str;
};
TEST(TSGBridge, SessionFlagsAsync)
{
	const struct streaminfo a_stream = {0};
	struct session_marker_notify_ctx sm_notify = {0};
	sm_notify.flags = 40;
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_ASYNC_SESSION_FLAGS].id, (void *)&sm_notify);
	struct session_marker_notify_ctx *test = (struct session_marker_notify_ctx *)session_session_flags_get(&a_stream);
	EXPECT_EQ(test->flags, 40);
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_ASYNC_SESSION_FLAGS].id, NULL);
	EXPECT_EQ(nullptr, session_session_flags_get(&a_stream));
}

extern int session_matched_rules_sync(const struct streaminfo *a_stream, TSG_SERVICE service, void *data);
struct matched_policy_rules matched_rules_test_data_after = {0};
int session_matched_rules_result_sync_cb(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	memcpy(&matched_rules_test_data_after, data, sizeof(struct matched_policy_rules));
	return 0;
}
TEST(TSGBridge, ShapingResultSync)
{
	stream_bridge_register_data_sync_cb(g_tsg_bridge_para[BRIDGE_TYPE_SHAPING_RESULT].id, session_matched_rules_result_sync_cb);
	const struct streaminfo a_stream = {0};
	struct matched_policy_rules ShapingResultSync_test_data_before = {0};
	ShapingResultSync_test_data_before.n_rules = 1;
	session_matched_rules_sync(&a_stream, TSG_SERVICE_SHAPING, (void *)&ShapingResultSync_test_data_before);
	EXPECT_EQ(1, matched_rules_test_data_after.n_rules);
	memset(&matched_rules_test_data_after, 0, sizeof(struct matched_policy_rules));
}

TEST(TSGBridge, ShapingResultAsync)
{
	const struct streaminfo a_stream = {0};
	struct matched_policy_rules *rules = (struct matched_policy_rules *)dictator_malloc(a_stream.threadnum, sizeof(struct matched_policy_rules));
	rules->n_rules = 1;
	rules->rules[0].rule_id = 10;

	session_matched_rules_async(&a_stream, TSG_SERVICE_SHAPING, (void *)rules);
	const struct matched_policy_rules *temp = session_matched_rules_get(&a_stream, TSG_SERVICE_SHAPING);
	EXPECT_EQ(temp->n_rules, 1);
	EXPECT_EQ(temp->rules[0].rule_id, 10);
	session_matched_rules_free(&a_stream, TSG_SERVICE_SHAPING, (void *)temp);
	session_matched_rules_async(&a_stream, TSG_SERVICE_SHAPING, NULL);
}

TEST(TSGBridge, ServiceChainingResultSync)
{
	stream_bridge_register_data_sync_cb(g_tsg_bridge_para[BRIDGE_TYPE_SERVICE_CHAINING_RESULT].id, session_matched_rules_result_sync_cb);
	const struct streaminfo a_stream = {0};
	struct matched_policy_rules ServiceChainingResultSync_test_data_before = {0};
	ServiceChainingResultSync_test_data_before.n_rules = 2;
	session_matched_rules_sync(&a_stream, TSG_SERVICE_CHAINING, (void *)&ServiceChainingResultSync_test_data_before);
	EXPECT_EQ(2, matched_rules_test_data_after.n_rules);
	memset(&matched_rules_test_data_after, 0, sizeof(struct matched_policy_rules));
}

TEST(TSGBridge, ServiceChainingResultAsync)
{
	const struct streaminfo a_stream = {0};
	struct matched_policy_rules *rules = (struct matched_policy_rules *)dictator_malloc(a_stream.threadnum, sizeof(struct matched_policy_rules));
	rules->n_rules = 2;
	rules->rules[0].rule_id = 20;

	session_matched_rules_async(&a_stream, TSG_SERVICE_CHAINING, (void *)rules);
	const struct matched_policy_rules *temp = session_matched_rules_get(&a_stream, TSG_SERVICE_CHAINING);
	EXPECT_EQ(temp->n_rules, 2);
	EXPECT_EQ(temp->rules[0].rule_id, 20);
	session_matched_rules_free(&a_stream, TSG_SERVICE_CHAINING, (void *)temp);
	session_matched_rules_async(&a_stream, TSG_SERVICE_CHAINING, NULL);
}

TEST(TSGBridge, SecurityResultSync)
{
	stream_bridge_register_data_sync_cb(g_tsg_bridge_para[BRIDGE_TYPE_SECURITY_RESULT].id, session_matched_rules_result_sync_cb);
	const struct streaminfo a_stream = {0};
	struct matched_policy_rules SecurityResultSync_test_data_before = {0};
	SecurityResultSync_test_data_before.n_rules = 3;
	session_matched_rules_sync(&a_stream, TSG_SERVICE_SECURITY, (void *)&SecurityResultSync_test_data_before);
	EXPECT_EQ(0, matched_rules_test_data_after.n_rules);
	memset(&matched_rules_test_data_after, 0, sizeof(struct matched_policy_rules));
}

TEST(TSGBridge, SecurityResultAsync)
{
	const struct streaminfo a_stream = {0};
	struct matched_policy_rules *rules = (struct matched_policy_rules *)dictator_malloc(a_stream.threadnum, sizeof(struct matched_policy_rules));
	rules->n_rules = 3;
	rules->rules[0].rule_id = 30;

	session_matched_rules_async(&a_stream, TSG_SERVICE_SECURITY, (void *)rules);
	const struct matched_policy_rules *temp = session_matched_rules_get(&a_stream, TSG_SERVICE_SECURITY);
	EXPECT_EQ(temp->n_rules, 3);
	EXPECT_EQ(temp->rules[0].rule_id, 30);
	session_matched_rules_free(&a_stream, TSG_SERVICE_SECURITY, (void *)temp);
	session_matched_rules_async(&a_stream, TSG_SERVICE_SECURITY, NULL);
}

TEST(TSGBridge, InterceptResultSync)
{
	stream_bridge_register_data_sync_cb(g_tsg_bridge_para[BRIDGE_TYPE_INTERCEPT_RESULT].id, session_matched_rules_result_sync_cb);
	const struct streaminfo a_stream = {0};
	struct matched_policy_rules InterceptResultSync_test_data_before = {0};
	InterceptResultSync_test_data_before.n_rules = 4;
	session_matched_rules_sync(&a_stream, TSG_SERVICE_INTERCEPT, (void *)&InterceptResultSync_test_data_before);
	EXPECT_EQ(4, matched_rules_test_data_after.n_rules);
	memset(&matched_rules_test_data_after, 0, sizeof(struct matched_policy_rules));
}

TEST(TSGBridge, InterceptResultAsync)
{
	const struct streaminfo a_stream = {0};
	struct matched_policy_rules *rules = (struct matched_policy_rules *)dictator_malloc(a_stream.threadnum, sizeof(struct matched_policy_rules));
	rules->n_rules = 4;
	rules->rules[0].rule_id = 40;

	session_matched_rules_async(&a_stream, TSG_SERVICE_INTERCEPT, (void *)rules);
	const struct matched_policy_rules *temp = session_matched_rules_get(&a_stream, TSG_SERVICE_INTERCEPT);
	EXPECT_EQ(temp->n_rules, 4);
	EXPECT_EQ(temp->rules[0].rule_id, 40);
	session_matched_rules_free(&a_stream, TSG_SERVICE_INTERCEPT, (void *)temp);
	session_matched_rules_async(&a_stream, TSG_SERVICE_INTERCEPT, NULL);
}

TEST(TSGBridge, AppSignatureResultSync)
{
	stream_bridge_register_data_sync_cb(g_tsg_bridge_para[BRIDGE_TYPE_APP_SIGNATURE_RESULT].id, session_matched_rules_result_sync_cb);
	const struct streaminfo a_stream = {0};
	struct matched_policy_rules AppSignaturegResultSync_test_data_before = {0};
	AppSignaturegResultSync_test_data_before.n_rules = 5;
	session_matched_rules_sync(&a_stream, TSG_SERVICE_SIGNATURE, (void *)&AppSignaturegResultSync_test_data_before);
	EXPECT_EQ(5, matched_rules_test_data_after.n_rules);
	memset(&matched_rules_test_data_after, 0, sizeof(struct matched_policy_rules));
}

TEST(TSGBridge, AppSignatureResultAsync)
{
	const struct streaminfo a_stream = {0};
	struct matched_policy_rules *rules = (struct matched_policy_rules *)dictator_malloc(a_stream.threadnum, sizeof(struct matched_policy_rules));
	rules->n_rules = 5;
	rules->rules[0].rule_id = 50;

	session_matched_rules_async(&a_stream, TSG_SERVICE_SIGNATURE, (void *)rules);
	const struct matched_policy_rules *temp = session_matched_rules_get(&a_stream, TSG_SERVICE_SIGNATURE);
	EXPECT_EQ(temp->n_rules, 5);
	EXPECT_EQ(temp->rules[0].rule_id, 50);
	session_matched_rules_free(&a_stream, TSG_SERVICE_SIGNATURE, (void *)temp);
	session_matched_rules_async(&a_stream, TSG_SERVICE_SIGNATURE, NULL);
}

extern const struct session_runtime_process_context *session_runtime_process_context_new(const struct streaminfo *a_stream);
extern void session_runtime_process_context_free_cb(const struct streaminfo *a_stream, int bridge_id, void *data);
TEST(TSGBridge, SessionProcessContextAsync)
{
	const struct streaminfo a_stream = {0};
	const struct session_runtime_process_context *context = session_runtime_process_context_new(&a_stream);
	EXPECT_EQ(session_runtime_process_context_get(&a_stream), context);
	EXPECT_EQ(session_runtime_process_context_get(&a_stream), session_runtime_process_context_new(&a_stream));
	session_runtime_process_context_free_cb(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_SESSION_PROCESS_CONTEXT].id, (void *)context);
	session_runtime_process_context_async(&a_stream, NULL);
	EXPECT_EQ(nullptr, session_runtime_process_context_get(&a_stream));
}

extern void session_runtime_action_context_free(const struct streaminfo *a_stream, int bridge_id, void *data);
TEST(TSGBridge, SessionActionContextAsync)
{
	const struct streaminfo a_stream = {0};
	struct session_runtime_action_context *context = (struct session_runtime_action_context *)session_runtime_action_context_new(&a_stream);
	EXPECT_EQ(session_runtime_action_context_get(&a_stream), context);
	EXPECT_EQ(session_runtime_action_context_get(&a_stream), session_runtime_action_context_new(&a_stream));
	context->direction = DIR_S2C;
	EXPECT_EQ(srt_action_context_get_direction(context), DIR_S2C);
	session_runtime_action_context_free(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_SESSION_ACTION_CONTEXT].id, (void *)context);
	session_runtime_action_context_async(&a_stream, NULL);
	EXPECT_EQ(nullptr, session_runtime_action_context_get(&a_stream));
}

static void tsg_bridge_test_init_process_ctx(const struct streaminfo *a_stream, struct session_runtime_process_context *process_ctx)
{
	process_ctx->domain = (char *)dictator_malloc(a_stream->threadnum, strlen("thisisdomain") + 1);
	memset(process_ctx->domain, 0, strlen("thisisdomain") + 1);
	memcpy(process_ctx->domain, "thisisdomain", strlen("thisisdomain"));

	process_ctx->http_url = (char *)dictator_malloc(a_stream->threadnum, strlen("thisishttp_url") + 1);
	memset(process_ctx->http_url, 0, strlen("thisishttp_url") + 1);
	memcpy(process_ctx->http_url, "thisishttp_url", strlen("thisishttp_url"));
}

TEST(TSGBridge, ProcessAndActionContextAsync)
{
	const struct streaminfo a_stream = {0};
	struct session_runtime_action_context *action_ctx = (struct session_runtime_action_context *)session_runtime_action_context_new(&a_stream);
	struct session_runtime_process_context *process_ctx = (struct session_runtime_process_context *)session_runtime_process_context_new(&a_stream);
	tsg_bridge_test_init_process_ctx(&a_stream, process_ctx);

	EXPECT_EQ(session_runtime_action_context_get(&a_stream), action_ctx);
	struct session_runtime_process_context *process_test = (struct session_runtime_process_context *)session_runtime_process_context_get(&a_stream);
	EXPECT_STREQ(process_test->domain, "thisisdomain");
	EXPECT_STREQ(process_test->http_url, "thisishttp_url");
	session_runtime_action_context_free(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_SESSION_ACTION_CONTEXT].id, (void *)action_ctx);
	session_runtime_process_context_free_cb(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_SESSION_PROCESS_CONTEXT].id, (void *)process_test);
	session_runtime_action_context_async(&a_stream, NULL);
	EXPECT_EQ(nullptr, session_runtime_action_context_get(&a_stream));
	session_runtime_process_context_async(&a_stream, NULL);
	EXPECT_EQ(nullptr, session_runtime_process_context_get(&a_stream));
}

extern void session_gather_app_results_free(const struct streaminfo *a_stream, int bridge_id, void *data);
TEST(TSGBridge, GatherAppResultAsync)
{
	const struct streaminfo a_stream = {0};
	struct gather_app_result *gather_result_in = (struct gather_app_result *)dictator_malloc(a_stream.threadnum, sizeof(struct gather_app_result));
	memset(gather_result_in, 0, sizeof(struct gather_app_result));

	gather_result_in->unknown_flag = 1;
	gather_result_in->unknown.app_id=4;
	gather_result_in->unknown.surrogate_id=0;
	gather_result_in->unknown.packet_sequence=40;
	
	session_gather_app_results_async(&a_stream, (void *)gather_result_in);
	struct gather_app_result *gather_result_out = (struct gather_app_result *)session_gather_app_results_get(&a_stream);
	EXPECT_NE(nullptr, gather_result_out);
	EXPECT_EQ(gather_result_out->unknown_flag, 1);
	EXPECT_EQ(gather_result_out->unknown.app_id, 4);
	EXPECT_EQ(gather_result_out->unknown.surrogate_id, 0);
	EXPECT_EQ(gather_result_out->unknown.packet_sequence, 40);
	
	EXPECT_EQ(gather_result_out->matched_app_flag, 0);
	EXPECT_EQ(gather_result_out->l7_protocol_num, 0);
	EXPECT_EQ(gather_result_out->l7_qm_engine_num, 0);
	EXPECT_EQ(gather_result_out->qm_engine_num, 0);
	EXPECT_EQ(gather_result_out->user_define_num, 0);
	EXPECT_EQ(gather_result_out->built_in_num, 0);
	
	EXPECT_EQ(nullptr, gather_result_out->built_in);
	EXPECT_EQ(nullptr, gather_result_out->l7_protocol);
	EXPECT_EQ(nullptr, gather_result_out->qm_engine);
	EXPECT_EQ(nullptr, gather_result_out->user_define);
	
	session_gather_app_results_free(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_GATHER_APP_RESULT].id, (void *)gather_result_out);
	session_gather_app_results_async(&a_stream, NULL);

	EXPECT_EQ(nullptr, session_gather_app_results_get(&a_stream));
}

static void tsg_bridge_test_init_attribute(const struct streaminfo *a_stream, struct session_runtime_attribute *attribute)
{
	attribute->client_asn = (struct asn_info *)dictator_malloc(a_stream->threadnum, sizeof(struct asn_info));
	attribute->client_asn->ref_cnt = 1;
	attribute->server_asn = (struct asn_info *)dictator_malloc(a_stream->threadnum, sizeof(struct asn_info));
	attribute->server_asn->ref_cnt = 2;
	attribute->client_location = (struct location_info *)dictator_malloc(a_stream->threadnum, sizeof(struct location_info));
	attribute->client_location->ref_cnt = 3;
	attribute->server_location = (struct location_info *)dictator_malloc(a_stream->threadnum, sizeof(struct location_info));
	attribute->server_location->ref_cnt = 4;
	attribute->client_endpoint = (struct tunnel_endpoint *)dictator_malloc(a_stream->threadnum, sizeof(struct tunnel_endpoint));
	attribute->client_endpoint->ref_cnt = 5;
	attribute->server_endpoint = (struct tunnel_endpoint *)dictator_malloc(a_stream->threadnum, sizeof(struct tunnel_endpoint));
	attribute->server_endpoint->ref_cnt = 6;
	attribute->client_subscribe_id = (struct subscribe_id_info *)dictator_malloc(a_stream->threadnum, sizeof(struct subscribe_id_info));
	attribute->client_subscribe_id->ref_cnt = 7;
	attribute->server_subscribe_id = (struct subscribe_id_info *)dictator_malloc(a_stream->threadnum, sizeof(struct subscribe_id_info));
	attribute->server_subscribe_id->ref_cnt = 8;
	attribute->user_info = (struct umts_user_info *)dictator_malloc(a_stream->threadnum, sizeof(struct umts_user_info));
	attribute->user_info->ref_cnt = 9;
	attribute->ja3_fingerprint = (char *)dictator_malloc(a_stream->threadnum, sizeof("thisisja3_fingerprint") + 1);
	memset((char *)attribute->ja3_fingerprint, 0, strlen("thisisja3_fingerprint") + 1);
	memcpy((char *)attribute->ja3_fingerprint, "thisisja3_fingerprint", strlen("thisisja3_fingerprint"));
	attribute->proxy_tcp_attr = (struct tsg_proxy_tcp_attribute *)dictator_malloc(a_stream->threadnum, sizeof(struct tsg_proxy_tcp_attribute));
	attribute->proxy_tcp_attr->tcp_seq = 10;
}

extern void session_runtime_attribute_free(const struct streaminfo *a_stream, int bridge_id, void *data);
TEST(TSGBridge, SessionAttributeAsync)
{
	const struct streaminfo a_stream = {0};
	struct session_runtime_attribute *attribute = (struct session_runtime_attribute *)session_runtime_attribute_new(&a_stream);
	tsg_bridge_test_init_attribute(&a_stream, attribute);
	EXPECT_EQ(session_runtime_attribute_get(&a_stream), attribute);
	EXPECT_EQ(session_runtime_attribute_get(&a_stream), session_runtime_attribute_new(&a_stream));
	struct session_runtime_attribute *attribute_test = (struct session_runtime_attribute *)session_runtime_attribute_get(&a_stream);
	EXPECT_EQ(attribute_test->client_asn->ref_cnt, 1);
	EXPECT_EQ(attribute_test->server_asn->ref_cnt, 2);
	EXPECT_EQ(attribute_test->client_location->ref_cnt, 3);
	EXPECT_EQ(attribute_test->server_location->ref_cnt, 4);
	EXPECT_EQ(attribute_test->client_endpoint->ref_cnt, 5);
	EXPECT_EQ(attribute_test->server_endpoint->ref_cnt, 6);
	EXPECT_EQ(attribute_test->client_subscribe_id->ref_cnt, 7);
	EXPECT_EQ(attribute_test->server_subscribe_id->ref_cnt, 8);
	EXPECT_EQ(attribute_test->user_info->ref_cnt, 9);
	EXPECT_STREQ(attribute->ja3_fingerprint, "thisisja3_fingerprint");
	EXPECT_EQ(attribute_test->proxy_tcp_attr->tcp_seq, 10);
	session_runtime_attribute_free(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_SESSION_ATTRIBUTE].id, (void *)attribute);
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_SESSION_ATTRIBUTE].id, NULL);
	EXPECT_EQ(nullptr, session_runtime_attribute_get(&a_stream));
}

TEST(TSGBridge, MacLinkinfoAsync)
{
	const struct streaminfo a_stream = {0};
	char linkinfo[10];
	linkinfo[0] = 0x01;
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_MAC_LINKINFO].id, (void *)linkinfo);
	char *test = (char *)session_mac_linkinfo_get(&a_stream);
	EXPECT_EQ(test[0], 0x01);
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_MAC_LINKINFO].id, NULL);
	EXPECT_EQ(nullptr, session_mac_linkinfo_get(&a_stream));
}

TEST(TSGBridge, NatC2sLinkinfoAsync)
{
	const struct streaminfo a_stream = {0};
	char linkinfo[10];
	linkinfo[0] = 0x02;
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_NAT_C2S_LINKINFO].id, (void *)linkinfo);
	char *test = (char *)session_nat_c2s_linkinfo_get(&a_stream);
	EXPECT_EQ(test[0], 0x02);
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_NAT_C2S_LINKINFO].id, NULL);
	EXPECT_EQ(nullptr, session_nat_c2s_linkinfo_get(&a_stream));
}

TEST(TSGBridge, NatS2cLinkinfoAsync)
{
	const struct streaminfo a_stream = {0};
	char linkinfo[10];
	linkinfo[0] = 0x03;
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_NAT_S2C_LINKINFO].id, (void *)linkinfo);
	char *test = (char *)session_nat_s2c_linkinfo_get(&a_stream);
	EXPECT_EQ(test[0], 0x03);
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_NAT_S2C_LINKINFO].id, NULL);
	EXPECT_EQ(nullptr, session_nat_s2c_linkinfo_get(&a_stream));
}

TEST(TSGBridge, AppLuaResultAsync)
{
	const struct streaminfo a_stream = {0};
	struct user_defined_attribute uda_label = {0};
	uda_label.n_akv = 4;
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_APP_LUA_RESULT].id, (void *)&uda_label);
	struct user_defined_attribute *test = (struct user_defined_attribute *)session_lua_user_defined_attribute_get(&a_stream);
	EXPECT_EQ(test->n_akv, 4);
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_APP_LUA_RESULT].id, NULL);
	EXPECT_EQ(nullptr, session_lua_user_defined_attribute_get(&a_stream));
}

TEST(TSGBridge, BusinessS3FilenameAsync)
{
	const struct streaminfo a_stream = {0};
	struct business_notify_data bnd_label;
	memset(&bnd_label, 0, sizeof(struct business_notify_data));
	bnd_label.proto = PROTO_HTTP;
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_BUSINESS_S3_FILENAME].id, (void *)&bnd_label);
	struct business_notify_data *test = (struct business_notify_data *)session_business_data_get(&a_stream);
	EXPECT_EQ(test->proto, PROTO_HTTP);
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_BUSINESS_S3_FILENAME].id, NULL);
	EXPECT_EQ(nullptr, session_business_data_get(&a_stream));
}

TEST(TSGBridge, AppBehaviorResultAsync)
{
	const struct streaminfo a_stream = {0};
	char stream_behavior[10];
	struct application_behavior behavior_result = {0};
	behavior_result.stream_behavior = stream_behavior;
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_APP_BEHAVIOR_RESULT].id, (void *)&behavior_result);
	struct application_behavior *test = (struct application_behavior *)session_application_behavior_get(&a_stream);
	EXPECT_EQ(test->stream_behavior, stream_behavior);
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_APP_BEHAVIOR_RESULT].id, NULL);
	EXPECT_EQ(nullptr, session_application_behavior_get(&a_stream));
}

TEST(TSGBridge, PolicyActionParaExecResultAsync)
{
	const struct streaminfo a_stream = {0};
	struct tsg_notify_execution_result execution_result = {0};
	execution_result.capture_result_cnt = 20;
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_POLICY_ACTION_PARA_EXEC_RESULT].id, (void *)&execution_result);
	struct tsg_notify_execution_result *test = (struct tsg_notify_execution_result *)session_mirrored_and_capture_packets_exec_result_get(&a_stream);
	EXPECT_EQ(test->capture_result_cnt, 20);
	stream_bridge_async_data_put(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_POLICY_ACTION_PARA_EXEC_RESULT].id, NULL);
	EXPECT_EQ(nullptr, session_mirrored_and_capture_packets_exec_result_get(&a_stream));
}

TEST(TSGBridge, SegmentIdsAsync)
{
	const struct streaminfo a_stream = {0};
	struct segment_id_list segment_ids = {0};
	segment_ids.sz_sidlist = 4;
	session_control_segment_ids_async(&a_stream, (void *)&segment_ids);
	struct segment_id_list *test = (struct segment_id_list *)session_control_segment_ids_get(&a_stream);
	EXPECT_EQ(test->sz_sidlist, 4);
	session_control_segment_ids_async(&a_stream, NULL);
	EXPECT_EQ(nullptr, session_control_segment_ids_get(&a_stream));
}

static void tsg_bridge_test_init_proxy(const struct streaminfo *a_stream, struct proxy_log_update *proxy)
{
	proxy->ssl_cert_verify = 5;
	proxy->ssl_error = (char *)dictator_malloc(a_stream->threadnum, sizeof("thisisssl_error") + 1);
	memset(proxy->ssl_error, 0, strlen("thisisssl_error") + 1);
	memcpy(proxy->ssl_error, "thisisssl_error", strlen("thisisssl_error"));

	proxy->ssl_passthrough_reason = (char *)dictator_malloc(a_stream->threadnum, sizeof("thisisssl_passthrough_reason") + 1);
	memset(proxy->ssl_passthrough_reason, 0, strlen("thisisssl_passthrough_reason") + 1);
	memcpy(proxy->ssl_passthrough_reason, "thisisssl_passthrough_reason", strlen("thisisssl_passthrough_reason"));

	proxy->ssl_downstream_version = (char *)dictator_malloc(a_stream->threadnum, sizeof("thisisssl_downstream_version") + 1);
	memset(proxy->ssl_downstream_version, 0, strlen("thisisssl_downstream_version") + 1);
	memcpy(proxy->ssl_downstream_version, "thisisssl_downstream_version", strlen("thisisssl_downstream_version"));

	proxy->ssl_upstream_version = (char *)dictator_malloc(a_stream->threadnum, sizeof("thisisssl_upstream_version") + 1);
	memset(proxy->ssl_upstream_version, 0, strlen("thisisssl_upstream_version") + 1);
	memcpy(proxy->ssl_upstream_version, "thisisssl_upstream_version", strlen("thisisssl_upstream_version"));
}
extern void session_proxy_log_update_free(const struct streaminfo *a_stream, int bridge_id, void *data);
TEST(TSGBridge, LogUpdateProxyAsync)
{
	const struct streaminfo a_stream = {0};
	struct proxy_log_update *proxy = (struct proxy_log_update *)dictator_malloc(a_stream.threadnum, sizeof(struct proxy_log_update));
	tsg_bridge_test_init_proxy(&a_stream, proxy);
	session_log_update_data_put(&a_stream, TSG_SERVICE_INTERCEPT, (void *)proxy);
	struct proxy_log_update *test = (struct proxy_log_update *)session_log_update_data_get(&a_stream, TSG_SERVICE_INTERCEPT);
	EXPECT_EQ(test->ssl_cert_verify, 5);
	EXPECT_STREQ(test->ssl_error, "thisisssl_error");
	EXPECT_STREQ(test->ssl_passthrough_reason, "thisisssl_passthrough_reason");
	EXPECT_STREQ(test->ssl_downstream_version, "thisisssl_downstream_version");
	EXPECT_STREQ(test->ssl_upstream_version, "thisisssl_upstream_version");
	session_proxy_log_update_free(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_LOG_UPDATE_PROXY].id, test);
	session_log_update_data_put(&a_stream, TSG_SERVICE_INTERCEPT, NULL);
	EXPECT_EQ(nullptr, session_log_update_data_get(&a_stream, TSG_SERVICE_INTERCEPT));
}

TEST(TSGBridge, LogUpdateSceAsync)
{
	const struct streaminfo a_stream = {0};
	struct sce_log_update sce = {0};
	sce.n_profile_ids = 6;
	session_log_update_data_put(&a_stream, TSG_SERVICE_CHAINING, (void *)&sce);
	struct sce_log_update *test = (struct sce_log_update *)session_log_update_data_get(&a_stream, TSG_SERVICE_CHAINING);
	EXPECT_EQ(test->n_profile_ids, 6);
	session_log_update_data_put(&a_stream, TSG_SERVICE_CHAINING, NULL);
	EXPECT_EQ(nullptr, session_log_update_data_get(&a_stream, TSG_SERVICE_CHAINING));
}

TEST(TSGBridge, LogUpdateShaperAsync)
{
	const struct streaminfo a_stream = {0};
	struct shaper_log_update shaper = {0};
	shaper.n_shaper_rule = 7;
	session_log_update_data_put(&a_stream, TSG_SERVICE_SHAPING, (void *)&shaper);
	struct shaper_log_update *test = (struct shaper_log_update *)session_log_update_data_get(&a_stream, TSG_SERVICE_SHAPING);
	EXPECT_EQ(test->n_shaper_rule, 7);
	session_log_update_data_put(&a_stream, TSG_SERVICE_SHAPING, NULL);
	EXPECT_EQ(nullptr, session_log_update_data_get(&a_stream, TSG_SERVICE_SHAPING));
}


TEST(TSGBridge, SessionSessionRuntimeProcessContext)
{

}

TEST(TSGBridge, SessionSessionRuntimeActionContext)
{

}

extern int session_async_bridge_set_data(const struct streaminfo * a_stream, int bridge_id, void * data);
extern void session_runtime_attribute_free(const struct streaminfo * a_stream, int bridge_id, void * data);

TEST(TSGBridge, SessionSessionRuntimeAttributeTSG15457)
{
	const struct streaminfo a_stream = {0};
	struct session_runtime_attribute *srt_attribute = (struct session_runtime_attribute *)session_runtime_attribute_new(&a_stream);

	srt_attribute->proto=PROTO_SSL;
	int length=strlen("30625db44eaf886e65bebc8d1e62f368");
	srt_attribute->ja3_fingerprint=(const char *)dictator_malloc(0, length+1);
	memset((char *)srt_attribute->ja3_fingerprint, 0, length+1);
	memcpy((void *)srt_attribute->ja3_fingerprint, (const void *)"30625db44eaf886e65bebc8d1e62f368", length);

	srt_attribute->n_fqdn_category_ids=8;

	for(size_t i=0; i<srt_attribute->n_fqdn_category_ids; i++)
	{
		srt_attribute->fqdn_category_ids[i]=10000+i;
	}

	srt_attribute->client_asn=(struct asn_info *)dictator_malloc(0, sizeof(struct asn_info));
	srt_attribute->client_asn->ref_cnt=1;
	srt_attribute->client_asn->asn_id=(char *)"1003";
	srt_attribute->client_asn->organization=(char *)"china";

	srt_attribute->server_asn=(struct asn_info *)dictator_malloc(0, sizeof(struct asn_info));
	srt_attribute->server_asn->ref_cnt=1;
	srt_attribute->server_asn->asn_id=(char *)"1004";
	srt_attribute->server_asn->organization=(char *)"china";

	srt_attribute->client_location=(struct location_info *)dictator_malloc(0, sizeof(struct location_info));
	srt_attribute->client_location->ref_cnt=1;
	srt_attribute->client_location->country_full=(char *)"china";
	srt_attribute->client_location->province_full=(char *)"beijing";
	srt_attribute->client_location->city_full=(char *)"west";
	srt_attribute->client_location->subdivision_addr=(char *)"yuming road";
	
	srt_attribute->server_location=(struct location_info *)dictator_malloc(0, sizeof(struct location_info));
	srt_attribute->server_location->ref_cnt=1;
	srt_attribute->server_location->country_full=(char *)"china";
	srt_attribute->server_location->province_full=(char *)"shanghai";
	srt_attribute->server_location->city_full=(char *)"east";
	srt_attribute->server_location->subdivision_addr=(char *)"zhongshan road";

	srt_attribute->client_subscribe_id=(struct subscribe_id_info *)dictator_malloc(0, sizeof(struct subscribe_id_info));
	srt_attribute->client_subscribe_id->ref_cnt=1;
	srt_attribute->client_subscribe_id->subscribe_id=(char *)"zhansan";
	
	srt_attribute->server_subscribe_id=(struct subscribe_id_info *)dictator_malloc(0, sizeof(struct subscribe_id_info));
	srt_attribute->server_subscribe_id->ref_cnt=1;
	srt_attribute->server_subscribe_id->subscribe_id=(char *)"lisi";

	srt_attribute->client_endpoint=(struct tunnel_endpoint *)dictator_malloc(0, sizeof(struct tunnel_endpoint));
	srt_attribute->client_endpoint->id=1005;
	srt_attribute->client_endpoint->ref_cnt=1;
	srt_attribute->client_endpoint->description=(char *)"GTP";

	srt_attribute->server_endpoint=(struct tunnel_endpoint *)dictator_malloc(0, sizeof(struct tunnel_endpoint));
	srt_attribute->server_endpoint->id=1006;
	srt_attribute->server_endpoint->ref_cnt=1;
	srt_attribute->server_endpoint->description=(char *)"GTP";

	srt_attribute->user_info=(struct umts_user_info *)dictator_malloc(0, sizeof(struct umts_user_info));
	srt_attribute->user_info->ref_cnt=1;
	srt_attribute->user_info->apn=(char *)"apn.beijing.net";
	srt_attribute->user_info->imsi=(char *)"IMSI=123456";
	srt_attribute->user_info->imei=(char *)"IMEI=7890";
	srt_attribute->user_info->msisdn=(char *)"13500912083";

	struct session_runtime_attribute *srt_attribute_out=(struct session_runtime_attribute *)session_runtime_attribute_get(&a_stream);
	EXPECT_NE(nullptr, srt_attribute_out);

	EXPECT_EQ(PROTO_SSL, srt_attribute_out->proto);

	EXPECT_EQ(8, srt_attribute_out->n_fqdn_category_ids);
	for(size_t i=0; i<srt_attribute_out->n_fqdn_category_ids; i++)
	{
		EXPECT_EQ(10000+i, srt_attribute_out->fqdn_category_ids[i]);
	}

	unsigned int fqdn_category_ids[MAX_CATEGORY_ID_NUM]={0};
	size_t n_fqdn_category_ids=srt_attribute_get_category_ids((const struct session_runtime_attribute *)srt_attribute, fqdn_category_ids, MAX_CATEGORY_ID_NUM);
	EXPECT_EQ(8, n_fqdn_category_ids);
	for(size_t i=0; i<n_fqdn_category_ids; i++)
	{
		EXPECT_EQ(10000+i, fqdn_category_ids[i]);
	}

	EXPECT_STREQ("30625db44eaf886e65bebc8d1e62f368", srt_attribute_out->ja3_fingerprint);
	EXPECT_STREQ("30625db44eaf886e65bebc8d1e62f368", srt_attribute_get_ja3_fingerprint(srt_attribute_out));

	EXPECT_NE(nullptr, srt_attribute_out->client_endpoint);
	EXPECT_EQ(1, srt_attribute_out->client_endpoint->ref_cnt);
	EXPECT_EQ(1005, srt_attribute_out->client_endpoint->id);
	EXPECT_STREQ("GTP", srt_attribute_out->client_endpoint->description);

	EXPECT_NE(nullptr, srt_attribute_out->server_endpoint);
	EXPECT_EQ(1, srt_attribute_out->server_endpoint->ref_cnt);
	EXPECT_EQ(1006, srt_attribute_out->server_endpoint->id);
	EXPECT_STREQ("GTP", srt_attribute_out->server_endpoint->description);

	EXPECT_NE(nullptr, srt_attribute_out->user_info);
	EXPECT_EQ(1, srt_attribute_out->user_info->ref_cnt);
	EXPECT_STREQ("apn.beijing.net", srt_attribute_out->user_info->apn);
	EXPECT_STREQ("IMSI=123456", srt_attribute_out->user_info->imsi);
	EXPECT_STREQ("IMEI=7890", srt_attribute_out->user_info->imei);
	EXPECT_STREQ("13500912083", srt_attribute_out->user_info->msisdn);

	EXPECT_NE(nullptr, srt_attribute_out->client_asn);
	EXPECT_EQ(1, srt_attribute_out->client_asn->ref_cnt);
	EXPECT_STREQ("1003", srt_attribute_out->client_asn->asn_id);
	EXPECT_STREQ("china", srt_attribute_out->client_asn->organization);

	const struct asn_info * c_asn=srt_attribute_get_client_ip_asn((const struct session_runtime_attribute *)srt_attribute_out);
	EXPECT_NE(nullptr, c_asn);
	EXPECT_EQ(1, c_asn->ref_cnt);
	EXPECT_STREQ("1003", c_asn->asn_id);
	EXPECT_STREQ("china", c_asn->organization);

	EXPECT_NE(nullptr, srt_attribute_out->server_asn);
	EXPECT_EQ(1, srt_attribute_out->server_asn->ref_cnt);
	EXPECT_STREQ("1004", srt_attribute_out->server_asn->asn_id);
	EXPECT_STREQ("china", srt_attribute_out->server_asn->organization);

	const struct asn_info * s_asn=srt_attribute_get_server_ip_asn((const struct session_runtime_attribute *)srt_attribute_out);
	EXPECT_NE(nullptr, s_asn);
	EXPECT_EQ(1, s_asn->ref_cnt);
	EXPECT_STREQ("1004", s_asn->asn_id);
	EXPECT_STREQ("china", s_asn->organization);

	EXPECT_NE(nullptr, srt_attribute_out->client_location);
	EXPECT_EQ(1, srt_attribute_out->client_location->ref_cnt);
	EXPECT_STREQ("china", srt_attribute_out->client_location->country_full);
	EXPECT_STREQ("beijing", srt_attribute_out->client_location->province_full);
	EXPECT_STREQ("west", srt_attribute_out->client_location->city_full);
	EXPECT_STREQ("yuming road", srt_attribute_out->client_location->subdivision_addr);

	const struct location_info *c_location=srt_attribute_get_client_ip_location((const struct session_runtime_attribute *)srt_attribute_out);
	EXPECT_NE(nullptr, c_location);
	EXPECT_EQ(1, c_location->ref_cnt);
	EXPECT_STREQ("china", c_location->country_full);
	EXPECT_STREQ("beijing", c_location->province_full);
	EXPECT_STREQ("west", c_location->city_full);
	EXPECT_STREQ("yuming road", c_location->subdivision_addr);

	EXPECT_NE(nullptr, srt_attribute_out->server_location);
	EXPECT_EQ(1, srt_attribute_out->server_location->ref_cnt);
	EXPECT_STREQ("china", srt_attribute_out->server_location->country_full);
	EXPECT_STREQ("shanghai", srt_attribute_out->server_location->province_full);
	EXPECT_STREQ("east", srt_attribute_out->server_location->city_full);
	EXPECT_STREQ("zhongshan road", srt_attribute_out->server_location->subdivision_addr);

	const struct location_info *s_location=srt_attribute_get_server_ip_location((const struct session_runtime_attribute *)srt_attribute_out);
	EXPECT_NE(nullptr, s_location);
	EXPECT_EQ(1, s_location->ref_cnt);
	EXPECT_STREQ("china", s_location->country_full);
	EXPECT_STREQ("shanghai", s_location->province_full);
	EXPECT_STREQ("east", s_location->city_full);
	EXPECT_STREQ("zhongshan road", s_location->subdivision_addr);

	EXPECT_NE(nullptr, srt_attribute_out->client_subscribe_id);
	EXPECT_EQ(1, srt_attribute_out->client_subscribe_id->ref_cnt);
	EXPECT_STREQ("zhansan", srt_attribute_out->client_subscribe_id->subscribe_id);
	EXPECT_STREQ("zhansan", srt_attribute_get_client_subscriber_id((const struct session_runtime_attribute *)srt_attribute_out));

	EXPECT_NE(nullptr, srt_attribute_out->server_subscribe_id);
	EXPECT_EQ(1, srt_attribute_out->server_subscribe_id->ref_cnt);
	EXPECT_STREQ("lisi", srt_attribute_out->server_subscribe_id->subscribe_id);
	EXPECT_STREQ("lisi", srt_attribute_get_server_subscriber_id((const struct session_runtime_attribute *)srt_attribute_out));

	session_runtime_attribute_free(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_SESSION_ATTRIBUTE].id, (void *)srt_attribute_out);
	session_async_bridge_set_data(&a_stream, g_tsg_bridge_para[BRIDGE_TYPE_SESSION_ATTRIBUTE].id, NULL);
	EXPECT_EQ(nullptr, session_runtime_attribute_get(&a_stream));
}

TEST(TSGBridge, SessionSessionRuntimeAttributeSubscriberIDTSG15568)
{
	const struct streaminfo a_stream = {0};
	struct session_runtime_attribute *srt_attribute = (struct session_runtime_attribute *)session_runtime_attribute_new(&a_stream);

	srt_attribute->client_subscribe_id=(struct subscribe_id_info *)dictator_malloc(0, sizeof(struct subscribe_id_info));
	srt_attribute->client_subscribe_id->ref_cnt=1;
	srt_attribute->client_subscribe_id->subscribe_id=(char *)"zhansan";

	struct session_runtime_attribute *srt_attribute_out=(struct session_runtime_attribute *)session_runtime_attribute_get(&a_stream);
	EXPECT_NE(nullptr, srt_attribute_out);

	EXPECT_NE(nullptr, srt_attribute_out->client_subscribe_id);
	EXPECT_EQ(1, srt_attribute_out->client_subscribe_id->ref_cnt);
	EXPECT_STREQ("zhansan", srt_attribute_out->client_subscribe_id->subscribe_id);
	EXPECT_STREQ("zhansan", srt_attribute_get_client_subscriber_id((const struct session_runtime_attribute *)srt_attribute_out));

	EXPECT_EQ(nullptr, srt_attribute_out->server_subscribe_id);
	EXPECT_EQ(nullptr, srt_attribute_get_server_subscriber_id((const struct session_runtime_attribute *)srt_attribute_out));
}

int main(int argc, char *argv[])
{
	int ret=tsg_bridge_init("tsgconf/main.conf");
	if(ret<0)
	{
		return -1;
	}
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

