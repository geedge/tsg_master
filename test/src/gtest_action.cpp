#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "tsg_rule.h"
#include "tsg_label.h"
#include "tsg_entry.h"
#include "tsg_variable.h"
#include "tsg_rule_internal.h"
#include "tsg_protocol_common.h"

#include <gtest/gtest.h>

struct maat *g_tsg_maat_feather;

const struct session_runtime_attribute *session_runtime_attribute_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *matched_rule_cites_http_response_pages(struct maat *feather, long long profile_id)
{
	return NULL;
}

void plugin_ex_data_http_response_pages_free(struct http_response_pages * response_pages)
{
}

void *matched_rule_cites_app_id_dict(struct maat *feather, long long app_id)
{
	return NULL;
}

void plugin_ex_data_app_id_dict_free(struct app_id_dict * dict)
{
}

void *matched_rule_cites_security_compile(struct maat *feather, long long profile_id)
{
	return NULL;
}

void plugin_ex_data_security_compile_free(struct maat_compile * maat_compile)
{
}

void *matched_rule_cites_dns_profile_record(struct maat *feather, long long profile_id)
{
	return NULL;
}

void plugin_ex_data_dns_profile_record_free(struct dns_profile_records * records)
{
}

int session_runtime_action_context_async(const struct streaminfo * a_stream, void * data)
{
	return 0;
}

int srt_attribute_set_reponse_size(const struct streaminfo * a_stream, int http_action_file_size)
{
	return 0;
}

int srt_action_context_set_leaky_bucket(const struct streaminfo * a_stream, struct leaky_bucket * bucket, int thread_seq)
{
	return 0;
}

int srt_action_context_set_l7_protocol(const struct streaminfo * a_stream, enum TSG_PROTOCOL protocol, int thread_seq)
{
	return 0;
}

int srt_action_context_set_rule_method(const struct streaminfo * a_stream, enum TSG_METHOD_TYPE method_type, int thread_seq)
{
	return 0;
}

int srt_action_context_set_after_n_packet(const struct streaminfo * a_stream, int after_n_packets, int thread_seq)
{
	return 0;
}

const struct session_runtime_action_context *session_runtime_action_context_get(const struct streaminfo *a_stream)
{
	return NULL;
}

int tsg_set_statistic_opt(int value, enum _STATISTIC_OPT_TYPE type, int thread_seq)
{
	return 0;
}

int session_packet_capture_by_rules_notify(const struct streaminfo * a_stream, struct maat_rule *rules, size_t n_rules, int thread_seq)
{
	return 0;
}

TEST(TM_ACTION, Http)
{
	EXPECT_EQ(1, 1);
}

int main(int argc, char *argv[])
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
