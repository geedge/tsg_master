#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <MESA/fieldstat.h>

#include "tsg_entry.h"
#include "gtest_common.h"
#include "tsg_variable.h"
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include <gtest/gtest.h>

const char *tsg_gtest_conffile = "tsgconf/main.conf";
extern struct tsg_statistic g_tsg_statis_para;
pthread_t g_pid[8];

TEST(FIELDSATA3, InterceptIllegalParameter)
{
    struct traffic_info _info;
    struct maat_rule p_result;

    int ret = tsg_set_intercept_flow(NULL, &_info, 0);
    EXPECT_EQ(ret, -1);

    ret = tsg_set_intercept_flow(&p_result, NULL, 0);
    EXPECT_EQ(ret, -1);

    ret = tsg_set_intercept_flow(&p_result, &_info, -1);
    EXPECT_EQ(ret, -1);
}

TEST(FIELDSATA3, PolicyIllegalParameter)
{
    struct maat_rule p_result;
    struct streaminfo a_stream;

    int ret = tsg_set_policy_flow(NULL, &p_result, 0);
    EXPECT_EQ(ret, -1);

    ret = tsg_set_policy_flow(&a_stream, NULL, 0);
    EXPECT_EQ(ret, -1);

    ret = tsg_set_policy_flow(&a_stream, &p_result, -1);
    EXPECT_EQ(ret, -1);
}

TEST(FIELDSATA3, Intercept)
{
    struct traffic_info _info;
    struct maat_rule p_result;

    _info.con_num = 10;
    _info.in_bytes = 1000;
    _info.in_packets = 25;
    _info.out_bytes = 1001;
    _info.out_packets = 24;

    p_result.action = TSG_ACTION_INTERCEPT;
    p_result.rule_id = 95536;
    p_result.do_log = 1;
    p_result.service_id = TSG_SERVICE_INTERCEPT;

    for (int i = 0; i < 50000; i++)
    {
        // p_result.rule_id += i;
        // _info.in_bytes += i;
        int ret = tsg_set_intercept_flow(&p_result, &_info, 0);
        EXPECT_EQ(ret, 0);
        // usleep(500);
    }
}

TEST(FIELDSATA3, PolicyFlow)
{
    struct maat_rule  p_result;
    struct streaminfo a_stream;

    p_result.action = TSG_ACTION_MONITOR;
    p_result.rule_id = 95500;
	p_result.service_id=TSG_SERVICE_SECURITY;

    for (int i = 0; i < 50000; i++)
    {
        // p_result.rule_id += i;
        // _info.in_bytes += i;
        int ret = tsg_set_policy_flow(&a_stream, &p_result, 0);
        EXPECT_EQ(ret, 0);
        // usleep(500);
    }
}

#if 0
void *run_time_funtion(void *arg)
{
    uint8_t pid = *(uint8_t *)arg;

    struct maat_rule p_result;
    struct streaminfo a_stream;
    struct traffic_info _info;

    while (1)
    {
        srand(time(NULL));
        p_result.action = TSG_ACTION_MONITOR;
        p_result.rule_id = rand() % 95500;

        usleep(rand() % 500);
        int ret = tsg_set_policy_flow(&a_stream, &p_result, pid);
        EXPECT_EQ(ret, 0);

        srand(time(NULL));
        usleep(rand() % 500);

        p_result.action = TSG_ACTION_DENY;
        p_result.rule_id = rand() % 95500;
        ret = tsg_set_policy_flow(&a_stream, &p_result, pid);
        EXPECT_EQ(ret, 0);

        srand(time(NULL));
        usleep(rand() % 500);

        p_result.action = TSG_ACTION_BYPASS;
        p_result.rule_id = rand() % 95500;
        ret = tsg_set_policy_flow(&a_stream, &p_result, pid);
        EXPECT_EQ(ret, 0);

        _info.con_num = rand() % 10;
        _info.in_bytes = rand() % 1000;
        _info.in_packets = rand() % 25;
        _info.out_bytes = rand() % 1001;
        _info.out_packets = rand() % 24;

        p_result.action = TSG_ACTION_INTERCEPT;
        p_result.rule_id = rand() % 95536;

        ret = tsg_set_intercept_flow(&p_result, &_info, pid);
        EXPECT_EQ(ret, 0);
    }

    return NULL;
}

TEST(FIELDSATA3, MultiThreading)
{
    for (uint8_t i = 0; i < 8; i++)
    {
        uint8_t i_pid = i;
        pthread_create(g_pid + i, NULL, run_time_funtion, (void *)&i_pid);
        EXPECT_NE(g_pid[i], 0);
    }
}
#endif

int main(int argc, char *argv[])
{
    void *logger = MESA_create_runtime_log_handle("log/gtest_fieldstat3.log", RLOG_LV_FATAL);
    tsg_metric_init(tsg_gtest_conffile, logger);
    testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
//    sleep(30);
//    for (int i = 0; i < 8; i++)
//    {
//        pthread_cancel(g_pid[i]);
//    }

    tsg_metric_destroy();

    return ret;
}
