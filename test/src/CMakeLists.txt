cmake_minimum_required(VERSION 2.8...3.10)

include_directories(${CMAKE_SOURCE_DIR}/inc)
include_directories(/opt/MESA/include/MESA/)
include_directories(/opt/MESA/include)
include_directories(/usr/include/)
include_directories(${PROJECT_SOURCE_DIR}/src/)

add_definitions(-std=c++11)
LINK_DIRECTORIES(/opt/MESA/lib)

add_executable(gtest_rule ${PROJECT_SOURCE_DIR}/src/tsg_rule.cpp ${PROJECT_SOURCE_DIR}/src/tsg_variable.cpp ${PROJECT_SOURCE_DIR}/src/tsg_stat.cpp gtest_common.cpp gtest_rule.cpp)
target_link_libraries(gtest_rule gtest-static ctemplate-static cjson MESA_prof_load MESA_handle_logger maat4 fieldstat3)


add_executable(gtest_tableinfo ${PROJECT_SOURCE_DIR}/src/tsg_rule.cpp ${PROJECT_SOURCE_DIR}/src/tsg_variable.cpp ${PROJECT_SOURCE_DIR}/src/tsg_stat.cpp gtest_common.cpp gtest_tableinfo.cpp)
target_link_libraries(gtest_tableinfo gtest-static ctemplate-static cjson MESA_prof_load MESA_handle_logger maat4 fieldstat3)

add_executable(gtest_bridge ${PROJECT_SOURCE_DIR}/src/tsg_bridge.cpp ${PROJECT_SOURCE_DIR}/src/tsg_variable.cpp ${PROJECT_SOURCE_DIR}/src/tsg_stat.cpp gtest_common.cpp gtest_bridge.cpp)
target_link_libraries(gtest_bridge gtest-static ctemplate-static cjson MESA_prof_load MESA_handle_logger maat4 fieldstat3)

add_executable(gtest_action ${PROJECT_SOURCE_DIR}/src/tsg_action.cpp ${PROJECT_SOURCE_DIR}/src/tsg_leaky_bucket.cpp ${PROJECT_SOURCE_DIR}/src/tsg_dns.cpp ${PROJECT_SOURCE_DIR}/src/tsg_icmp.cpp ${PROJECT_SOURCE_DIR}/src/tsg_tamper.cpp ${PROJECT_SOURCE_DIR}/src/tsg_variable.cpp ${PROJECT_SOURCE_DIR}/src/tsg_stat.cpp gtest_common.cpp gtest_action.cpp)
target_link_libraries(gtest_action gtest-static ctemplate-static cjson MESA_prof_load MESA_handle_logger maat4 fieldstat3)

add_executable(gtest_sendlog ${PROJECT_SOURCE_DIR}/src/tsg_send_log.cpp ${PROJECT_SOURCE_DIR}/src/tsg_variable.cpp ${PROJECT_SOURCE_DIR}/src/tsg_stat.cpp gtest_common.cpp gtest_kafka.cpp gtest_sendlog.cpp)
target_link_libraries(gtest_sendlog gtest-static ctemplate-static cjson MESA_prof_load MESA_handle_logger maat4 rdkafka fieldstat3 ipfix_exporter)

set(TSG_MASTER_SRC ${PROJECT_SOURCE_DIR}/src/tsg_entry.cpp 
	${PROJECT_SOURCE_DIR}/src/tsg_rule.cpp 
	${PROJECT_SOURCE_DIR}/src/tsg_ssl_utils.cpp 
	${PROJECT_SOURCE_DIR}/src/tsg_send_log.cpp 
	${PROJECT_SOURCE_DIR}/src/tsg_statistic.cpp
	${PROJECT_SOURCE_DIR}/src/tsg_ssh_utils.cpp 
	${PROJECT_SOURCE_DIR}/src/tsg_gtp_signaling.cpp 
	${PROJECT_SOURCE_DIR}/src/tsg_action.cpp
	${PROJECT_SOURCE_DIR}/src/tsg_leaky_bucket.cpp 
	${PROJECT_SOURCE_DIR}/src/tsg_dns.cpp 
	${PROJECT_SOURCE_DIR}/src/tsg_icmp.cpp
	${PROJECT_SOURCE_DIR}/src/tsg_tamper.cpp
	${PROJECT_SOURCE_DIR}/src/tsg_bridge.cpp
	${PROJECT_SOURCE_DIR}/src/tsg_sync_state.cpp
	${PROJECT_SOURCE_DIR}/src/tsg_variable.cpp
	${PROJECT_SOURCE_DIR}/src/tsg_proxy.cpp
	${PROJECT_SOURCE_DIR}/src/mpack.c
	${PROJECT_SOURCE_DIR}/src/tsg_stat.cpp
	${PROJECT_SOURCE_DIR}/src/tsg_ssl_ja3_fingerprint.cpp
)

add_executable(gtest_master ${TSG_MASTER_SRC} gtest_kafka.cpp gtest_common.cpp gtest_master.cpp)
target_link_libraries(gtest_master gtest-static ctemplate-static cjson MESA_prof_load MESA_handle_logger MESA_jump_layer MESA_field_stat2 maat4 MESA_htable fieldstat3 crypto ipfix_exporter osfp)

add_executable(gtest_sync_state ${PROJECT_SOURCE_DIR}/src/tsg_sync_state.cpp ${PROJECT_SOURCE_DIR}/src/mpack.c ${PROJECT_SOURCE_DIR}/src/tsg_stat.cpp gtest_common.cpp gtest_sync_state.cpp)
target_link_libraries(gtest_sync_state gtest-static cjson ctemplate-static MESA_prof_load MESA_handle_logger fieldstat3)

add_executable(gtest_fieldstat3 ${TSG_MASTER_SRC} gtest_common.cpp gtest_kafka.cpp gtest_fieldstat3.cpp)
target_link_libraries(gtest_fieldstat3 gtest-static ctemplate-static cjson MESA_prof_load MESA_handle_logger MESA_jump_layer MESA_field_stat2 maat4 MESA_htable fieldstat3 crypto ipfix_exporter osfp)

add_executable(gtest_proxy ${TSG_MASTER_SRC} gtest_common.cpp gtest_proxy.cpp)
target_link_libraries(gtest_proxy gtest-static ctemplate-static cjson MESA_prof_load MESA_handle_logger MESA_jump_layer MESA_field_stat2 maat4 rdkafka MESA_htable fieldstat3 pcap crypto ipfix_exporter osfp)

file(COPY ../pcap/ DESTINATION ./pcap/)
