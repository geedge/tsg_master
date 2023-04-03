cmake_minimum_required(VERSION 2.8)

include_directories(${CMAKE_SOURCE_DIR}/inc)
include_directories(/opt/MESA/include/MESA/)
include_directories(/opt/MESA/include)
include_directories(/usr/include/)
include_directories(${PROJECT_SOURCE_DIR}/src/)

add_definitions(-std=c++11)
LINK_DIRECTORIES(/opt/MESA/lib)

add_executable(gtest_rule ${PROJECT_SOURCE_DIR}/src/tsg_rule.cpp ${PROJECT_SOURCE_DIR}/src/tsg_variable.cpp gtest_common.cpp gtest_rule.cpp)
target_link_libraries(gtest_rule gtest-static ctemplate-static cjson MESA_prof_load MESA_handle_logger maat4)

add_executable(gtest_bridge ${PROJECT_SOURCE_DIR}/src/tsg_bridge.cpp ${PROJECT_SOURCE_DIR}/src/tsg_protocol.cpp ${PROJECT_SOURCE_DIR}/src/tsg_variable.cpp gtest_common.cpp gtest_bridge.cpp)
target_link_libraries(gtest_bridge gtest-static ctemplate-static cjson MESA_prof_load MESA_handle_logger maat4)

add_executable(gtest_action ${PROJECT_SOURCE_DIR}/src/tsg_action.cpp ${PROJECT_SOURCE_DIR}/src/tsg_leaky_bucket.cpp ${PROJECT_SOURCE_DIR}/src/tsg_dns.cpp ${PROJECT_SOURCE_DIR}/src/tsg_icmp.cpp ${PROJECT_SOURCE_DIR}/src/tsg_tamper.cpp ${PROJECT_SOURCE_DIR}/src/tsg_variable.cpp gtest_common.cpp gtest_action.cpp)
target_link_libraries(gtest_action gtest-static ctemplate-static cjson MESA_prof_load MESA_handle_logger maat4 MESA_field_stat2)

add_executable(gtest_sendlog ${PROJECT_SOURCE_DIR}/src/tsg_send_log.cpp ${PROJECT_SOURCE_DIR}/src/tsg_variable.cpp gtest_common.cpp gtest_sendlog.cpp)
target_link_libraries(gtest_sendlog gtest-static ctemplate-static cjson MESA_prof_load MESA_handle_logger maat4 rdkafka MESA_field_stat2)

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
	${PROJECT_SOURCE_DIR}/src/tsg_protocol.cpp
)

add_executable(gtest_master ${TSG_MASTER_SRC} gtest_kafka.cpp gtest_common.cpp gtest_master.cpp)
target_link_libraries(gtest_master gtest-static ctemplate-static cjson MESA_prof_load MESA_handle_logger MESA_jump_layer MESA_field_stat2 maat4 MESA_htable)

add_executable(gtest_sync_session_state ${PROJECT_SOURCE_DIR}/src/tsg_sync_state.cpp gtest_common.cpp gtest_session_state.cpp)
target_link_libraries(gtest_sync_session_state gtest-static cjson ctemplate-static)
