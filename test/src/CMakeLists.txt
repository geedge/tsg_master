cmake_minimum_required(VERSION 2.8)

include_directories(${CMAKE_SOURCE_DIR}/inc)
include_directories(/opt/MESA/include/MESA/)
include_directories(/opt/MESA/include)
include_directories(/usr/include/)
include_directories(${PROJECT_SOURCE_DIR}/src/)

add_definitions(-std=c++11)
LINK_DIRECTORIES(/opt/MESA/lib)

#add_executable(gtest_rule ${PROJECT_SOURCE_DIR}/src/tsg_rule.cpp ${PROJECT_SOURCE_DIR}/src/tsg_bridge.cpp ${PROJECT_SOURCE_DIR}/src/tsg_leaky_bucket.cpp gtest_common.cpp gtest_rule.cpp)
#target_link_libraries(gtest_rule gtest-static ctemplate-static cjson MESA_prof_load MESA_handle_logger MESA_jump_layer MESA_field_stat2 maatframe)

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
)

add_executable(gtest_master ${TSG_MASTER_SRC} gtest_kafka.cpp gtest_common.cpp gtest_master.cpp)
target_link_libraries(gtest_master gtest-static ctemplate-static cjson MESA_prof_load MESA_handle_logger MESA_jump_layer MESA_field_stat2 maatframe MESA_htable)
