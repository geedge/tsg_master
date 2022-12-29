cmake_minimum_required(VERSION 2.8)

set(SRC ../src/tsg_entry.cpp ../src/tsg_rule.cpp ../src/tsg_ssl_utils.cpp ../src/tsg_send_log.cpp ../src/tsg_statistic.cpp ../src/tsg_ssh_utils.cpp ../src/tsg_gtp_signaling.cpp ../src/tsg_action.cpp ../src/tsg_leaky_bucket.cpp ../src/tsg_dns.cpp ../src/tsg_icmp.cpp ../src/tsg_tamper.cpp tsg_master_gtest_protocol.cpp tsg_master_gtest_entry.cpp)

include_directories(${CMAKE_SOURCE_DIR}/inc)
include_directories(/opt/MESA/include/MESA/)
include_directories(/opt/MESA/include)
include_directories(/usr/include/)

set(TSG_MASTER_DEPEND_DYN_LIB  MESA_handle_logger MESA_prof_load maatframe pthread MESA_field_stat2 rdkafka cjson MESA_jump_layer)

set(CMAKE_INSTALL_PREFIX /home/mesasoft/sapp_run)

add_library(tsg_master_gtest SHARED ${SRC})
set_target_properties(tsg_master_gtest PROPERTIES LINK_FLAGS "-Wl,--version-script=${PROJECT_SOURCE_DIR}/src/version.map")
target_link_libraries(tsg_master_gtest ${TSG_MASTER_DEPEND_DYN_LIB} ctemplate-static)
set_target_properties(tsg_master_gtest  PROPERTIES PREFIX "")

install(TARGETS tsg_master_gtest LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/plug/platform/tsg_master_gtest COMPONENT LIBRARIES)
install(FILES ../bin/tsg_master.inf DESTINATION ${CMAKE_INSTALL_PREFIX}/plug/platform/tsg_master_gtest COMPONENT PROFILE)


add_definitions(-std=c++11)
LINK_DIRECTORIES(/opt/MESA/lib)

file(GLOB TEST_CASE "tsg_master_gtest_main.cpp")

add_executable(master_gtest ${TEST_CASE})
target_compile_options(master_gtest PUBLIC ${MEM_POOL_DEFINITIONS})
target_link_libraries(master_gtest nsl pthread dl m pcap systemd cjson MESA_prof_load MESA_htable MESA_handle_logger MESA_jump_layer breakpad_mini MESA_field_stat2 rdkafka)
target_link_libraries(master_gtest /home/mesasoft/sapp_run/lib/libsapp_devel.so)
target_link_libraries(master_gtest gtest-static ctemplate-static)

install(TARGETS master_gtest DESTINATION ${CMAKE_INSTALL_PREFIX}/ COMPONENT EXECUTABLE)


