cmake_minimum_required(VERSION 2.8)

add_definitions(-fPIC)

set(SRC tsg_entry.cpp tsg_rule.cpp tsg_ssl_utils.cpp tsg_send_log.cpp tsg_statistic.cpp tsg_ssh_utils.cpp tsg_gtp_signaling.cpp tsg_action.cpp tsg_leaky_bucket.cpp tsg_dns.cpp tsg_icmp.cpp tsg_tamper.cpp tsg_bridge.cpp tsg_protocol.cpp tsg_sync_state.cpp tsg_variable.cpp tsg_proxy.cpp mpack.c)

include_directories(${CMAKE_SOURCE_DIR}/inc)
include_directories(/opt/MESA/include/MESA/)
include_directories(/usr/include/)

set(TSG_MASTER_DEPEND_DYN_LIB  MESA_handle_logger MESA_prof_load maat4 pthread MESA_field_stat2 rdkafka cjson MESA_jump_layer fieldstat3)

set(CMAKE_INSTALL_PREFIX /home/mesasoft/sapp_run)

add_library(tsg_master SHARED ${SRC})
set_target_properties(tsg_master PROPERTIES LINK_FLAGS "-Wl,--version-script=${PROJECT_SOURCE_DIR}/src/version.map")
target_link_libraries(tsg_master ${TSG_MASTER_DEPEND_DYN_LIB} ctemplate-static)
set_target_properties(tsg_master  PROPERTIES PREFIX "")

install(TARGETS tsg_master LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/plug/platform/tsg_master COMPONENT LIBRARIES)
install(FILES ../bin/tsg_master.inf DESTINATION ${CMAKE_INSTALL_PREFIX}/plug/platform/tsg_master COMPONENT PROFILE)
