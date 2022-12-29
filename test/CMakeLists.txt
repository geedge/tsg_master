cmake_minimum_required(VERSION 2.8)


include_directories(${CMAKE_SOURCE_DIR}/inc)
include_directories(/opt/MESA/include/MESA/)
include_directories(/opt/MESA/include)
include_directories(/usr/include/)

set(CMAKE_INSTALL_PREFIX /home/mesasoft/sapp_run)

add_library(tsg_master_gtest SHARED src/tsg_master_gtest_protocol.cpp src/tsg_master_gtest_entry.cpp)
set_target_properties(tsg_master_gtest  PROPERTIES PREFIX "")

add_definitions(-std=c++11)
LINK_DIRECTORIES(/opt/MESA/lib)

add_executable(master_gtest "src/tsg_master_gtest_main.cpp")
target_compile_options(master_gtest PUBLIC ${MEM_POOL_DEFINITIONS})
target_link_libraries(master_gtest pthread dl m pcap systemd cjson MESA_prof_load MESA_htable MESA_handle_logger MESA_jump_layer breakpad_mini MESA_field_stat2)
target_link_libraries(master_gtest /home/mesasoft/sapp_run/lib/libsapp_devel.so)
target_link_libraries(master_gtest gtest-static ctemplate-static)

install(TARGETS master_gtest DESTINATION ${CMAKE_INSTALL_PREFIX}/ COMPONENT EXECUTABLE)


