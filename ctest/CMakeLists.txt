cmake_minimum_required (VERSION 2.8)

project(sapp_ctest)

add_test(NAME COPY_CREATE_DIR COMMAND sh -c "mkdir -p ${CMAKE_BINARY_DIR}/testing/tsgconf/ ")
add_test(NAME COPY_GTEST_MAIN_CONF COMMAND sh -c "cp -r ${CMAKE_SOURCE_DIR}/bin/main.conf ${CMAKE_BINARY_DIR}/testing/tsgconf/")
add_test(NAME COPY_GTEST_MAAT_CONF COMMAND sh -c "cp -r ${CMAKE_SOURCE_DIR}/bin/maat.conf ${CMAKE_BINARY_DIR}/testing/tsgconf/")
add_test(NAME COPY_GTEST_LOG_CONF COMMAND sh -c "cp -r ${CMAKE_SOURCE_DIR}/bin/tsg_log_field.conf ${CMAKE_BINARY_DIR}/testing/tsgconf/")
add_test(NAME COPY_GTEST_PROTO_CONF COMMAND sh -c "cp -r ${CMAKE_SOURCE_DIR}/bin/tsg_l7_protocol.conf ${CMAKE_BINARY_DIR}/testing/tsgconf/")
add_test(NAME COPY_GTEST_TABLEINFO COMMAND sh -c "cp -r ${CMAKE_SOURCE_DIR}/bin/tsg_static_tableinfo.json ${CMAKE_BINARY_DIR}/testing/tsgconf/")
add_test(NAME COPY_GTEST_MAAT_RULE COMMAND sh -c "cp -r ${CMAKE_SOURCE_DIR}/test/bin/gtest_maat.json ${CMAKE_BINARY_DIR}/testing/tsgconf/tsg_maat.json")
add_test(NAME COPY_GTEST_PROFILE_RESPONSE_PAGES COMMAND sh -c "cp -r ${CMAKE_SOURCE_DIR}/test/bin/foreign_files ${CMAKE_BINARY_DIR}/testing/")

add_test(NAME COPY_GTEST_RULE_BIN COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/test/src/gtest_rule ${CMAKE_BINARY_DIR}/testing/")
add_test(NAME COPY_GTEST_BRIDGE_BIN COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/test/src/gtest_bridge ${CMAKE_BINARY_DIR}/testing/")
add_test(NAME COPY_GTEST_ACTION_BIN COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/test/src/gtest_action ${CMAKE_BINARY_DIR}/testing/")
add_test(NAME COPY_GTEST_SENDLOG_BIN COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/test/src/gtest_sendlog ${CMAKE_BINARY_DIR}/testing/")
add_test(NAME COPY_GTEST_MASTER_BIN COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/test/src/gtest_master ${CMAKE_BINARY_DIR}/testing/")
add_test(NAME COPY_GTEST_SYNC_SESSION_STATE_BIN COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/test/src/gtest_sync_session_state ${CMAKE_BINARY_DIR}/testing/")

set(GTEST_RUN_DIR ${CMAKE_BINARY_DIR}/testing)
add_test(NAME GTEST_RULE COMMAND gtest_rule WORKING_DIRECTORY ${GTEST_RUN_DIR})
add_test(NAME GTEST_BRIDGE COMMAND gtest_bridge WORKING_DIRECTORY ${GTEST_RUN_DIR})
add_test(NAME GTEST_ACTION COMMAND gtest_action WORKING_DIRECTORY ${GTEST_RUN_DIR})
add_test(NAME GTEST_SENDLOG COMMAND gtest_sendlog WORKING_DIRECTORY ${GTEST_RUN_DIR})
add_test(NAME GTEST_MASTER COMMAND gtest_master WORKING_DIRECTORY ${GTEST_RUN_DIR})
add_test(NAME GTEST_SYNC_SESSION_STATE COMMAND gtest_sync_session_state WORKING_DIRECTORY ${GTEST_RUN_DIR})

