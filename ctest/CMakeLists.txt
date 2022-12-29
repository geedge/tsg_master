cmake_minimum_required (VERSION 2.8)

project(sapp_ctest)

add_test(NAME COPY_CREATE_DIR COMMAND sh -c "mkdir -p ${CMAKE_BINARY_DIR}/testing/ ${CMAKE_BINARY_DIR}/testing/plug")
add_test(NAME COPY_MASTER_GTEST_BIN COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/test/master_gtest ${CMAKE_BINARY_DIR}/testing/")
add_test(NAME COPY_MASTER_GTEST_CONF COMMAND sh -c "cp -r ${CMAKE_SOURCE_DIR}/test/bin/etc/ ${CMAKE_BINARY_DIR}/testing/")
add_test(NAME COPY_MASTER_GTEST_CONFLIST COMMAND sh -c "cp -r ${CMAKE_SOURCE_DIR}/test/bin/conflist.inf ${CMAKE_BINARY_DIR}/testing/plug")


add_test(NAME COPY_MASTER_DIR COMMAND sh -c "mkdir -p ${CMAKE_BINARY_DIR}/testing/plug/platform/tsg_master/")
add_test(NAME COPY_MASTER_INF COMMAND sh -c "cp ${CMAKE_SOURCE_DIR}/bin/tsg_master.inf ${CMAKE_BINARY_DIR}/testing/plug/platform/tsg_master/tsg_master.inf")
add_test(NAME COPY_MASTER_SO COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/test/tsg_master_gtest.so ${CMAKE_BINARY_DIR}/testing/plug/platform/tsg_master/tsg_master.so")
add_test(NAME COPY_MASTER_CONF COMMAND sh -c "cp -r ${CMAKE_SOURCE_DIR}/bin/ ${CMAKE_BINARY_DIR}/testing/tsgconf")

add_test(NAME FAKE_TEST COMMAND sh -c "pwd")

