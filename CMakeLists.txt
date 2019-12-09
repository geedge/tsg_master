cmake_minimum_required (VERSION 2.8)

project(tsg_master)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(Version)

set(CMAKE_MACOSX_RPATH 0)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

include_directories(${PROJECT_SOURCE_DIR}/inc/)
include_directories(/opt/MESA/include/)

option(ENABLE_WARNING_ALL "Enable all optional warnings which are desirable for normal code" TRUE)
option(ENABLE_SANITIZE_ADDRESS "Enable AddressSanitizer" FALSE)
option(ENABLE_SANITIZE_THREAD "Enable ThreadSanitizer" FALSE)

if(ENABLE_SANITIZE_ADDRESS)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
elseif(ENABLE_SANITIZE_THREAD)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread -fno-omit-frame-pointer")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread -fno-omit-frame-pointer")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
endif()

set(CMAKE_INSTALL_PREFIX /home/mesasoft/sapp_run)

add_subdirectory (src) 

set(CONFLIST /plug/conflist.inf)
set(MASTER_INF "./plug/platform/tsg_master/tsg_master.inf")
set(PROJECT_LIST /etc/project_list.conf)

file(WRITE ${PROJECT_SOURCE_DIR}/install.sh "#!/bin/sh\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "DST=\${RPM_INSTALL_PREFIX}\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "mkdir -p \${DST}/plug/platform/\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "mkdir -p \${DST}/etc/\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "touch \${DST}${CONFLIST}\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "touch \${DST}${PROJECT_LIST}\r\n")

file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "if [[ -z `grep -rn 'POLICY_PRIORITY' \${DST}${PROJECT_LIST}` ]];then\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "echo 'POLICY_PRIORITY	struct' >> \${DST}${PROJECT_LIST}\r\nfi\r\n")

file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "if [[ -z `grep -rn 'tsg_master.inf' \${DST}${CONFLIST}` ]];then\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "sed -i '/\\[platform\\]/a\\${MASTER_INF}' \${DST}${CONFLIST}\r\nfi\r\n")
#file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "echo './plug/platform/tsg_master/tsg_master.inf' >> \${DST}\${CONFLIST}\r\nfi\r\n")

SET(CPACK_RPM_PRE_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/install.sh")

file(WRITE ${PROJECT_SOURCE_DIR}/uninstall.sh "#!/bin/sh\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/uninstall.sh "DST=\${RPM_INSTALL_PREFIX}\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/uninstall.sh "mkdir -p \${DST}/plug/platform/\r\n")

file(APPEND ${PROJECT_SOURCE_DIR}/uninstall.sh "sed -i '/tsg_master.inf/d' \${DST}${CONFLIST}\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/uninstall.sh "sed -i '/POLICY_PRIORITY/d' \${DST}${PROJECT_LIST}\r\n")

SET(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/uninstall.sh")

install(FILES bin/main.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf)
install(FILES bin/tsg_tableinfo.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf)
install(FILES bin/tsg_log_field.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf)
install(FILES bin/tsg_maat.json DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf)
install(FILES bin/tsg_maat_ip_deny.json DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf)
install(FILES inc/tsg_send_log.h DESTINATION /opt/MESA/include/tsg)
install(FILES inc/tsg_rule.h DESTINATION /opt/MESA/include/tsg)

include(Package)
