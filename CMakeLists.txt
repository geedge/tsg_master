cmake_minimum_required (VERSION 2.8)

set(lib_name tsg_master)
project(${lib_name})

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

add_subdirectory(src) 

SET(CPACK_RPM_LIBRARY_PRE_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/cmake/PreInstall.sh")
SET(CPACK_RPM_LIBRARY_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/cmake/PreUninstall.sh")

set(CPACK_RPM_LIBRARY_USER_FILELIST "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/tsgconf/main.conf"
                           		 "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/tsgconf/maat.conf"
			 "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/tsgconf/tsg_static_tableinfo.conf"
			 "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/tsgconf/tsg_dynamic_tableinfo.conf"
			 "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/tsgconf/tsg_log_field.conf"
			 "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/tsgconf/tsg_maat.json"
)

install(FILES bin/main.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)
install(FILES bin/maat.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)
install(FILES bin/tsg_static_tableinfo.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)
install(FILES bin/tsg_dynamic_tableinfo.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)
install(FILES bin/tsg_log_field.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)
install(FILES bin/tsg_maat.json DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)
install(FILES inc/tsg_send_log.h DESTINATION /opt/MESA/include/tsg COMPONENT HEADER)
install(FILES inc/tsg_rule.h DESTINATION /opt/MESA/include/tsg COMPONENT HEADER)
install(FILES inc/tsg_statistic.h DESTINATION /opt/MESA/include/tsg COMPONENT HEADER)

include(Package)
