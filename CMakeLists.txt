cmake_minimum_required (VERSION 2.8...3.10)

set(lib_name tsg_master)
project(${lib_name})

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(Version)

set(CMAKE_MACOSX_RPATH 0)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

include_directories(${PROJECT_SOURCE_DIR}/inc/)
include_directories(/opt/MESA/include/)

#for cppcheck
find_program(CMAKE_CXX_CPPCHECK NAMES cppcheck)
if (CMAKE_CXX_CPPCHECK)
    list(
        APPEND CMAKE_CXX_CPPCHECK 
            "--enable=all"
            "--error-exitcode=1"
            "--suppress=unreachableCode"
            "--suppress=unusedFunction"
            "--suppress=missingInclude"
            "--suppress=uselessAssignmentPtrArg"
            "--suppress=unmatchedSuppression"
            "--suppress=internalAstError"
            "--suppress=unmatchedSuppression"
	    "--suppress=memleakOnRealloc"
	    "--suppress=redundantAssignment"
	    "--suppress=constParameter"
		"--suppress=*:${PROJECT_SOURCE_DIR}/src/mpack.c"
    )
    set(CMAKE_C_CPPCHECK ${CMAKE_CXX_CPPCHECK})
else()
  message(FATAL_ERROR "Could not find the program cppcheck.")
endif()

#for ASAN
set(ASAN_OPTION "OFF" CACHE STRING " set asan type chosen by the user, using OFF as default")
set_property(CACHE ASAN_OPTION  PROPERTY STRINGS OFF ADDRESS THREAD)
message(STATUS "ASAN_OPTION='${ASAN_OPTION}'")

if(ASAN_OPTION MATCHES "ADDRESS")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
elseif(ASAN_OPTION MATCHES "THREAD")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
endif()
# end of for ASAN

set(CMAKE_INSTALL_PREFIX /home/mesasoft/sapp_run)

add_subdirectory(support)
add_subdirectory(src) 
add_subdirectory(vendor)
add_subdirectory(test/src)

enable_testing()
add_subdirectory(./ctest)


SET(CPACK_RPM_LIBRARIES_PRE_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/cmake/PreInstall.sh")
SET(CPACK_RPM_LIBRARIES_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/cmake/PreUninstall.sh")

set(CPACK_RPM_LIBRARIES_USER_FILELIST "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/tsgconf/main.conf"
                           		 "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/tsgconf/maat.conf"
)

install(FILES bin/main.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)
install(FILES bin/maat.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)
install(FILES bin/tsg_static_tableinfo.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)
install(FILES bin/tsg_static_tableinfo.json DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)
install(FILES bin/tsg_dynamic_tableinfo.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)
install(FILES bin/tsg_log_field.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)
install(FILES bin/app_l7_proto_id.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)
install(FILES bin/tsg_l7_protocol.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)
install(FILES bin/tsg_maat.json DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)

install(FILES bin/HTTP200.html DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)
install(FILES bin/HTTP204.html DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)
install(FILES bin/HTTP303.html DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)
install(FILES bin/HTTP403.html DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)
install(FILES bin/HTTP404.html DESTINATION ${CMAKE_INSTALL_PREFIX}/tsgconf COMPONENT PROFILE)

install(FILES inc/tsg_send_log.h DESTINATION /opt/MESA/include/tsg COMPONENT HEADER)
install(FILES inc/tsg_rule.h DESTINATION /opt/MESA/include/tsg COMPONENT HEADER)
install(FILES inc/tsg_statistic.h DESTINATION /opt/MESA/include/tsg COMPONENT HEADER)
install(FILES inc/tsg_label.h DESTINATION /opt/MESA/include/tsg COMPONENT HEADER)
install(FILES inc/app_label.h DESTINATION /opt/MESA/include/tsg COMPONENT HEADER)
install(FILES inc/tsg_gtp_signaling.h DESTINATION /opt/MESA/include/tsg COMPONENT HEADER)

include(Package)
