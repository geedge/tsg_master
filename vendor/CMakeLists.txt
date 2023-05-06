# CMakeFiles for 3rd vendor library

include(ExternalProject)
# libgtest
ExternalProject_Add(libgtest PREFIX libgtest
        URL ${CMAKE_SOURCE_DIR}/vendor/googletest-release-1.10.0.tar.gz
        URL_MD5 ecd1fa65e7de707cd5c00bdac56022cd
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE})
ExternalProject_Get_Property(libgtest INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)
add_library(gtest-static STATIC IMPORTED GLOBAL)
add_dependencies(gtest-static libgtest)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set_property(TARGET gtest-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib64/libgtestd.a)
else()
	set_property(TARGET gtest-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib64/libgtest.a)
endif()
set_property(TARGET gtest-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
set_property(TARGET gtest-static PROPERTY INTERFACE_LINK_LIBRARIES pthread)

# # libmsgpackc
# ExternalProject_Add(libmsgpackc PREFIX libmsgpackc
#         URL ${CMAKE_SOURCE_DIR}/vendor/msgpack-c-6.0.0.tar.gz
#         URL_MD5 adc08f48550ce772fe24c0b41166b0de
#         CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
#         -DMSGPACK_BUILD_TESTS=OFF -DMSGPACK_USE_BOOST=OFF)
# ExternalProject_Get_Property(libmsgpackc INSTALL_DIR)
# file(MAKE_DIRECTORY ${INSTALL_DIR}/include)
# add_library(msgpackc-static STATIC IMPORTED GLOBAL)
# add_dependencies(msgpackc-static libmsgpackc)

# set_property(TARGET msgpackc-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libmsgpack-c.a)
# set_property(TARGET msgpackc-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)



