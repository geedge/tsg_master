include(ExternalProject)

### ctemplate
ExternalProject_Add(ctemplate PREFIX ctemplate
        URL ${CMAKE_CURRENT_SOURCE_DIR}/ctemplate-2.3.tar.gz
        URL_MD5 3b91f3c1e7aa55cb4c2957acf77d6b9a
        PATCH_COMMAND patch -p1 < ${CMAKE_CURRENT_LIST_DIR}/patch/compile_ctemplate_use_centos8_with_gcc7.patch
        BUILD_COMMAND sh autogen.sh
        CONFIGURE_COMMAND CPPFLAGS=-fPIC ./configure --prefix=<INSTALL_DIR> CFLAGS=-fPIC CXXFLAGS=-fPIC  LDFLAGS=-fPIC
        BUILD_IN_SOURCE 1)

ExternalProject_Get_Property(ctemplate INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(ctemplate-static STATIC IMPORTED GLOBAL)
add_dependencies(ctemplate-static ctemplate)
set_property(TARGET ctemplate-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libctemplate.a)
set_property(TARGET ctemplate-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
