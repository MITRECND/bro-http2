# - Try to find LibNGHTTP2 headers and libraries.
#
# Usage of this module as follows:
#
#     find_package(LibNGHTTP2)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  LibNGHTTP2_ROOT_DIR  Set this variable to the root installation of
#                       LibNGHTTP2 if the module has problems finding
#                       the proper installation path.
#
# Variables defined by this module:
#
#  LIBNGHTTP2_FOUND              System has LibNGHTTP2 libs/headers
#  LibNGHTTP2_LIBRARIES          The LibNGHTTP2 libraries
#  LibNGHTTP2_INCLUDE_DIR        The location of LibNGHTTP2 headers
#  LibNGHTTP2_VERSION            The version of the library

find_path(LibNGHTTP2_ROOT_DIR
    NAMES include/nghttp2/nghttp2.h
)

find_path(LibNGHTTP2_INCLUDE_DIR
    NAMES nghttp2.h nghttp2ver.h
    HINTS ${LibNGHTTP2_ROOT_DIR}/include/nghttp2/
)

find_library(LibNGHTTP2_LIBRARIES
    NAMES nghttp2
    HINTS ${LibNGHTTP2_ROOT_DIR}/lib
)

find_file(LibNGHTTP2 LIBVERSION_FILE_FOUND nghttp2ver.h
          PATHS ${LibNGHTTP2_INCLUDE_DIR})

set(LibNGHTTP2_VERSION "NOTFOUND")
if(NOT (${LibNGHTTP2_LIBVERSION_FILE_FOUND} MATCHES "NOTFOUND"))
    file(READ ${LibNGHTTP2_INCLUDE_DIR}/nghttp2ver.h VERSION_FILE)
    string(REGEX MATCH "#define NGHTTP2_VERSION \"([0-9]*.[0-9]*.[0-9]*)"
           VERSION_STRING ${VERSION_FILE})
    if (VERSION_STRING)
        set(LibNGHTTP2_VERSION ${CMAKE_MATCH_1})
    endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibNGHTTP2 FOUND_VAR LIBNGHTTP2_FOUND
                                  REQUIRED_VARS LibNGHTTP2_LIBRARIES
                                                LibNGHTTP2_INCLUDE_DIR
                                  VERSION_VAR LibNGHTTP2_VERSION
)

mark_as_advanced(LibNGHTTP2_ROOT_DIR
                 LibNGHTTP2_LIBRARIES
                 LibNGHTTP2_INCLUDE_DIR
                 LibNGHTTP2_VERSION
)
