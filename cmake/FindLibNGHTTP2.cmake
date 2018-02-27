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

find_path(LibNGHTTP2_ROOT_DIR
    NAMES include nghttp2.h
)

find_path(LibNGHTTP2_INCLUDE_DIR
    NAMES nghttp2.h nghttp2ver.h
    HINTS ${LibNGHTTP2_ROOT_DIR}/include/nghttp2/ /usr/include/nghttp2/
)

find_library(LibNGHTTP2_LIBRARIES
    NAMES nghttp2
    HINTS ${LibNGHTTP2_ROOT_DIR}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibNGHTTP2 DEFAULT_MSG
    LibNGHTTP2_LIBRARIES
    LibNGHTTP2_INCLUDE_DIR
)

mark_as_advanced(
    LibNGHTTP2_ROOT_DIR
    LibNGHTTP2_LIBRARIES
    LibNGHTTP2_INCLUDE_DIR
)
