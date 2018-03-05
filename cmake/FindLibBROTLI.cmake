# - Try to find LibBROTLI headers and libraries.
#
# Usage of this module as follows:
#
#     find_package(LibBROTLI)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  LibBROTLI_ROOT_DIR  Set this variable to the root installation of
#                      LibBROTLI if the module has problems finding
#                      the proper installation path.
#
# Variables defined by this module:
#
#  LIBBROTLI_FOUND              System has LibBROTLI libs/headers
#  LibBROTLI_LIBRARIES          The LibBROTLI libraries
#  LibBROTLI_INCLUDE_DIR        The location of LibBROTLI headers

find_path(LibBROTLI_ROOT_DIR
    NAMES include/brotli/decode.h include/brotli/encode.h
)

find_path(LibBROTLI_INCLUDE_DIR
    NAMES decode.h encode.h
    HINTS ${LibBROTLI_ROOT_DIR}/include/brotli
)

find_library(LibBROTLI_LIBRARIES
    NAMES brotlidec
    PATHS ${LibBROTLI_ROOT_DIR}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    LibBROTLI DEFAULT_MSG
    LibBROTLI_LIBRARIES
    LibBROTLI_INCLUDE_DIR
)

mark_as_advanced(
    LibBROTLI_ROOT_DIR
    LibBROTLI_INCLUDE_DIR
    LibBROTLI_LIBRARIES
)
