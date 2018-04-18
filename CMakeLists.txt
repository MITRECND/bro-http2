cmake_minimum_required(VERSION 2.8)

project(BroPluginHTTP2)


if ( NOT BRO_DIST )
    message(FATAL_ERROR "BRO_DIST not set")
endif ()

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

include(BroPlugin)

find_package(LibNGHTTP2)
find_package(LibBROTLI)

if (NOT LIBNGHTTP2_FOUND)
  message(STATUS "LibNGHTTP2 ROOT DIR : ${LibNGHTTP2_ROOT_DIR}")
  message(STATUS "LibNGHTTP2 INC DIR  : ${LibNGHTTP2_INCLUDE_DIR}")
  message(STATUS "LibNGHTTP2 LIB DIR  : ${LibNGHTTP2_LIBRARIES}")
  message(FATAL_ERROR "LibNGHTTP2 not found.")
endif()

if (LibNGHTTP2_VERSION)
    if(LibNGHTTP2_VERSION VERSION_LESS "1.11.0")
        message(FATAL_ERROR "LibNGHTTP2 must be 1.11.0 or greater")
    endif()
else()
    message(WARNING "Unable to determine LibNGHTTP2 library version")
endif()

if (NOT LIBBROTLI_FOUND)
  message(STATUS "LibBROTLI ROOT DIR  : ${LibBROTLI_ROOT_DIR}")
  message(STATUS "LibBROTLI INC DIR   : ${LibBROTLI_INCLUDE_DIR}")
  message(STATUS "LibBROTLI LIB DIR   : ${LibBROTLI_LIBRARIES}")
  message(FATAL_ERROR "LibBROTLI not found.")
endif()

message(STATUS "---------------------")
message(STATUS "LibBROTLI ROOT DIR  : ${LibBROTLI_ROOT_DIR}")
message(STATUS "LibBROTLI INC DIR   : ${LibBROTLI_INCLUDE_DIR}")
message(STATUS "LibBROTLI LIB DIR   : ${LibBROTLI_LIBRARIES}")
message(STATUS "---------------------")
message(STATUS "LibNGHTTP2 ROOT DIR : ${LibNGHTTP2_ROOT_DIR}")
message(STATUS "LibNGHTTP2 INC DIR  : ${LibNGHTTP2_INCLUDE_DIR}")
message(STATUS "LibNGHTTP2 LIB DIR  : ${LibNGHTTP2_LIBRARIES}")

include_directories(BEFORE ${LibNGHTTP2_INCLUDE_DIR})
bro_plugin_begin(mitrecnd HTTP2)

include_directories(BEFORE ${LibBROTLI_INCLUDE_DIR})
bro_plugin_link_library(${LibBROTLI_LIBRARIES})

bro_plugin_cc(src/Plugin.cc)
bro_plugin_cc(src/HTTP2_Frame.cc)
bro_plugin_cc(src/HTTP2_FrameReassembler.cc)
bro_plugin_cc(src/HTTP2_HeaderStorage.cc)
bro_plugin_cc(src/HTTP2_Stream.cc)
bro_plugin_cc(src/HTTP2.cc)
bro_plugin_bif(src/events.bif src/http2.bif)
bro_plugin_dist_files(COPYING LICENSE README README.md VERSION)
bro_plugin_link_library(${LibNGHTTP2_LIBRARIES})
bro_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
