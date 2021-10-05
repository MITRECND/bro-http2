#ifndef ANALYZER_PROTOCOL_HTTP2_HTTP2_DEBUG_H
#define ANALYZER_PROTOCOL_HTTP2_HTTP2_DEBUG_H
#include "zeek/Reporter.h"
#define HTTP2_DEBUG_LEVEL 0

#if (HTTP2_DEBUG_LEVEL > 2)
#define DEBUG_ERR  reporter->Error
#define DEBUG_INFO reporter->Info
#define DEBUG_DBG reporter->Info
#elif (HTTP2_DEBUG_LEVEL > 1)
#define DEBUG_ERR  reporter->Error
#define DEBUG_INFO reporter->Info
#define DEBUG_DBG(format, ...)
#elif (HTTP2_DEBUG_LEVEL > 0)
#define DEBUG_ERR  reporter->Error
#define DEBUG_INFO(format, ...)
#define DEBUG_DBG(format, ...)
#else
#define DEBUG_ERR(format, ...)
#define DEBUG_INFO(format, ...)
#define DEBUG_DBG(format, ...)
#endif

#endif
