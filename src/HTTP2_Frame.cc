#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "HTTP2.h"
#include "HTTP2_Frame.h"
#include "zeek/util.h"
#include "nghttp2.h"
#include "nghttp2ver.h"
#include "debug.h"
#include "zeek/Reporter.h"

using namespace analyzer::mitrecnd;

static inline uint32_t ntoh24(uint8_t* data)
{
    // Extract as is into a 32-bit integer
    uint32_t num = data[2] << 24 | data[1] << 16 | data[0] << 8;
    return ntohl(num);
}

/******** HTTP2_FrameHeader *********/
HTTP2_FrameHeader::HTTP2_FrameHeader(uint8_t* data)
{
    len = 0;
    typ = HTTP2_FRAME_UNDEFINED;
    flags = 0;
    streamId = 0;

    RawFrameHeader* fh = reinterpret_cast<RawFrameHeader*>(data);

    // Parse Frame Length
    this->len = ntoh24(fh->len);
    // Parse Type
    this->typ = fh->typ;
    // Parse Flags
    this->flags = fh->flags;
    // Parse Stream ID, reverse endianess
    uint8_t* sid = fh->streamId;
    this->streamId = ntohl(*reinterpret_cast<uint32_t*>(sid)) & 0x7FFFFFFF;// mask off R bitfield
}

bool HTTP2_FrameHeader::isEndHeaders(void)
{
    return (this->flags & NGHTTP2_FLAG_END_HEADERS) != 0;
}

bool HTTP2_FrameHeader::isEndStream(void)
{
    return (this->flags & NGHTTP2_FLAG_END_STREAM) != 0;
}

bool HTTP2_FrameHeader::isPadded(void)
{
    return (this->flags & NGHTTP2_FLAG_PADDED) != 0;
}

bool HTTP2_FrameHeader::isPriority(void)
{
    return (this->flags & NGHTTP2_FLAG_PRIORITY) != 0;
}

bool HTTP2_FrameHeader::isAck(void)
{
    return (this->flags & NGHTTP2_FLAG_ACK) != 0;
}



/******** HTTP2_Frame **********/

HTTP2_Frame::HTTP2_Frame(HTTP2_FrameHeader* h)
{
    this->header = h;
    this->valid = false;
}

HTTP2_Frame::~HTTP2_Frame(void)
{
    delete this->header;
}

bool HTTP2_Frame::checkPadding(uint8_t* payload, uint32_t len, uint8_t &padLength)
{
    if((len > 0) && (this->header->isPadded())) {
        padLength = payload[0];
        return true;
    }
    return false;
}

/*
** Utility
*/
/**
 * const char* HTTP2_Frame::errorToText(uint32_t error)
 *
 * Description: Convert header decompression error code into
 * ASCII string for display.
 *
 *
 * @param error the error code
 *
 * @return const char*
 */
const std::string HTTP2_Frame::errorToText(uint32_t error)
{
    std::string s = "NGHTTP2_UNKNOWN_ERROR";

    switch (error) {
    case  NGHTTP2_NO_ERROR:
        s = "NGHTTP2_NO_ERROR";
        break;
    case  NGHTTP2_PROTOCOL_ERROR:
        s = "NGHTTP2_PROTOCOL_ERROR";
        break;
    case  NGHTTP2_INTERNAL_ERROR:
        s = "NGHTTP2_INTERNAL_ERROR";
        break;
    case  NGHTTP2_FLOW_CONTROL_ERROR:
        s = "NGHTTP2_FLOW_CONTROL_ERROR";
        break;
    case  NGHTTP2_SETTINGS_TIMEOUT:
        s = "NGHTTP2_SETTINGS_TIMEOUT";
        break;
    case  NGHTTP2_STREAM_CLOSED:
        s = "NGHTTP2_STREAM_CLOSED";
        break;
    case  NGHTTP2_FRAME_SIZE_ERROR:
        s = "NGHTTP2_FRAME_SIZE_ERROR";
        break;
    case  NGHTTP2_REFUSED_STREAM:
        s = "NGHTTP2_REFUSED_STREAM";
        break;
    case  NGHTTP2_CANCEL:
        s = "NGHTTP2_CANCEL";
        break;
    case  NGHTTP2_COMPRESSION_ERROR:
        s = "NGHTTP2_COMPRESSION_ERROR";
        break;
    case  NGHTTP2_CONNECT_ERROR:
        s = "NGHTTP2_CONNECT_ERROR";
        break;
    case  NGHTTP2_ENHANCE_YOUR_CALM:
        s = "NGHTTP2_ENHANCE_YOUR_CALM";
        break;
    case  NGHTTP2_INADEQUATE_SECURITY:
        s = "NGHTTP2_INADEQUATE_SECURITY";
        break;
    case  NGHTTP2_HTTP_1_1_REQUIRED:
        s = "NGHTTP2_HTTP_1_1_REQUIRED";
        break;
    default:
        break;
    }

    return s;

}


/********* HTTP2_DATA_FRAME ********/
HTTP2_Data_Frame::HTTP2_Data_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len)
: HTTP2_Frame(h)
{
    this->dataMsg = nullptr;
    this->dataLength = 0;

    if(this->header->getLen() != len){ //Not provided enough information
        return;
    }

    uint8_t padLength = 0;
    uint8_t* cursor = payload;
    if (this->checkPadding(payload, len, padLength)){
        //Add the padding field itself
        padLength += 1;
        cursor += 1;
    }

    if (padLength > this->header->getLen()){ // Padding too much
        return;
    }

    this->dataLength = this->header->getLen() - padLength;
    this->dataMsg = new uint8_t[this->dataLength];
    if (!this->dataMsg){// allocation error?
        return;
    }

    memcpy(this->dataMsg, cursor, this->dataLength);

    this->valid = true;
}

HTTP2_Data_Frame::~HTTP2_Data_Frame(void)
{
    if(this->dataMsg){
        delete[] this->dataMsg;
    }
}


const uint8_t* HTTP2_Data_Frame::getData(uint32_t& len)
{
    if (this->dataMsg){
        len = this->dataLength;
        return (const uint8_t*) this->dataMsg;
    } else {
        len = 0;
        return nullptr;
    }
}

/********* Header Base Class *********/
HTTP2_Header_Frame_Base::HTTP2_Header_Frame_Base(HTTP2_FrameHeader* h)
:HTTP2_Frame(h)
{
    this->headerBlock = nullptr;
    this->headerBlockLen = 0;
}

HTTP2_Header_Frame_Base::~HTTP2_Header_Frame_Base(void)
{
    if (this->headerBlock){
        delete[] this->headerBlock;
        this->headerBlock = nullptr;
    }
}

const uint8_t* HTTP2_Header_Frame_Base::getHeaderBlock(uint32_t& len)
{
    if(this->headerBlock){
        len = this->headerBlockLen;
        return (const uint8_t*) this->headerBlock;
    } else {
        len = 0;
        return nullptr;
    }
}


/******** HTTP2_Header_Frame ********/
HTTP2_Header_Frame::HTTP2_Header_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len)
:HTTP2_Header_Frame_Base(h)
{
    if (this->header->getLen() != len){
        return;
    }

    uint8_t padLength = 0;
    uint8_t* cursor = payload;
    if (this->checkPadding(payload, len, padLength)){
        // Add padding field itself
        padLength += 1;
        cursor += 1;
    }

    if (this->header->isPriority()) {
        cursor += 5; // Compensate for additional priority header info. (E bit, Stream Dependency, Weight)
        // Add extra fields to the pad length
        padLength += 5;
    }

    if (padLength > len) {
        return;
    }

    this->headerBlockLen = len - padLength;
    this->headerBlock = new uint8_t[this->headerBlockLen];

    if (!this->headerBlock){
        return;
    }

    memcpy(this->headerBlock, cursor, this->headerBlockLen);

    this->valid = true;
}

HTTP2_Header_Frame::~HTTP2_Header_Frame(void)
{
    // Parent Header_Frame_Base takes care of deleting header block structure
}


/******** HTTP2_Priority_Frame ********/
HTTP2_Priority_Frame::HTTP2_Priority_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len)
:HTTP2_Frame(h)
{
    if (this->header->getLen() != len){
        return;
    }

    if (len != 5) { // Priority frames must be 5 bytes
        return;
    }

    this->dependentStream = ntohl(*reinterpret_cast<uint32_t*>(payload));
    this->exclusive = ((this->dependentStream & 0x80000000) != 0);
    this->dependentStream &= 0x7FFFFFFF;// mask off E bitfield
    this->weight = *(payload + 4);

    this->valid = true;
}

HTTP2_Priority_Frame::~HTTP2_Priority_Frame(void)
{
}

/******** HTTP2_RstStream_Frame *********/
HTTP2_RstStream_Frame::HTTP2_RstStream_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len)
:HTTP2_Frame(h)
{
    if (this->header->getLen() != len){
        return;
    }

    if (len != 4){ //Reset frames must be 4 bytes
        return;
    }

    this->errorCode = ntohl(*reinterpret_cast<uint32_t*>(payload));
    this->valid = true;
}

HTTP2_RstStream_Frame::~HTTP2_RstStream_Frame(void)
{
}


/******** HTTP2_Settings_Frame ******/
HTTP2_Settings_Frame::HTTP2_Settings_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len)
:HTTP2_Frame(h)
{
    if (this->header->getLen() != len){
        return;
    }

    if (len % 6 != 0){ // settings frames must have a length divisible by 6
        return;
    }

    this->header_table_size_set = false;
    this->enable_push_set = false;
    this->max_concurrent_streams_set = false;
    this->initial_window_size_set = false;
    this->max_frame_size_set = false;
    this->max_header_list_size_set = false;
    this->unrecognized_settings = false;

    uint16_t ident;
    uint32_t val;
    uint8_t* cursor = payload;
    uint32_t dataLen = len;

    while (dataLen > 0) {
        ident = ntohs(*reinterpret_cast<uint16_t*>(cursor));
        val = ntohl(*reinterpret_cast<uint32_t*>(cursor + 2));
        cursor += 6;
        dataLen -= 6;

        switch (ident) {
            case NGHTTP2_SETTINGS_HEADER_TABLE_SIZE:
                this->header_table_size_set = true;
                this->header_table_size = val;
                break;
            case NGHTTP2_SETTINGS_ENABLE_PUSH:
                this->enable_push_set = true;
                this->enable_push = val;
                break;
            case NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
                this->max_concurrent_streams_set = true;
                this->max_concurrent_streams = val;
                break;
            case NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
                this->initial_window_size_set = true;
                this->initial_window_size = val;
                break;
            case NGHTTP2_SETTINGS_MAX_FRAME_SIZE:
                this->max_frame_size_set = true;
                this->max_frame_size = val;
                break;
            case NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
                this->max_header_list_size_set = true;
                this->max_header_list_size = val;
                break;
            default:
                this->unrec_settings.push_back(std::pair<uint16_t, uint32_t>(ident, val));
                break;
        }
    }

    this->valid = true;
}

HTTP2_Settings_Frame::~HTTP2_Settings_Frame(void)
{
}

bool HTTP2_Settings_Frame::getHeaderTableSize(uint32_t& size)
{
    if(this->header_table_size_set){
        size = this->header_table_size;
    }

    return this->header_table_size_set;
}
bool HTTP2_Settings_Frame::getEnablePush(uint32_t& push)
{
    if(this->enable_push_set){
        push = this->enable_push;
    }

    return this->enable_push_set;

}
bool HTTP2_Settings_Frame::getMaxConcurrentStreams(uint32_t& streams)
{
    if(this->max_concurrent_streams_set){
        streams = this->max_concurrent_streams;
    }

    return this->max_concurrent_streams_set;
}

bool HTTP2_Settings_Frame::getInitialWindowSize(uint32_t& size)
{
    if(this->initial_window_size_set){
        size = this->initial_window_size;
    }

    return this->initial_window_size_set;
}

bool HTTP2_Settings_Frame::getMaxFrameSize(uint32_t& size)
{
    if(this->max_frame_size_set){
        size = this->max_frame_size;
    }

    return this->max_frame_size_set;
}

bool HTTP2_Settings_Frame::getMaxHeaderListSize(uint32_t& size)
{
    if(this->max_header_list_size_set){
        size = this->max_header_list_size;
    }

    return this->max_header_list_size_set;
}


/********** HTTP2_PushPromise_Frame *********/
HTTP2_PushPromise_Frame::HTTP2_PushPromise_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len)
:HTTP2_Header_Frame_Base(h)
{
    if (this->header->getLen() != len){
        return;
    }

    uint8_t padLength = 0;
    uint8_t* cursor = payload;
    if (this->checkPadding(payload, len, padLength)){
        // Add padding field itself
        padLength += 1;
        cursor += 1;
    }

    // Grab promised stream id
    this->promisedStream = ntohl(*reinterpret_cast<uint32_t*>(payload)) & 0x7FFFFFFF; // Remove reserved bit
    padLength += 4;
    cursor += 4;

    if (padLength > len){
        return;
    }

    this->headerBlockLen = len - padLength;
    this->headerBlock = new uint8_t[this->headerBlockLen];
    if (!this->headerBlock) {
        return;
    }

    memcpy(this->headerBlock, cursor, this->headerBlockLen);

    this->valid = true;
}

HTTP2_PushPromise_Frame::~HTTP2_PushPromise_Frame(void)
{
    // Parent Header_Frame_Base takes care of deleting header block structure
}


/********** HTTP2_Ping_Frame *********/
HTTP2_Ping_Frame::HTTP2_Ping_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len)
:HTTP2_Frame(h)
{
    if (this->header->getLen() != len){
        return;
    }

    if (this->header->getLen() != 8){
        return;
    }

    memcpy(this->data, payload, PING_OPAQUE_DATA_LENGTH);

    this->valid = true;
}

HTTP2_Ping_Frame::~HTTP2_Ping_Frame(void)
{
}


/********** HTTP2_GoAway_Frame *********/
HTTP2_GoAway_Frame::HTTP2_GoAway_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len)
:HTTP2_Frame(h)
{
    this->debugData = nullptr;
    this->debugDataLength = 0;

    if (this->header->getLen() != len){
        return;
    }
    if (len < 8){
        return;
    }

    this->lastStreamId = ntohl(*reinterpret_cast<uint32_t*>(payload)) & 0x7FFFFFFF;// mask off R bitfield
    this->errorCode = ntohl(*reinterpret_cast<uint32_t*>(payload + 4));

    if (len > 8){
        this->debugDataLength = len - 8;
        this->debugData = new uint8_t[this->debugDataLength];
        if (!this->debugData){
            return;
        }

        memcpy(this->debugData, payload + 8, this->debugDataLength);
    }

    this->valid = true;
}

HTTP2_GoAway_Frame::~HTTP2_GoAway_Frame(void)
{
    if (this->debugData){
        delete[] this->debugData;
    }
}

const uint8_t* HTTP2_GoAway_Frame::getDebugData(uint32_t& len)
{
    if (this->debugData){
        len = this->debugDataLength;
        return (const uint8_t*) this->debugData;
    } else {
        len = 0;
        return nullptr;
    }
}

/********** HTTP2_WindowUpdate_Frame *********/
HTTP2_WindowUpdate_Frame::HTTP2_WindowUpdate_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len)
:HTTP2_Frame(h)
{
    if (this->header->getLen() != len){
        return;
    }

    if(len != 4 ){
        return;
    }

    this->sizeIncrement = ntohl(*reinterpret_cast<uint32_t*>(payload)) & 0x7FFFFFFF;// mask off R bitfield
    this->valid = true;
}

HTTP2_WindowUpdate_Frame::~HTTP2_WindowUpdate_Frame(void)
{
}

/********** HTTP2_Continuation_Frame *********/
HTTP2_Continuation_Frame::HTTP2_Continuation_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len)
:HTTP2_Header_Frame(h, payload, len)
{
    // Parent Header_Frame type should take care of everything
}

HTTP2_Continuation_Frame::~HTTP2_Continuation_Frame(void)
{
}
