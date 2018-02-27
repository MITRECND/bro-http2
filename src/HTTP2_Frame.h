#ifndef ANALYZER_PROTOCOL_HTTP2_HTTP2_FRAME_H
#define ANALYZER_PROTOCOL_HTTP2_HTTP2_FRAME_H

static constexpr size_t MAX_FRAME_SIZE = 16777215;

#include "util.h"

namespace analyzer { namespace http2 {

struct RawFrameHeader
{
   uint8_t len[3];
   uint8_t typ;
   uint8_t flags;
   uint8_t streamId[4]; //MSB is reserved bit.
};

static constexpr size_t FRAME_HEADER_LENGTH = (sizeof(RawFrameHeader)/sizeof(uint8_t));

static constexpr uint8_t HTTP2_FRAME_UNDEFINED = 255;


/**
 * Class HTTP2_FrameHeader
 *
 * Description: Represents a frame header, provides easy processing
 * of http 2 frame header information including processing of flags
 *
 */
class HTTP2_FrameHeader {
public:
    HTTP2_FrameHeader(uint8_t* data);
    ~HTTP2_FrameHeader(void)=default;

    // Frame Header Info API
    const uint32_t getLen(void) const{return len;};
    const uint8_t getType(void) const{return typ;};
    const uint8_t getFlags(void) const{return flags;};
    const uint32_t getStreamId(void) const{return streamId;};

    // Flag functions
    bool isEndHeaders(void);
    bool isEndStream(void);
    bool isPadded(void);
    bool isPriority(void);
    bool isAck(void);

private:
    uint32_t len;
    uint8_t typ;
    uint8_t flags;
    uint32_t streamId;
};


class HTTP2_Frame{
public:
    HTTP2_Frame(HTTP2_FrameHeader* h);
    virtual ~HTTP2_Frame(void);

    const HTTP2_FrameHeader* getHeader(void) const {return this->header;};
    const uint8_t getType(void) const {return this->header->getType();};
    const uint32_t getStreamId(void) const {return this->header->getStreamId();};
    const std::string errorToText(uint32_t error);
    bool validate(void){return this->valid;};

protected:
    HTTP2_FrameHeader* header;
    // Convenience Function to check for padding
    bool checkPadding(uint8_t* payload, uint32_t len, uint8_t &padLength);
    bool valid;
};

class HTTP2_Data_Frame : public HTTP2_Frame {
public:
    HTTP2_Data_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len);
    ~HTTP2_Data_Frame(void);

    const uint8_t* getData(uint32_t& len);
    bool isEndStream(void){return this->header->isEndStream();};

private:
    int dataLength;
    uint8_t* dataMsg;
};


class HTTP2_Header_Frame_Base: public HTTP2_Frame {

public:
    HTTP2_Header_Frame_Base(HTTP2_FrameHeader* h);
    ~HTTP2_Header_Frame_Base(void);

    const uint8_t* getHeaderBlock(uint32_t& len);
    bool isEndHeaders(void){return this->header->isEndHeaders();};
    virtual bool isEndStream(void){return this->header->isEndStream();};

protected:
    uint8_t* headerBlock;
    uint32_t headerBlockLen;

};

class HTTP2_Header_Frame : public HTTP2_Header_Frame_Base {
public:
    HTTP2_Header_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len);
    ~HTTP2_Header_Frame(void);
    bool isEndStream(void){return this->header->isEndStream();};

};

class HTTP2_Priority_Frame : public HTTP2_Frame {
public:
    HTTP2_Priority_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len);
    ~HTTP2_Priority_Frame(void);

    uint32_t getDependentStream(void){return dependentStream;};
    bool getExclusive(void){return exclusive;};
    uint8_t getWeight(void){return weight;};

private:
    uint32_t dependentStream;
    bool exclusive;
    uint8_t weight;
};

class HTTP2_RstStream_Frame : public HTTP2_Frame {
public:
    HTTP2_RstStream_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len);
    ~HTTP2_RstStream_Frame(void);

    uint32_t getErrorCode(void){return errorCode;};
    const std::string getErrorText(void) {return this->errorToText(this->errorCode);};

private:
    uint32_t errorCode;

};

class HTTP2_Settings_Frame : public HTTP2_Frame {    
public:
    HTTP2_Settings_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len);
    ~HTTP2_Settings_Frame(void);

    bool getHeaderTableSize(uint32_t& size);
    bool getEnablePush(uint32_t& push);
    bool getMaxConcurrentStreams(uint32_t& streams);
    bool getInitialWindowSize(uint32_t& size);
    bool getMaxFrameSize(uint32_t& size);
    bool getMaxHeaderListSize(uint32_t& size);
    bool unrecognizedSettings(void){return this->unrecognized_settings;};
    const std::vector<pair<uint16_t, uint32_t>>& getUnrecognizedSettings(void){return (this->unrec_settings);};
    bool isAck(void){return this->header->isAck();};

private:
    bool header_table_size_set;
    bool enable_push_set;
    bool max_concurrent_streams_set;
    bool initial_window_size_set;
    bool max_frame_size_set;
    bool max_header_list_size_set;
    bool unrecognized_settings;

    uint32_t header_table_size;
    uint32_t enable_push;
    uint32_t max_concurrent_streams;
    uint32_t initial_window_size;
    uint32_t max_frame_size;
    uint32_t max_header_list_size;
    std::vector<pair<uint16_t, uint32_t>> unrec_settings;

};                                                 
                                             
class HTTP2_PushPromise_Frame : public HTTP2_Header_Frame_Base {
public:
    HTTP2_PushPromise_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len);
    ~HTTP2_PushPromise_Frame(void);

    uint32_t getPromisedStreamId(void){return this->promisedStream;};

private:
    uint32_t promisedStream;

};

static constexpr size_t PING_OPAQUE_DATA_LENGTH = 8;
class HTTP2_Ping_Frame : public HTTP2_Frame {
public:
    HTTP2_Ping_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len);
    ~HTTP2_Ping_Frame(void);

    const uint8_t* getData(void){return data;};
    bool isAck(void){return this->header->isAck();};

private:
    uint8_t data[PING_OPAQUE_DATA_LENGTH];
};

class HTTP2_GoAway_Frame : public HTTP2_Frame {
public:
    HTTP2_GoAway_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len);
    ~HTTP2_GoAway_Frame(void);

    uint32_t getLastStreamId(void){return lastStreamId;};
    uint32_t getErrorCode(void){return errorCode;};
    const uint8_t* getDebugData(uint32_t& len);
    const std::string getErrorText(void) {return this->errorToText(this->errorCode);};

private:
    uint32_t lastStreamId;
    uint32_t errorCode;
    uint8_t* debugData;
    uint32_t debugDataLength;
};

class HTTP2_WindowUpdate_Frame : public HTTP2_Frame {
public:
    HTTP2_WindowUpdate_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len);
    ~HTTP2_WindowUpdate_Frame(void);

    const uint32_t getSizeIncrement(void) const {return sizeIncrement;};

private:
    uint32_t sizeIncrement;
};

class HTTP2_Continuation_Frame : public HTTP2_Header_Frame {
public:
    HTTP2_Continuation_Frame(HTTP2_FrameHeader* h, uint8_t* payload, uint32_t len);
    ~HTTP2_Continuation_Frame(void);

private:
};


} } // namespace analyzer::* 

#endif
