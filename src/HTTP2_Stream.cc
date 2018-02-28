#include <string>
#include "HTTP2_Stream.h"
#include "util.h"
#include "analyzer/protocol/http/HTTP.h"
#include "file_analysis/Manager.h"
#include "debug.h"
#include "Reporter.h"

using namespace analyzer::http2;                    

/**
 * HTTP2_Stream::UncompressedOutput : public analyzer::OutputHandler
 * 
 * Description: The output handler type used by the zip decompression api.
 *
 */
class HTTP2_HalfStream::UncompressedOutput : public analyzer::OutputHandler {
public:
    UncompressedOutput(HTTP2_HalfStream* s) { stream = s; }
    virtual ~UncompressedOutput() { }
    virtual void DeliverStream(int len, const u_char* data, bool orig)
    {
        stream->DeliverBodyClear(len, (char*) data, false);
    }

private:
    HTTP2_HalfStream* stream;
};



/********** HTTP2_HalfStream *********/
HTTP2_HalfStream::HTTP2_HalfStream(HTTP2_Analyzer* analyzer, uint32_t stream_id, nghttp2_hd_inflater* inflater)
{
    this->id = stream_id;
    this->analyzer = analyzer;
    this->inflater = inflater;
    this->expectContinuation = false;
    this->state = HTTP2_STREAM_STATE_IDLE;
    this->dataOffset = 0;
    this->dataBlockCnt = 0;
    this->endStreamDetected = false;
    this->peerStreamEnded = false;
    this->zip = nullptr;
    this->send_size = true;

    this->data_size = 0;
    this->contentLength = 0;
    this->contentEncodingId = DATA_ENCODING_IDENTITY;
}

HTTP2_HalfStream::~HTTP2_HalfStream()
{
    if (zip) {
        zip->Done();
        delete zip;
    }
}

bool HTTP2_HalfStream::processHeaders(uint8_t** headerBlockFragmentPtr, uint32_t& len,
                                      bool endHeaders, string& name, string& value)
{
    int processed = 0;
    int flags = 0;
    bool rval = false;
    nghttp2_nv nv_out;

    processed = nghttp2_hd_inflate_hd2(this->inflater, &nv_out, &flags,
                                       *(headerBlockFragmentPtr), len,
                                       endHeaders);
    *(headerBlockFragmentPtr) += processed;
    len -= processed;

    if ((flags & NGHTTP2_HD_INFLATE_EMIT) > 0){
        name = (char*) nv_out.name;
        value = (char*) nv_out.value;
        rval = true;
    } else { // No header emitted
        if (!endHeaders) { // all data processed
            this->expectContinuation = true;
        } else {
            this->expectContinuation = false;
        }
        rval = false;
    }

    if ((flags & NGHTTP2_HD_INFLATE_FINAL) > 0){
        nghttp2_hd_inflate_end_headers(this->inflater);
    }

    return rval;
}

void HTTP2_HalfStream::parseContentEncoding(std::string& s)
{
    DataEncoding encoding = DATA_ENCODING_IDENTITY;

    if (s.find("aes128gcm") != std::string::npos){
        encoding = DATA_ENCODING_AES128GCM;
    }
    else if (s.find("compress") != std::string::npos){
        encoding = DATA_ENCODING_COMPRESS;
    }
    else if (s.find("deflate") != std::string::npos){
        encoding = DATA_ENCODING_DEFLATE;
        this->send_size = false;
    }
    else if (s.find("pack200-gzip") != std::string::npos){
        encoding = DATA_ENCODING_PACK200GZIP;
    }
    else if (s.find("gzip") != std::string::npos){
        encoding = DATA_ENCODING_GZIP;
        this->send_size = false;
    }
    else if (s.find("exi") != std::string::npos){
        encoding = DATA_ENCODING_EXI;
    }
    else if (s.find("br") != std::string::npos){
        encoding = DATA_ENCODING_BROTLI;
        this->send_size = false;
    }

    this->contentEncodingId = encoding;
    this->contentEncoding = s;
}

void HTTP2_HalfStream::extractDataInfoHeaders(std::string& name, std::string& value)
{
    if (name.find("content-encoding") != std::string::npos) {
        parseContentEncoding(value);
    }
    else if (name.find("content-type") != std::string::npos) {
        this->contentType = value;
    }
    else if (name.find("content-length") != std::string::npos){
        try {
            this->contentLength = std::stoi(value);
        }
        catch (std::invalid_argument&) {
            this->analyzer->Weird("Invalid content-length value!");
        }
        catch (std::out_of_range&) {
            this->analyzer->Weird("Out of range content-length value!");
        }
    }
}

void HTTP2_HalfStream::SubmitData(int len, const char* buf){
        
    // if partial data
    if ((this->send_size && this->contentLength > 0 && len < this->contentLength)
        || !this->send_size) {
        file_mgr->DataIn(reinterpret_cast<const u_char*>(buf), len, this->dataOffset,
                         this->analyzer->GetAnalyzerTag(), this->analyzer->Conn(),
                         this->isOrig, this->precomputed_file_id);
        
        this->dataOffset += len;
    }
    else{
        file_mgr->DataIn(reinterpret_cast<const u_char*>(buf), len,
                         this->analyzer->GetAnalyzerTag(), this->analyzer->Conn(),
                         this->isOrig, this->precomputed_file_id);
    }
}

void HTTP2_HalfStream::EndofData(void)
{
    // If a unique file identifier has been created then use it, otherwise 
    // relay to the file manager all information it needs to uniquely identify
    // the message.
    if (!this->precomputed_file_id.empty()) {
        file_mgr->EndOfFile(this->precomputed_file_id);
    } else {
        file_mgr->EndOfFile(this->analyzer->GetAnalyzerTag(),
                            this->analyzer->Conn(), 
                            this->isOrig);
    }
}

void HTTP2_HalfStream::DeliverBody(int len, const char* data, int trailing_CRLF)
{
    switch (this->contentEncodingId) {
        case DATA_ENCODING_DEFLATE:
            translateZipBody(len, data, zip::ZIP_Analyzer::DEFLATE);
            break;
        case DATA_ENCODING_GZIP:
            translateZipBody(len, data, zip::ZIP_Analyzer::GZIP);
            break;
        case DATA_ENCODING_BROTLI:
            if (this->dataBlockCnt == 1) { // Begin Entity
                this->brotli = BrotliDecoderCreateInstance(0, 0, 0); 
            }
            translateBrotliBody(len, data);
            if (trailing_CRLF) { // End Entity
                BrotliDecoderDestroyInstance(this->brotli);
            }
            break;
        case DATA_ENCODING_AES128GCM:   // AES encrypted with 128 bit Key in Galois/Counter Mode
        case DATA_ENCODING_COMPRESS:
        case DATA_ENCODING_EXI:
        case DATA_ENCODING_PACK200GZIP: // Compressed Jar file (pack200) then gzip'd
        case DATA_ENCODING_IDENTITY:    // No compression... clear text.
        default:
            DeliverBodyClear(len, data, false);
            break;
    }
}

void HTTP2_HalfStream::DeliverBodyClear(int len, const char* data, int trailing_CRLF)
{
    if (http2_entity_data) {
        this->analyzer->HTTP2_EntityData(this->isOrig, this->id, len, data);
    }

    this->data_size += len;
    this->SubmitData(len, data);
}

void HTTP2_HalfStream::translateZipBody(int len, const char* data, int method)
{
    if (!zip){
        // We don't care about the direction here.
        zip = new zip::ZIP_Analyzer(this->analyzer->Conn(), false, 
                                    (zip::ZIP_Analyzer::Method) method);
        zip->SetOutputHandler(new UncompressedOutput(this));
    }
    zip->NextStream(len, (const u_char*) data, false);
}

void HTTP2_HalfStream::translateBrotliBody(int len, const char* data)
{
    BrotliDecoderResult result;
    size_t total_out = 0;
    size_t available_in = len;
    const uint8_t* next_in = (const uint8_t*) data;
    size_t available_out = MAX_FRAME_SIZE;  
    uint8_t *next_out = this->brotli_buffer;

    result = BrotliDecoderDecompressStream(this->brotli,
                                           &available_in,
                                           &next_in,
                                           &available_out,
                                           &next_out,
                                           &total_out);
    if (result == BROTLI_DECODER_RESULT_SUCCESS) {
        DeliverBodyClear((int)available_out, (const char *)this->brotli_buffer, false);
    }
}

void HTTP2_HalfStream::processData(HTTP2_Data_Frame* data)
{
    if (++this->dataBlockCnt == 1) {
        // Generate a unique file id for the file being transferred
        if(this->precomputed_file_id.empty()){
            char tmp[16];
            uint64 uid = calculate_unique_id(UID_POOL_DEFAULT_SCRIPT);
            this->precomputed_file_id = uitoa_n(uid, tmp, sizeof(tmp), 62, "F");
        }
        if ( http2_begin_entity )
            this->analyzer->HTTP2_BeginEntity(this->isOrig, this->id, this->contentType);
    }

    uint32_t length;
    const char* dataMsg = (const char*) data->getData(length);
    this->DeliverBody(length, dataMsg, data->isEndStream());

    if(data->isEndStream()){
        if ( http2_end_entity )
            this->analyzer->HTTP2_EndEntity(this->isOrig, this->id);
        this->EndofData();
    }
}

/******** HTTP2_OrigStream *******/
HTTP2_OrigStream::HTTP2_OrigStream(HTTP2_Analyzer* analyzer, uint32_t stream_id, nghttp2_hd_inflater* inflater)
: HTTP2_HalfStream(analyzer, stream_id, inflater)
{
    isOrig = true;
}

HTTP2_OrigStream::~HTTP2_OrigStream()
{
}

void HTTP2_OrigStream::handleFrame(HTTP2_Frame* frame)
{
    switch(this->state){
        case HTTP2_STREAM_STATE_IDLE:
            this->Idle_State(frame);
            break;
        case HTTP2_STREAM_STATE_OPEN:
            this->Open_State(frame);
            break;
        case HTTP2_STREAM_STATE_HALF_CLOSED:
            this->Open_State(frame); 
            break;
        case HTTP2_STREAM_STATE_CLOSED:
            this->Closed_State(frame); 
            break;
        default:
            break;
    }

}

void HTTP2_OrigStream::handleEndStream(void)
{
    this->endStreamDetected = true;
    if(this->peerStreamEnded){
        this->state = HTTP2_STREAM_STATE_CLOSED;
    }
}

void HTTP2_OrigStream::handlePeerEndStream(void)
{
    this->peerStreamEnded = true;
    if(this->endStreamDetected){
        this->state = HTTP2_STREAM_STATE_CLOSED;
    }
}

void HTTP2_OrigStream::handlePushRequested(HTTP2_Frame* frame)
{
    HTTP2_Header_Frame_Base* header = static_cast<HTTP2_Header_Frame_Base*>(frame);
    this->ProcessHeaderBlock(header);

    // Finished processing headers send request and advance the state
    if (header->isEndHeaders()) {
        //Request
        if(http2_request) {
            // unescape_URI will return a 'new' BroString, but
            // a StringVal init'd with a BroString takes ownership of the BroString
            BroString* unescapedPath = analyzer::http::unescape_URI((const unsigned char*)this->request_path.c_str(),
                                                                    (const unsigned char*)(this->request_path.c_str() + this->request_path.length()),
                                                                    this->analyzer);

            this->analyzer->HTTP2_Request(this->isOrig, this->id, this->request_method,
                                          this->request_authority, this->request_host,
                                          this->request_path, unescapedPath, true);
        }

        // Send all buffered headers
        if ( http2_all_headers ) {
            this->analyzer->HTTP2_AllHeaders(this->isOrig, this->id, this->hlist.BuildHeaderTable());
            // Flush the headers since no longer necessary
            this->hlist.flushHeaders();
        }

        // There is no client body to a push promise
        // only headers
        this->state = HTTP2_STREAM_STATE_HALF_CLOSED;
        this->handleEndStream();
    } // else expect continuation frames
}

void HTTP2_OrigStream::ProcessHeaderBlock(HTTP2_Header_Frame_Base* header)
{
    std::string name;
    std::string value;
    uint32_t len = 0;
    uint8_t* ptr = (uint8_t*) header->getHeaderBlock(len);
    while(this->processHeaders(&ptr, len, header->isEndHeaders(), name, value)){
        // Pseudo Header?
        if (name[0] == ':') {
            // Determine if this is one of the Pseudo Headers
            if (name == ":authority") {
                std::string token = value.substr(value.find("@") + 1, std::string::npos); 
                this->request_host = token.substr(0, token.find(":"));
                this->request_authority = value;
            }
            else if (name == ":method") {
                this->request_method = value;
            }
            else if (name == ":scheme") {
                this->request_scheme = value;
            }
            else if (name == ":path") {
                this->request_path = value;
            } else {
                this->analyzer->Weird("Unexpected pseudo header");
                if (http2_header){
                    this->analyzer->HTTP2_Header(this->isOrig, this->id, name, value);
                }
                if (http2_all_headers) {
                    this->hlist.addHeader(name, value);
                }
            }
        }
        // Not a Pseudo Header.
        else{
            if (http2_header) {
                this->analyzer->HTTP2_Header(this->isOrig, this->id, name, value);
            }

            // Retrieve the header info on a per header basis so that 
            // persistent header storage is only necessary if http2_all_headers 
            // is hooked. 
            extractDataInfoHeaders(name, value);

            // Cache off if http2_all_headers is hooked.
            if (http2_all_headers) {
                this->hlist.addHeader(name, value);
            }
        }
    }
}

void HTTP2_OrigStream::Idle_State(HTTP2_Frame* frame)
{
    switch (frame->getType()) {
        case NGHTTP2_PUSH_PROMISE:
        // Orig direction shouldn't receive a push promise
        case NGHTTP2_HEADERS:
        case NGHTTP2_CONTINUATION:
        {
            HTTP2_Header_Frame_Base* header = static_cast<HTTP2_Header_Frame_Base*>(frame);
            this->ProcessHeaderBlock(header);

            // Finished processing headers send request and advance the state
            if (header->isEndHeaders()) {
                //Request
                if(http2_request) {
                    // unescape_URI will return a 'new' BroString, but
                    // a StringVal init'd with a BroString takes ownership of the BroString
                    BroString* unescapedPath = analyzer::http::unescape_URI((const unsigned char*)this->request_path.c_str(),
                                                                            (const unsigned char*)(this->request_path.c_str() + this->request_path.length()),
                                                                            this->analyzer);

                    this->analyzer->HTTP2_Request(this->isOrig, this->id, this->request_method,
                                                  this->request_authority, this->request_host,
                                                  this->request_path, unescapedPath);
                }

                // At this point we have enough information to determine if the content-length sent is
                // accurate based on the encoding of the file
                if (this->send_size && this->contentLength > 0) {
                        file_mgr->SetSize(this->contentLength, this->analyzer->GetAnalyzerTag(),
                                          this->analyzer->Conn(), this->isOrig, this->precomputed_file_id);
                }

                // Send all buffered headers
                if ( http2_all_headers ) {
                    this->analyzer->HTTP2_AllHeaders(this->isOrig, this->id, this->hlist.BuildHeaderTable());
                    // Flush the headers since no longer necessary
                    this->hlist.flushHeaders();
                }

                if (http2_content_type) {
                    if (this->contentType.empty()) {
                        this->contentType = "text/plain";
                    } 
                    this->analyzer->HTTP2_ContentType(this->isOrig, this->id, this->contentType);
                }

                // Advanced the state to 'open'
                this->state = HTTP2_STREAM_STATE_OPEN; 
            } else  { // expect continuation frames

            }

            // The end stream flag has been set, there is no body
            if (header->isEndStream()){
                // Advance the state and do some book-keeping
                this->state = HTTP2_STREAM_STATE_HALF_CLOSED;
                this->handleEndStream();
            } 
            break;
        }
        case NGHTTP2_DATA:
            this->analyzer->Weird("Received data frame while in the 'idle' state");
            //shouldn't receive data in idle state
            break;
        // These are not allowed in a stream
        case NGHTTP2_SETTINGS:
        case NGHTTP2_GOAWAY:
        case NGHTTP2_PING:
            this->analyzer->Weird("Unexpected frame in non-zero stream");
            DEBUG_ERR("Invalid Frame Type:%d for non-\"0\" Stream\n", frame->getType());
            break;
        // Doesn't affect state
        case NGHTTP2_WINDOW_UPDATE:
        case NGHTTP2_PRIORITY:
            break;
        case NGHTTP2_RST_STREAM:
        {
            /* RST_STREAM frames MUST NOT be sent for a stream in the "idle"
               state. If a RST_STREAM frame identifying an idle stream is
               received, the recipient MUST treat this as a connection error. */
            this->analyzer->Weird("RST_STREAM received for stream in idle state.");
            DEBUG_ERR("Connection Error! RST_STREAM received for stream(%d[%d]) in idle state.\n", this->id, this->isOrig);
            this->state = HTTP2_STREAM_STATE_CLOSED;
            break;
        }
        default:
            DEBUG_ERR("Invalid Frame Type:%d\n", frame->getType());
            break;
    }

}


void HTTP2_OrigStream::Open_State(HTTP2_Frame* frame)
{
    switch (frame->getType()) {
        // These should not appear in the open state
        case NGHTTP2_PUSH_PROMISE:
        case NGHTTP2_HEADERS:
        case NGHTTP2_CONTINUATION:
            this->analyzer->Weird("Received header-like frame while in the 'open' state");
            break;
        case NGHTTP2_DATA:
        {
            HTTP2_Data_Frame* data = static_cast<HTTP2_Data_Frame*>(frame);
            this->processData(data);
            if (data->isEndStream()) {
                if (this->state == HTTP2_STREAM_STATE_OPEN)
                    this->state = HTTP2_STREAM_STATE_HALF_CLOSED;
                else
                    this->state = HTTP2_STREAM_STATE_CLOSED;
                this->handleEndStream();
            }
            break;
        }
        // These are not allowed in a stream
        case NGHTTP2_SETTINGS:
        case NGHTTP2_GOAWAY:
        case NGHTTP2_PING:
            this->analyzer->Weird("Received unexpected frame in non-zero stream");
            DEBUG_ERR("Invalid Frame Type:%d for non-\"0\" Stream\n", frame->getType());
            break;
        // Doesn't affect state
        case NGHTTP2_WINDOW_UPDATE:
        case NGHTTP2_PRIORITY:
            break;
        case NGHTTP2_RST_STREAM:
        {
            this->state = HTTP2_STREAM_STATE_CLOSED;
            break;
        }
        default:
            DEBUG_ERR("Invalid Frame Type:%d\n", frame->getType());
            break;
    }
}

void HTTP2_OrigStream::Closed_State(HTTP2_Frame* frame)
{
}


/******** HTTP2_RespStream *******/
HTTP2_RespStream::HTTP2_RespStream(HTTP2_Analyzer* analyzer, uint32_t stream_id, nghttp2_hd_inflater* inflater)
: HTTP2_HalfStream(analyzer, stream_id, inflater)
{
    isOrig = false;
}

HTTP2_RespStream::~HTTP2_RespStream()
{
}

void HTTP2_RespStream::handleFrame(HTTP2_Frame* frame)
{
    switch(this->state){
        case HTTP2_STREAM_STATE_IDLE:
            this->Idle_State(frame);
            break;
        case HTTP2_STREAM_STATE_OPEN:
            this->Open_State(frame);
            break;
        case HTTP2_STREAM_STATE_HALF_CLOSED:
            this->Open_State(frame); 
            break;
        case HTTP2_STREAM_STATE_CLOSED:
            this->Closed_State(frame); 
            break;
        default:
            break;
    }
}

void HTTP2_RespStream::handleEndStream(void)
{
    this->endStreamDetected = true;
    if(this->peerStreamEnded){
        this->state = HTTP2_STREAM_STATE_CLOSED;
    }
}

void HTTP2_RespStream::handlePeerEndStream(void)
{
    this->peerStreamEnded = true;
    if(this->endStreamDetected){
        this->state = HTTP2_STREAM_STATE_CLOSED;
    }
}

void HTTP2_RespStream::handlePushRequested(HTTP2_Frame* frame)
{
    // This should be an error if client sends a pp. There is no client side
    // to a push promise only a response.
    this->analyzer->Weird("Client sent push promise, unexpected behavior");
    DEBUG_ERR("Invalid Push Promise From Client Side\n");
    this->state = HTTP2_STREAM_STATE_HALF_CLOSED;
    this->handleEndStream();
}

void HTTP2_RespStream::ProcessHeaderBlock(HTTP2_Header_Frame_Base* header)
{
    std::string name;
    std::string value;
    uint32_t len = 0;
    uint8_t* ptr = const_cast<uint8_t*>(header->getHeaderBlock(len));
    while(this->processHeaders(&ptr, len, header->isEndHeaders(), name, value)){
        // Pseudo Header?
        if (name[0] == ':') {
            // Determine if this is one of the Pseudo Headers
            if (name == ":status") {
                int32_t code = 0;
                try {
                    code = std::stoi(value);
                }
                catch (std::invalid_argument&) {
                    this->analyzer->Weird("Invalid status code!");
                }
                catch (std::out_of_range&) {
                    this->analyzer->Weird("Out of range status code!");
                }
                if (code < 0 || code > 999) {
                    this->analyzer->Weird("Reply code unexpected value");
                }
                else
                    this->reply_status = static_cast<uint16_t>(code);
            } else {
                this->analyzer->Weird("Unexpected pseudo header");
                if (http2_header) {
                    this->analyzer->HTTP2_Header(this->isOrig, this->id, name, value);
                }
                if ( http2_all_headers) {
                    this->hlist.addHeader(name, value);
                }
            }
        }
        // Not a Pseudo Header.
        else {
            if (http2_header) {
                this->analyzer->HTTP2_Header(this->isOrig, this->id, name, value);
            }

            // Retrieve the header info on a per header basis so that 
            // persistent header storage is only necessary if http2_all_headers 
            // is hooked. 
            extractDataInfoHeaders(name, value);

            // Cache off if http2_all_headers is hooked.
            if ( http2_all_headers) {
                this->hlist.addHeader(name, value);
            }
        }
    }
}

void HTTP2_RespStream::Idle_State(HTTP2_Frame* frame)
{

    switch (frame->getType()) {
        case NGHTTP2_PUSH_PROMISE:
        case NGHTTP2_HEADERS:
        case NGHTTP2_CONTINUATION:
        {
            HTTP2_Header_Frame_Base* header = (HTTP2_Header_Frame_Base*) frame;
            this->ProcessHeaderBlock(header);

            if (header->isEndHeaders()) {
                if(http2_reply) {
                    this->analyzer->HTTP2_Reply(this->isOrig, this->id, this->reply_status);
                }

                if (this->send_size && this->contentLength > 0) {
                        file_mgr->SetSize(this->contentLength, this->analyzer->GetAnalyzerTag(),
                                          this->analyzer->Conn(), this->isOrig, this->precomputed_file_id);
                }

                if (http2_content_type) {
                    if (this->contentType.empty()){
                        this->contentType = "text/plain";
                    }
                    this->analyzer->HTTP2_ContentType(this->isOrig, this->id, this->contentType);
                }

                if ( http2_all_headers ) {
                    this->analyzer->HTTP2_AllHeaders(this->isOrig, this->id, this->hlist.BuildHeaderTable());
                    this->hlist.flushHeaders();
                }

                this->state = HTTP2_STREAM_STATE_OPEN; 
            } else { // expect continuation frames

            }

            if (header->isEndStream()){
                this->state = HTTP2_STREAM_STATE_HALF_CLOSED;
                this->handleEndStream();
            } 
            break;
        }
        case NGHTTP2_DATA:
            this->analyzer->Weird("Received data frame while in the 'idle' state [resp]");
            break;
        // These are not allowed in a stream
        case NGHTTP2_SETTINGS:
        case NGHTTP2_GOAWAY:
        case NGHTTP2_PING:
            this->analyzer->Weird("Unexpected frame in non-zero stream");
            DEBUG_ERR("Invalid Frame Type:%d for non-\"0\" Stream\n", frame->getType());
            break;
        // Do not affect state
        case NGHTTP2_WINDOW_UPDATE:
        case NGHTTP2_PRIORITY:
            break;
        case NGHTTP2_RST_STREAM:
        {
            /* RST_STREAM frames MUST NOT be sent for a stream in the "idle"
               state. If a RST_STREAM frame identifying an idle stream is
               received, the recipient MUST treat this as a connection error. */
            this->analyzer->Weird("RST_STREAM received for stream in idle state.");
            DEBUG_ERR("Connection Error! RST_STREAM received for stream(%d[%d]) in idle state.\n", this->id, this->isOrig);
            this->state = HTTP2_STREAM_STATE_CLOSED;
            break;
        }
        default:
            break;
    }

}

void HTTP2_RespStream::Open_State(HTTP2_Frame* frame)
{
    switch (frame->getType()) {
        // These should not appear in the open state
        case NGHTTP2_PUSH_PROMISE:
        case NGHTTP2_HEADERS:
        case NGHTTP2_CONTINUATION:
            this->analyzer->Weird("Received header-like frame while in the 'open' state");
            break;
        case NGHTTP2_DATA:
        {
            HTTP2_Data_Frame* data = static_cast<HTTP2_Data_Frame*>(frame);
            this->processData(data);
            if (data->isEndStream()) {
                if (this->state == HTTP2_STREAM_STATE_OPEN)
                    this->state = HTTP2_STREAM_STATE_HALF_CLOSED;
                else
                    this->state = HTTP2_STREAM_STATE_CLOSED;
                this->handleEndStream();
            }
            break;
        }
        // These are not allowed in a stream
        case NGHTTP2_SETTINGS:
        case NGHTTP2_GOAWAY:
        case NGHTTP2_PING:
            this->analyzer->Weird("Received unexpected frame in non-zero stream");
            break;
        // Does not affect state
        case NGHTTP2_WINDOW_UPDATE:
        case NGHTTP2_PRIORITY:
            break;
        case NGHTTP2_RST_STREAM:
        {
            this->state = HTTP2_STREAM_STATE_CLOSED;
            break;
        }
        default:
            break;
    }
}

void HTTP2_RespStream::Closed_State(HTTP2_Frame* frame)
{
}

HTTP2_Stream::HTTP2_Stream(HTTP2_Analyzer* analyzer, uint32_t stream_id, nghttp2_hd_inflater* inflaters[2])
{                                                   
    this->id = stream_id;
    this->inflaters[0] = inflaters[0];
    this->inflaters[1] = inflaters[1];
    this->analyzer = analyzer;

    // orig = false = 0 = responder so make sure to swap the inflaters
    this->halfStreams[0] = new HTTP2_RespStream(analyzer, stream_id, inflaters[0]);
    this->halfStreams[1] = new HTTP2_OrigStream(analyzer, stream_id, inflaters[1]);
    this->streamReset = false;
    this->streamResetter = 0;

    DEBUG_INFO("Create Stream: [%d]\n",this->id);
}

HTTP2_Stream::~HTTP2_Stream()
{
    delete this->halfStreams[0];
    delete this->halfStreams[1];

    DEBUG_INFO("Destroy Stream: [%d]\n",this->id);
}

bool HTTP2_Stream::handleFrame(HTTP2_Frame* f, bool orig) {

    if (!this->handlingPush) {
        if (f->getType() == NGHTTP2_PUSH_PROMISE){
            this->handlingPush = true;
            this->halfStreams[!orig]->handlePushRequested(f);
        } else {
            this->halfStreams[orig]->handleFrame(f);
        }
    } else { //handling a push, should only be continuation, otherwise the push is over
        if (f->getType() != NGHTTP2_CONTINUATION) {
            // during a push it should only be PP and Cont frames
            // if following spec this should be a header frame
            this->handlingPush = false;
            this->halfStreams[orig]->handleFrame(f);
        } else { //continuation frame, continue handling push
            this->halfStreams[!orig]->handlePushRequested(f);
        }
    }

    if (f->getType() == NGHTTP2_RST_STREAM){
        // TODO FIXME how to handle a rst stream frame
        // -- spec specifies rst frame sender must be able to accept frames 
        // already in transit also priority frames can still be sent after a 
        // reset can either keep stream allocated to allow for processing of 
        // frames after reset or ignore further frames
        this->streamReset = true;
        this->streamResetter = orig;
    }

    if (this->halfStreams[orig]->isStreamEnded()){
        this->halfStreams[!orig]->handlePeerEndStream();
    }

    return (this->halfStreams[orig]->isClosed() &&
            this->halfStreams[!orig]->isClosed());
}

bool HTTP2_Stream::handleStreamEnd() {
    if (http2_stream_end) {
        RecordVal* stream_stats = new RecordVal(BifType::Record::http2_stream_stat);
        // process is_orig == true first
        stream_stats->Assign(0, new Val(this->halfStreams[1]->getDataSize(), TYPE_COUNT));
        stream_stats->Assign(1, new Val(this->halfStreams[0]->getDataSize(), TYPE_COUNT));
        this->analyzer->HTTP2_StreamEnd(this->id, stream_stats);
    }

    return true;
}
