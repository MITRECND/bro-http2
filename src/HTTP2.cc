#include <string.h>

#include "HTTP2.h"

#include "Var.h"
#include "NetVar.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "analyzer/protocol/mime/MIME.h"
#include "debug.h"
#include "Reporter.h"

using namespace analyzer::mitrecnd;

const bool DEBUG_http2 = true;

// This is the HTTP2 client connection preface. It indicates the connection is using HTTP2 protocol.
static constexpr uint8_t connectionPreface[]=
{
    0x50,0x52,0x49,0x20,0x2a,0x20,0x48,0x54,
    0x54,0x50,0x2f,0x32,0x2e,0x30,0x0d,0x0a,
    0x0d,0x0a,0x53,0x4d,0x0d,0x0a,0x0d,0x0a
};

static constexpr uint8_t CONN_PREFACE_LENGTH = static_cast<uint8_t>(sizeof(connectionPreface)/sizeof(uint8_t));


/*
** HTTP2_Analyzer
*/

HTTP2_Analyzer::HTTP2_Analyzer(Connection* conn)
: tcp::TCP_ApplicationAnalyzer("HTTP2", conn)
    {
    DEBUG_INFO("Create Analyzer: [%p]\n",Conn());
    this->connectionActive = false;
    this->had_gap = false;
    this->request_version = this->reply_version = 0.0;  // unknown version
    this->reassemblers = nullptr;
    this->inflaters[0] = this->inflaters[1] = nullptr;
    this->protocol_errored = false;


    // header table size default is 4096
    this->headerTableSize = 4096;

    // push is enabled by default
    this->pushEnabled = true;

    // By spec default is infinite, but zero disables
    // streams
    this->maxConcurrentStreams = -1;

    // Default by spec is 65535
    this->initialWindowSize = 65535;

    // max frame size initial value is 16384 according to spec
    // maximum by spec is 16777215
    this->maxFrameSize = 16384; // 4 * default

    // By spec default is infinite
    this->maxHeaderListSize = -1;

    // Stream numbering is sequential and only increases
    // A new stream id should not be less than existing streams
    this->lastStreams[0] = this->lastStreams[1] = 0;

    // GoAway frame will indicate the last stream it will
    // recognize
    this->goAwayStream = 0;

    }

HTTP2_Analyzer::~HTTP2_Analyzer()
    {
        DEBUG_INFO("Destroy Analyzer: [%p]\n",Conn());
        this->connectionActive = false;
        this->destroyReassemblers();
        this->deleteInflaters();
        this->destroyStreams();
    }

void HTTP2_Analyzer::Done()
    {
    tcp::TCP_ApplicationAnalyzer::Done();
    }

void HTTP2_Analyzer::EndpointEOF(bool is_orig)
    {
    tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
    }

void HTTP2_Analyzer::DeliverStream(int len, const u_char* data, bool orig){
    tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

    // If we see the connection Preface we will have to skip it to realign the 
    // stream for processing
    int prefaceOffset;

    assert(TCP());
    if ( TCP()->IsPartial() )
        return;

    if ( this->had_gap )
        // If only one side had a content gap, we could still try to
        // deliver data to the other side if the script layer can handle this.
        return;

    if (this->protocol_errored) {
        // Protocol violation has occurred, can't continue
        return;
    }

    DEBUG_INFO("[%p][%d]DeliverStream(%d)->\n",Conn(),orig,len);

#if (HTTP2_DEBUG_LEVEL > 3)
    for (int i = 0; i < len; i++) {
        if (!(i%32)) { printf("\n"); }
        printf("%2x ",data[i]);
        if (i>=255) { break; }
    }
    printf("\n");
#endif
    prefaceOffset = 0;
    // Evaluate incoming data to determine if it is HTTP2 protocol or not
    if (!this->connectionActive) {
        this->connectionActive = connectionPrefaceDetected(len, data);
        if(this->connectionActive){
            // Skip the preface and process what comes after it.
            prefaceOffset = CONN_PREFACE_LENGTH;
            this->request_version = this->reply_version = 2.0;
            // Allocate hpack inflaters
            this->initInflaters();
            // Create the stream mapping objects -- inflaters are passed to streams
            this->initStreams();
            // Create frame reassemblers which will stitch frames together
            this->initReassemblers();
            ProtocolConfirmation(); // Notify system that this is HTTP2.
            DEBUG_INFO("Connection Preface Detected: [%p]!\n", Conn());
        }
    }
    // If the connection is HTTP2
    if (this->connectionActive) {
        vector<HTTP2_Frame*> frames = this->reassemblers[orig].process(&data[prefaceOffset], (len - prefaceOffset));
        // Frame memory is callee handled so clean it up after use
        for (vector<HTTP2_Frame*>::iterator it = frames.begin(); it != frames.end(); ++it){
            if(*it == nullptr) {
                // Reassembler will ensure last frame pointer is null, so no other, valid,
                // frames should be present that need to be to be handled/deleted
                ProtocolViolation("Unable to parse http 2 frame from data stream, fatal error");
                this->protocol_errored = true;
                return;
            }

            HTTP2_Frame* frame = *it;

            uint32_t stream_id = 0;
            // Push Promise is a special case
            // since it provides the id of the new stream in the payload
            if (frame->getType() == NGHTTP2_PUSH_PROMISE) {
                stream_id = static_cast<HTTP2_PushPromise_Frame*>(frame)->getPromisedStreamId();
            } else {
                stream_id = frame->getStreamId();
            }

            this->handleFrameEvents(frame, orig, stream_id);

            if (stream_id == 0) {
                this->handleStream0(frame, orig);
            } else {
                HTTP2_Stream* stream = this->getStream(stream_id, orig);
                if (stream != nullptr) {
                    bool closed = stream->handleFrame(frame, orig);
                    if (closed){
                        if (http2_stream_end) {
                            stream->handleStreamEnd();
                        }
                        this->removeStream(stream);
                    }
                }
            }
            delete (frame);
        }
    }
}

void HTTP2_Analyzer::Undelivered(uint64 seq, int len, bool orig){
    tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
    this->had_gap = true;
}

static inline RecordVal* generateSettingsRecord(HTTP2_Settings_Frame* frame) {
    uint32_t val;
    RecordVal* settings_rec = new RecordVal(BifType::Record::http2_settings);

    if(frame->getHeaderTableSize(val)){
        settings_rec->Assign(0, new Val(val, TYPE_COUNT));
    }
    if(frame->getEnablePush(val)){
        settings_rec->Assign(1, new Val((bool)val, TYPE_BOOL));
    }
    if(frame->getMaxConcurrentStreams(val)){
        settings_rec->Assign(2, new Val(val, TYPE_COUNT));
    }
    if(frame->getInitialWindowSize(val)){
        settings_rec->Assign(3, new Val(val, TYPE_COUNT));
    }
    if(frame->getMaxFrameSize(val)){
        settings_rec->Assign(4, new Val(val, TYPE_COUNT));
    }
    if(frame->getMaxHeaderListSize(val)){
        settings_rec->Assign(5, new Val(val, TYPE_COUNT));
    }

    if(frame->unrecognizedSettings()){
        TableVal* unrec_table = new TableVal(BifType::Table::http2_settings_unrecognized_table);
        auto unrec = frame->getUnrecognizedSettings();
        for (auto it=unrec.begin(); it != unrec.end(); it++) {
            Val* index = new Val(it->first, TYPE_COUNT);
            unrec_table->Assign(index, new Val(it->second, TYPE_COUNT));
            Unref(index);
        }
        settings_rec->Assign(6, unrec_table);
    }

    return settings_rec;
}

void HTTP2_Analyzer::handleFrameEvents(HTTP2_Frame* frame, bool orig, uint32_t stream_id) {

    if ( http2_data_event ||
         http2_header_event ||
         http2_priority_event ||
         http2_rststream_event ||
         http2_settings_event ||
         http2_pushpromise_event ||
         http2_ping_event ||
         http2_goaway_event ||
         http2_windowupdate_event ||
         http2_continuation_event) {

        switch(frame->getType()) {
            case NGHTTP2_DATA:
                if (http2_data_event) {
                    HTTP2_Data_Frame* df = static_cast<HTTP2_Data_Frame*>(frame);
                    uint32_t dataLen;
                    const char* data = reinterpret_cast<const char*>(df->getData(dataLen));
                    this->HTTP2_Data_Event(orig, stream_id, dataLen, data);
                }
                break;
            case NGHTTP2_HEADERS:
                if (http2_header_event) {
                    HTTP2_Header_Frame* hf = static_cast<HTTP2_Header_Frame*>(frame);
                    uint32_t headerLen;
                    const char* headerBlock = reinterpret_cast<const char*>(hf->getHeaderBlock(headerLen));
                    this->HTTP2_Header_Event(orig, stream_id, headerLen, headerBlock);
                }
                break;
            case NGHTTP2_PRIORITY:
                if (http2_priority_event) {
                    HTTP2_Priority_Frame* pf = static_cast<HTTP2_Priority_Frame*>(frame);
                    this->HTTP2_Priority_Event(orig, stream_id, pf->getExclusive(),
                                               pf->getDependentStream(), pf->getWeight()); 
                }
                break;
            case NGHTTP2_RST_STREAM:
                if (http2_rststream_event) {
                    HTTP2_RstStream_Frame* rf = static_cast<HTTP2_RstStream_Frame*>(frame);
                    this->HTTP2_RstStream_Event(orig, stream_id, rf->getErrorText());
                }
                break;
            case NGHTTP2_SETTINGS:
                if (http2_settings_event) {
                    HTTP2_Settings_Frame* sf = static_cast<HTTP2_Settings_Frame*>(frame);
                    this->HTTP2_Settings_Event(orig, stream_id, generateSettingsRecord(sf));
                }
                break;
            case NGHTTP2_PUSH_PROMISE:
                if (http2_pushpromise_event) {
                    HTTP2_PushPromise_Frame* ppf = static_cast<HTTP2_PushPromise_Frame*>(frame);
                    uint32_t headerLen;
                    const char* headerBlock = reinterpret_cast<const char*>(ppf->getHeaderBlock(headerLen));
                    this->HTTP2_PushPromise_Event(orig, stream_id, ppf->getPromisedStreamId(), headerLen, headerBlock);
                }
                break;
            case NGHTTP2_PING:
                if (http2_ping_event) {
                    HTTP2_Ping_Frame* pf = static_cast<HTTP2_Ping_Frame*>(frame);
                    this->HTTP2_Ping_Event(orig, stream_id, PING_OPAQUE_DATA_LENGTH,
                                           reinterpret_cast<const char*>(pf->getData()));
                }
                break;
            case NGHTTP2_GOAWAY:
                if (http2_goaway_event) {
                    HTTP2_GoAway_Frame* gf = static_cast<HTTP2_GoAway_Frame*>(frame);
                    uint32_t debugLen;
                    const char* debugData = reinterpret_cast<const char*>(gf->getDebugData(debugLen));
                    this->HTTP2_GoAway_Event(orig, stream_id, gf->getLastStreamId(),
                                             gf->getErrorText(), debugLen, debugData);
                }
                break;
            case NGHTTP2_WINDOW_UPDATE:
                if (http2_windowupdate_event) {
                    HTTP2_WindowUpdate_Frame* wf = static_cast<HTTP2_WindowUpdate_Frame*>(frame);
                    this->HTTP2_WindowUpdate_Event(orig, stream_id, wf->getSizeIncrement());
                }
                break;
            case NGHTTP2_CONTINUATION:
                if (http2_continuation_event) {
                    HTTP2_Continuation_Frame* hf = static_cast<HTTP2_Continuation_Frame*>(frame);
                    uint32_t headerLen;
                    const char* headerBlock = reinterpret_cast<const char*>(hf->getHeaderBlock(headerLen));
                    this->HTTP2_Continuation_Event(orig, stream_id, headerLen, headerBlock);
                }
                break;
            default:
                break;
        }

    }
}

// Stream 0 functions
void HTTP2_Analyzer::handleStream0(HTTP2_Frame* frame, bool orig)
{
    switch(frame->getType()){
        // The following should only be seen by stream 0
        case NGHTTP2_SETTINGS:
            this->handleSettings((HTTP2_Settings_Frame*)frame, orig);
            break;
        case NGHTTP2_GOAWAY:
            this->handleGoAway((HTTP2_GoAway_Frame*)frame, orig);
            break;
        case NGHTTP2_PING:
            this->handlePing((HTTP2_Ping_Frame*)frame, orig);
            break;
        // The following can be seen in stream 0 or others
        case NGHTTP2_WINDOW_UPDATE:
            this->handleWindowUpdate((HTTP2_WindowUpdate_Frame*)frame, orig);
            break;
        // The following are invalid with stream id == 0
        case NGHTTP2_DATA:
        case NGHTTP2_HEADERS:
        case NGHTTP2_PRIORITY:
        case NGHTTP2_RST_STREAM:
        case NGHTTP2_PUSH_PROMISE:
        case NGHTTP2_CONTINUATION:
            this->Weird("Unexpected frame in Stream 0");
            DEBUG_ERR("Invalid Frame Type:%d for Stream \"0\"\n", frame->getType());
            break;
    }
}

void HTTP2_Analyzer::handleSettings(HTTP2_Settings_Frame* frame, bool orig)
{
    uint32_t val;

    if(frame->getHeaderTableSize(val)){
        this->headerTableSize = val;
    }
    if(frame->getEnablePush(val)){
        this->pushEnabled = (bool) val;
    }
    if(frame->getMaxConcurrentStreams(val)){
        this->maxConcurrentStreams = val;
    }
    if(frame->getInitialWindowSize(val)){
        this->initialWindowSize = val;
    }
    if(frame->getMaxFrameSize(val)){
        this->maxFrameSize = val;
        for(int i=0; i<2;i++){
            this->reassemblers[i].resizeBuffer(val);
        }
    }
    if(frame->getMaxHeaderListSize(val)){
        this->maxHeaderListSize = val;
    }

    if(frame->unrecognizedSettings()){
    }
}

void HTTP2_Analyzer::handleGoAway(HTTP2_GoAway_Frame* frame, bool orig)
{
    this->goAwayStream = frame->getLastStreamId();
}

void HTTP2_Analyzer::handlePing(HTTP2_Ping_Frame* frame, bool orig)
{
    //noop -- not handled in any special way
}

void HTTP2_Analyzer::handleWindowUpdate(HTTP2_WindowUpdate_Frame* frame, bool orig)
{
    //noop -- not handled in any special way
}

HTTP2_Stream* HTTP2_Analyzer::getStream(uint32_t stream_id, bool orig)
{
    HTTP2_Stream* stream = nullptr;

    auto it = this->streams.find(stream_id);
    if (it == this->streams.end()) { // Doesn't exist
        if(this->goAwayStream > 0 && stream_id > this->goAwayStream){
            // Streams greater than goaway technically can't be established ...
            this->Weird("Streams greater than goaway can't be established!");
            return nullptr;
        }

        if(stream_id < this->lastStreams[orig]){
            //Stream id can't be less than last established stream.
            this->Weird("Stream Id less than last established stream!");
            return nullptr;
        }

        this->lastStreams[orig] = stream_id;
        stream = new HTTP2_Stream(this, stream_id, this->inflaters);
        this->streams.insert(std::pair<uint32_t, HTTP2_Stream*>(stream_id, stream));
        if (http2_stream_start) {
            this->HTTP2_StreamStart(orig, stream_id);
        }
    }else{
        stream = it->second;
    }

    return stream;
}

void HTTP2_Analyzer::removeStream(HTTP2_Stream* stream)
{
    this->streams.erase(stream->getId());
    delete stream;
}

void HTTP2_Analyzer::initStreams(void)
{
}

void HTTP2_Analyzer::destroyStreams(void)
{
    auto it = this->streams.begin();
    auto next_it = this->streams.begin();
    for (; it != this->streams.end(); it = next_it)
    {
        next_it = it; ++next_it;
        auto stream = it->second;
        delete stream;
        this->streams.erase(it);
    }    
    this->streams.clear();
}

void HTTP2_Analyzer::initInflaters(void)
{
    for(int i = 0; i < 2; i++){
        if (nghttp2_hd_inflate_new(&this->inflaters[i]) != 0) {
            DEBUG_ERR("nghttp2_hd_inflate_init failed with error: %s\n", nghttp2_strerror(rv));
        }
        else{
            size_t max_table_size = 4294967295; //(size_t)this->getMaxHeaderTableSize();
            if (nghttp2_hd_inflate_change_table_size(this->inflaters[i], max_table_size) != 0) {
                DEBUG_ERR("nghttp2_hd_inflate_init failed with error: %s\n", nghttp2_strerror(rv));
            }
            else{
                DEBUG_INFO("******** Inflator[%p] Created ********\n", this->inflaters[i]);
            }
        }
    }
}

void HTTP2_Analyzer::deleteInflaters(void)
{
    for(int i = 0; i < 2; i++){
        DEBUG_INFO("******** Delete Inflater[%p] ********\n", this->inflaters[i]);
        if (this->inflaters[i] != nullptr) {
            nghttp2_hd_inflate_del(this->inflaters[i]);
            this->inflaters[i] = nullptr;
        }
    }
}

void HTTP2_Analyzer::initReassemblers(void)
{
    if(this->reassemblers == nullptr){
        this->reassemblers = new HTTP2_FrameReassembler[2];
    }
}

void HTTP2_Analyzer::destroyReassemblers(void)
{
    if(this->reassemblers != nullptr){
        delete[] this->reassemblers;
    }
}

/*
** Utility 
*/ 

bool HTTP2_Analyzer::connectionPrefaceDetected(int len, const u_char* data)
{

    if ((len >= CONN_PREFACE_LENGTH) &&
       (memcmp((void*) data, (void*) connectionPreface, CONN_PREFACE_LENGTH) == 0)){
        return true;
    }

    return false;

}

/*
** Bro Interface wrappers. 
*/
void HTTP2_Analyzer::HTTP2_Request(bool orig, unsigned stream, std::string& method, 
                                   std::string& authority, std::string& host, 
                                   std::string& path, BroString* unescaped, bool push){
    //this->num_requests++;
    if ( http2_request ){
        val_list* vl = new val_list;
        vl->append(this->BuildConnVal());
        vl->append(new Val(orig, TYPE_BOOL));
        vl->append(new Val(stream, TYPE_COUNT));
        vl->append(new StringVal(method));
        vl->append(new StringVal(authority));
        vl->append(new StringVal(host));
        vl->append(new StringVal(path));
        vl->append(new StringVal(unescaped));
        vl->append(new StringVal(fmt("%.1f", 2.0)));
        vl->append(new Val(push, TYPE_BOOL));
        DEBUG_DBG("[%3u][%1d] http2_request\n", stream, orig);
        this->ConnectionEvent(http2_request, vl);
    }
}

void HTTP2_Analyzer::HTTP2_Reply(bool orig, unsigned stream, uint16_t status){
    if ( http2_reply ){
        val_list* vl = new val_list;
        vl->append(this->BuildConnVal());
        vl->append(new Val(orig, TYPE_BOOL));
        vl->append(new Val(stream, TYPE_COUNT));
        vl->append(new StringVal(fmt("%.1f", 2.0)));
        vl->append(new Val(status, TYPE_COUNT));
        vl->append(new StringVal("<empty>"));
        DEBUG_DBG("[%3u][%1d] http2_reply\n", stream, orig);
        this->ConnectionEvent(http2_reply, vl);
    }
}

void HTTP2_Analyzer::HTTP2_StreamEnd(unsigned stream, RecordVal* stream_stats){
    if ( http2_stream_end ){
        val_list* vl = new val_list;
        vl->append(this->BuildConnVal());
        vl->append(new Val(stream, TYPE_COUNT));
        vl->append(stream_stats);
        DEBUG_DBG("[%3u][%1d] http2_stream_end\n", stream, orig);
        this->ConnectionEvent(http2_stream_end, vl);
    }
}

void HTTP2_Analyzer::HTTP2_StreamStart(bool orig, unsigned stream){
    if ( http2_stream_start ){
        val_list* vl = new val_list;
        vl->append(this->BuildConnVal());
        vl->append(new Val(orig, TYPE_BOOL));
        vl->append(new Val(stream, TYPE_COUNT));
        DEBUG_DBG("[%3u][%1d] http2_stream_start\n", stream, orig);
        this->ConnectionEvent(http2_stream_start, vl);
    }
}

void HTTP2_Analyzer::HTTP2_Header(bool orig, unsigned stream, std::string& name, std::string& value){
    if ( http2_header ){
        val_list* vl = new val_list();
        vl->append(this->BuildConnVal());
        vl->append(new Val(orig, TYPE_BOOL));
        vl->append(new Val(stream, TYPE_COUNT));
        vl->append((new StringVal(name))->ToUpper());
        vl->append(new StringVal(value));
        DEBUG_DBG("http2_header\n");
        this->ConnectionEvent(http2_header, vl);
    }
}

void HTTP2_Analyzer::HTTP2_AllHeaders(bool orig, unsigned stream, TableVal* hlist){
    if ( http2_all_headers ){
        val_list* vl = new val_list();
        vl->append(this->BuildConnVal());
        vl->append(new Val(orig, TYPE_BOOL));
        vl->append(new Val(stream, TYPE_COUNT));
        vl->append(hlist);
        DEBUG_DBG("http2_all_headers\n");
        this->ConnectionEvent(http2_all_headers, vl);
    }
}

void HTTP2_Analyzer::HTTP2_BeginEntity(bool orig, unsigned stream, std::string& contentType){
    if ( http2_begin_entity ){
        val_list* vl = new val_list();
        vl->append(this->BuildConnVal());
        vl->append(new Val(orig, TYPE_BOOL));
        vl->append(new Val(stream, TYPE_COUNT));
        vl->append(new StringVal(contentType));
        DEBUG_DBG("http2_begin_entity\n");
        this->ConnectionEvent(http2_begin_entity, vl);
    }
}

void HTTP2_Analyzer::HTTP2_EndEntity(bool orig, unsigned stream){
    if ( http2_end_entity ){
        val_list* vl = new val_list();
        vl->append(this->BuildConnVal());
        vl->append(new Val(orig, TYPE_BOOL));
        vl->append(new Val(stream, TYPE_COUNT));
        DEBUG_DBG("http2_end_entity\n");
        this->ConnectionEvent(http2_end_entity, vl);
    }
}

void HTTP2_Analyzer::HTTP2_EntityData(bool orig, unsigned stream, int len, const char* data){
    if ( http2_entity_data ){
        val_list* vl = new val_list();
        vl->append(this->BuildConnVal());
        vl->append(new Val(orig, TYPE_BOOL));
        vl->append(new Val(stream, TYPE_COUNT));
        vl->append(new Val(len, TYPE_COUNT));
        vl->append(new StringVal(len, data));
        DEBUG_DBG("http2_entity_data\n");
        this->ConnectionEvent(http2_entity_data, vl);
    }
}

void HTTP2_Analyzer::HTTP2_ContentType(bool orig, unsigned stream, std::string& contentType){
    if ( http2_content_type ){
        val_list* vl = new val_list();
        vl->append(this->BuildConnVal());
        vl->append(new Val(orig, TYPE_BOOL));
        vl->append(new Val(stream, TYPE_COUNT));
        vl->append(new StringVal(contentType));
        DEBUG_DBG("http2_content_type\n");
        this->ConnectionEvent(http2_content_type, vl);
    }
}

/* 
** Frame Processing Events
*/

void HTTP2_Analyzer::HTTP2_Data_Event(bool orig, unsigned stream, uint32_t len, const char* data){
    val_list* vl = new val_list();
    vl->append(this->BuildConnVal());
    vl->append(new Val(orig, TYPE_BOOL));
    vl->append(new Val(stream, TYPE_COUNT));
    vl->append(new Val(len, TYPE_COUNT));
    vl->append(new StringVal(len, data));
    DEBUG_INFO("http2_data_event\n");
    this->ConnectionEvent(http2_data_event, vl);
}

void HTTP2_Analyzer::HTTP2_Header_Event(bool orig, unsigned stream, uint32_t len, const char* headerData){
    val_list* vl = new val_list();
    vl->append(this->BuildConnVal());
    vl->append(new Val(orig, TYPE_BOOL));
    vl->append(new Val(stream, TYPE_COUNT));
    vl->append(new Val(len, TYPE_COUNT));
    vl->append(new StringVal(len, headerData));
    DEBUG_INFO("http2_header_event\n");
    this->ConnectionEvent(http2_header_event, vl);
}

void HTTP2_Analyzer::HTTP2_Priority_Event(bool orig, unsigned stream, bool exclusive, unsigned priStream, unsigned weight){
    val_list* vl = new val_list();
    vl->append(this->BuildConnVal());
    vl->append(new Val(orig, TYPE_BOOL));
    vl->append(new Val(stream, TYPE_COUNT));
    vl->append(new Val(exclusive, TYPE_BOOL));
    vl->append(new Val(priStream, TYPE_COUNT));
    vl->append(new Val(weight, TYPE_COUNT));
    DEBUG_INFO("http2_priority_event\n");
    this->ConnectionEvent(http2_priority_event, vl);
}

void HTTP2_Analyzer::HTTP2_RstStream_Event(bool orig, unsigned stream, const std::string& error){
    val_list* vl = new val_list();
    vl->append(this->BuildConnVal());
    vl->append(new Val(orig, TYPE_BOOL));
    vl->append(new Val(stream, TYPE_COUNT));
    vl->append(new StringVal(error));
    DEBUG_INFO("http2_rststream_event\n");
    this->ConnectionEvent(http2_rststream_event, vl);
}

void HTTP2_Analyzer::HTTP2_Settings_Event(bool orig, uint32_t stream, RecordVal* settingsRecord) {
    val_list* vl = new val_list();
    vl->append(this->BuildConnVal());
    vl->append(new Val(orig, TYPE_BOOL));
    vl->append(new Val(stream, TYPE_COUNT));
    vl->append(settingsRecord);
    DEBUG_INFO("http2_settings_event\n");
    this->ConnectionEvent(http2_settings_event, vl);
}

void HTTP2_Analyzer::HTTP2_PushPromise_Event(bool orig, unsigned stream, unsigned pushStream,
                                             uint32_t len, const char* headerData){
    val_list* vl = new val_list();
    vl->append(this->BuildConnVal());
    vl->append(new Val(orig, TYPE_BOOL));
    vl->append(new Val(stream, TYPE_COUNT));
    vl->append(new Val(pushStream, TYPE_COUNT));
    vl->append(new Val(len, TYPE_COUNT));
    vl->append(new StringVal(len, headerData));
    DEBUG_INFO("http2_pushpromise_event\n");
    this->ConnectionEvent(http2_pushpromise_event, vl);
}

void HTTP2_Analyzer::HTTP2_Ping_Event(bool orig, unsigned stream, uint8_t length, const char* data){
    val_list* vl = new val_list();
    vl->append(this->BuildConnVal());
    vl->append(new Val(orig, TYPE_BOOL));
    vl->append(new Val(stream, TYPE_COUNT));
    vl->append(new StringVal(length, data));
    DEBUG_INFO("http2_ping_event\n");
    this->ConnectionEvent(http2_ping_event, vl);
}

void HTTP2_Analyzer::HTTP2_GoAway_Event(bool orig, unsigned stream, unsigned lastStream,
                                        const std::string& error, uint32_t length, const char* data){
    val_list* vl = new val_list();
    vl->append(this->BuildConnVal());
    vl->append(new Val(orig, TYPE_BOOL));
    vl->append(new Val(stream, TYPE_COUNT));
    vl->append(new Val(lastStream, TYPE_COUNT));
    vl->append(new StringVal(error));
    DEBUG_INFO("http2_goaway_event\n");
    this->ConnectionEvent(http2_goaway_event, vl);
}

void HTTP2_Analyzer::HTTP2_WindowUpdate_Event(bool orig, unsigned stream, unsigned increment){
    val_list* vl = new val_list();
    vl->append(this->BuildConnVal());
    vl->append(new Val(orig, TYPE_BOOL));
    vl->append(new Val(stream, TYPE_COUNT));
    vl->append(new Val(increment, TYPE_COUNT));
    DEBUG_INFO("http2_windowupdate_event\n");
    this->ConnectionEvent(http2_windowupdate_event, vl);
}

void HTTP2_Analyzer::HTTP2_Continuation_Event(bool orig, unsigned stream, uint32_t len, const char* headerData){
    val_list* vl = new val_list();
    vl->append(this->BuildConnVal());
    vl->append(new Val(orig, TYPE_BOOL));
    vl->append(new Val(stream, TYPE_COUNT));
    vl->append(new Val(len, TYPE_COUNT));
    vl->append(new StringVal(len, headerData));
    DEBUG_INFO("http2_continuation_event\n");
    this->ConnectionEvent(http2_continuation_event, vl);
}

void HTTP2_Analyzer::HTTP2_Event(std::string& category, std::string& detail){
    if ( http2_event ){
        val_list* vl = new val_list();
        vl->append(this->BuildConnVal());
        vl->append(new StringVal(category));
        vl->append(new StringVal(detail));

        DEBUG_DBG("http2_event\n");
        this->ConnectionEvent(http2_event, vl);
    }
}
