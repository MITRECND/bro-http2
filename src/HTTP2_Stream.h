#ifndef ANALYZER_PROTOCOL_HTTP2_HTTP2_STREAM_H
#define ANALYZER_PROTOCOL_HTTP2_HTTP2_STREAM_H

#include "analyzer/protocol/zip/ZIP.h"
#include "util.h"
#include "decode.h"
#include "nghttp2.h"
#include "nghttp2ver.h"

#include "HTTP2_HeaderStorage.h"
#include "HTTP2_Frame.h"
#include "HTTP2.h"

using namespace std;

namespace analyzer { namespace http2 {
/* The currently supported stream states as specified in RFC-7540
 */
enum StreamState {
    // Stream States
    HTTP2_STREAM_STATE_IDLE,
    HTTP2_STREAM_STATE_OPEN,
    HTTP2_STREAM_STATE_HALF_CLOSED,
    HTTP2_STREAM_STATE_CLOSED
};
/* The currently supported Data Content Encoding types used in accordance with
** RFC-7540 and specified in IANA HTTP Content Coding Registry.
 */
enum DataEncoding {
    DATA_ENCODING_IDENTITY,
    DATA_ENCODING_AES128GCM,
    DATA_ENCODING_BROTLI,
    DATA_ENCODING_COMPRESS,
    DATA_ENCODING_DEFLATE,
    DATA_ENCODING_EXI,
    DATA_ENCODING_GZIP,
    DATA_ENCODING_PACK200GZIP
};


class HTTP2_Analyzer;

/*  This class represents common/shared functionality
    between client and server sides including processing of headers
    and data. It is meant to be inherited by child classes for
    actual usage
*/
class HTTP2_HalfStream {
public:
    HTTP2_HalfStream(HTTP2_Analyzer* analyzer, uint32_t stream_id, nghttp2_hd_inflater* inflater);
    virtual ~HTTP2_HalfStream();
    virtual void handleFrame(HTTP2_Frame* frame) = 0;
    virtual void handlePeerEndStream(void) = 0;
    virtual void handlePushRequested(void) = 0;
    bool isStreamEnded(void){return this->endStreamDetected;};
    bool isClosed(void){return this->state == HTTP2_STREAM_STATE_CLOSED;};
    size_t getDataSize(void) const {return this->data_size;};

protected:
    uint32_t id;
    bool isOrig;
    bool send_size;
    std::string precomputed_file_id;
    StreamState state;
    HTTP2_Analyzer* analyzer;
    nghttp2_hd_inflater* inflater;
    /**
     * bool analyzer/http2/HTTP2_HalfStream::processHeaders(uint8_t **headerBlockFragmentPtr, uint32_t &len, bool endHeaders, string &name, string &value)
     * 
     * Description: Uses the NGHTTP2 library to decompress the HTTP2
     * headers.
     * 
     * 
     * @param headerBlockFragmentPtr pointer to start of the data 
     *                               stream representing the header
     *                               block to be processed.
     * @param len                    the length of the data stream.
     * @param endHeaders             indication of whether or not 
     *                               this is the end of the header
     *                               block.
     * @param name                   Location to store the name of 
     *                               the next inflated header.
     * @param value                  Location to store the value of 
     *                               the next inflated header.
     * 
     * @return bool                  indication of whether or not a 
     *                               header was found and
     *                               decompressed.
     */
    bool processHeaders(uint8_t** headerBlockFragmentPtr, uint32_t& len, bool endHeaders, string& name, string& value);

    // Data Management
    int dataOffset;
    size_t dataBlockCnt;
    size_t data_size;
    zip::ZIP_Analyzer* zip;
    BrotliDecoderState* brotli;
    uint8_t brotli_buffer[MAX_FRAME_SIZE];


    /**
     * void SubmitData(int len, const char *buf)
     * 
     * Description: Submission of clear data messages to the file
     * manager for post processing.
     * 
     * @param len   The length of the message body.
     * @param buf   A reference to where the message body is stored.
     */
    void SubmitData(int len, const char* buf);
    /**
     * void EndofData(void)
     * 
     * Description: Notification to file manager that the message
     * submission has been completed.
     *
     */
    void EndofData(void);
    /**
     * void DeliverBody(int len, const char *data, int trailing_CRLF)
     * 
     * Description: Orchestrates content type encoding specific
     * processing on data frame message payloads. 
     * 
     * @param len 
     * @param data 
     * @param trailing_CRLF 
     */
    void DeliverBody(int len, const char* data, int trailing_CRLF);
    /**
     * void DeliverBodyClear(int len, const char *data, int trailing_CRLF)
     * 
     * Description: Orchestrates processing of post processed (e.g. 
     * clear text) data frame message payloads. 
     * 
     * @param len 
     * @param data 
     * @param trailing_CRLF 
     */
    void DeliverBodyClear(int len, const char* data, int trailing_CRLF);
    /**
     * void translateZipBody(int len, const char *data, int method)
     * 
     * Description: Handles decompressing of zip & deflate encoded 
     * data frame message payloads. 
     * 
     * @param len 
     * @param data 
     * @param method 
     */
    void translateZipBody(int len, const char* data, int method);
    /**
     * void translateBrotliBody(int len, const char *data)
     * 
     * Description: Handles decompressing of brotli encoded data 
     * frame message payloads. 
     * 
     * @param len 
     * @param data 
     */
    void translateBrotliBody(int len, const char* data);
    /**
     * void processData(HTTP2_Data_Frame *frame)
     * 
     * Description: Assigns a unique identifier to an incoming data 
     * frame message and posts events to indicate the beginning and 
     * end of the data message entity. 
     * 
     * @param frame 
     */
    void processData(HTTP2_Data_Frame* frame);

    int contentLength;
    DataEncoding contentEncodingId;
    std::string contentEncoding;
    std::string contentType;



    // Header Parsing Functions
    void parseContentEncoding(std::string& s);
    void extractDataInfoHeaders(std::string& name, std::string& value);

    class UncompressedOutput;
    friend class UncompressedOutput;

    bool endStreamDetected;
    bool peerStreamEnded;

    // Header Storage
    HTTP2_HeaderList hlist;

private:
    bool expectContinuation;
};

/* This class represents the processing of client traffic
*/
class HTTP2_OrigStream: public HTTP2_HalfStream {
public:
    HTTP2_OrigStream(HTTP2_Analyzer* analyzer, uint32_t stream_id, nghttp2_hd_inflater* inflater);
    virtual ~HTTP2_OrigStream();
    /**
     * handleFrame(HTTP2_Frame *frame)
     * 
     * Description: Perform state processing on a client frame.
     *
     * 
     * @param frame 
     */
    void handleFrame(HTTP2_Frame* frame);
    /**
     * void handlePushRequested(void)
     * 
     * Description: A Push Promise frame is only sent by the
     *  server and implies there is no header or data from the
     *  client. This function allows the client side to move to a
     *  different state
     *
     * 
     * @param void 
     */
    void handlePushRequested(void);
    /**
     * void handlePeerEndStream(void)
     * 
     * Description: Process notification of peer stream ending. 
     *
     * 
     * @param void 
     */
    void handlePeerEndStream(void);

private:

    void Idle_State(HTTP2_Frame* frame);
    void Open_State(HTTP2_Frame* frame);
    void Closed_State(HTTP2_Frame* frame);
    void ProcessHeaderBlock(HTTP2_Header_Frame_Base* header);
    void handleEndStream(void);

    // Pseudo Headers
    std::string request_method;
    std::string request_authority;
    std::string request_host;
    std::string request_path;
    std::string request_scheme;

};

/* This class represents the processing of server traffic
*/
class HTTP2_RespStream: public HTTP2_HalfStream {
public:
    HTTP2_RespStream(HTTP2_Analyzer* analyzer, uint32_t stream_id, nghttp2_hd_inflater* inflater);
    virtual ~HTTP2_RespStream();
    /**
     * void handleFrame(HTTP2_Frame *frame)
     * 
     * Description: Perform state processing on a server frame.
     *
     * 
     * @param frame 
     */
    void handleFrame(HTTP2_Frame* frame);
    /**
     * void handlePushRequested(void)
     * 
     * Description: Performs processing on a server push promise
     * request.
     *
     * 
     * @param void 
     */
    void handlePushRequested(void);
    /**
     * void handlePeerEndStream(void)
     * 
     * Description: Process notification of peer stream ending.
     *
     * 
     * @param void 
     */
    void handlePeerEndStream(void);

private:
    void Idle_State(HTTP2_Frame* frame);
    void Open_State(HTTP2_Frame* frame);
    void Closed_State(HTTP2_Frame* frame);
    void ProcessHeaderBlock(HTTP2_Header_Frame_Base* header);
    void handleEndStream(void);

    // Pseudo Headers
    uint16_t reply_status;
};

class HTTP2_Stream {
public:
    HTTP2_Stream(HTTP2_Analyzer* analyzer, uint32_t stream_id, nghttp2_hd_inflater* inflaters[2]);
    virtual ~HTTP2_Stream();

    // Stream Bookkeeping API
    uint32_t getId(){return this->id;};
    /**
     * bool handleFrame(HTTP2_Frame *f, bool orig)
     * 
     * Description: Routes frame to appropriate HTTP2_HalfStream for
     * processing.
     *
     * 
     * @param f 
     * @param orig 
     * 
     * @return bool 
     */
    bool handleFrame(HTTP2_Frame* f, bool orig);
    bool handleStreamEnd();

protected:

private:
    uint32_t id;
    bool streamReset;
    bool streamResetter;
    HTTP2_Analyzer* analyzer;
    nghttp2_hd_inflater* inflaters[2];
    HTTP2_HalfStream* halfStreams[2];
};

} } // namespace analyzer::* 

#endif
