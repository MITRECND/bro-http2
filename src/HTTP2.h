#ifndef ANALYZER_PROTOCOL_HTTP2_HTTP2_H
#define ANALYZER_PROTOCOL_HTTP2_HTTP2_H

#include <string>
#include <unordered_map>
#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/tcp/ContentLine.h"
#include "analyzer/protocol/pia/PIA.h"
#include "analyzer/protocol/zip/ZIP.h"
#include "analyzer/protocol/mime/MIME.h"
#include "IPAddr.h"
#include "events.bif.h"
#include "http2.bif.h"
#include "debug.h"
#include "Reporter.h"


#include "HTTP2_FrameReassembler.h"
#include "HTTP2_Stream.h"
#include "HTTP2_Frame.h"

#include "nghttp2.h"
#include "nghttp2ver.h"

using namespace std;

namespace analyzer { namespace mitrecnd {


class HTTP2_Stream;
class HTTP2_HalfStream;

class HTTP2_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
    HTTP2_Analyzer(Connection* conn);
    virtual ~HTTP2_Analyzer();

    // Overriden from Analyzer.
    virtual void Done();

    /**
     * void HTTP2_Analyzer::DeliverStream(int len, const u_char *data, bool orig)
     *
     * Description: Point of injection for the TCP stream. This does
     * not include the TCP header only the payload.
     *
     *
     * @param len   The length of the incoming data stream
     * @param data  A reference to the stream data
     * @param orig  Flag indicating whether the stream came from the
     *              originator or receiver.
     */
    virtual void DeliverStream(int len, const u_char* data, bool orig);
    /**
     * void HTTP2_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
     *
     * Description:
     *
     *
     * @param seq
     * @param len
     * @param orig  Flag indicating whether the stream came from the
     *              originator or receiver.
     */
    virtual void Undelivered(uint64_t seq, int len, bool orig);

    // Overriden from tcp::TCP_ApplicationAnalyzer.
    /**
     * void HTTP2_Analyzer::EndpointEOF(bool is_orig)
     *
     * Description:
     *
     *
     * @param is_orig   Flag indicating whether the stream came from
     *                  the originator or receiver.
     */
    virtual void EndpointEOF(bool is_orig);

    static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
        { return new HTTP2_Analyzer(conn); }

    // Utility
    void deactivateConnection(void) {connectionActive = false;};

    // Bro Events
    /**
     * void HTTP2_Analyzer::HTTP2_Request(bool orig, unsigned
     * stream, std::string method, std::string authority,
     * std::string  host, std::string path,  Val*  unescaped,
     * bool push=false)
     *
     * Description: Notification to Bro that an HTTP2 Request event
     * has occurred.
     *
     *
     * @param orig      Flag indicating whether the stream came from the
     *                  originator or receiver.
     * @param stream    unique identifier for the stream.
     * @param method    description of the request method
     * @param authority description of the request authority
     * @param host      description of the request host
     * @param path      description of the request path
     * @param unescaped description of the request unescaped path
     * @param push      Whether this is a push promise transaction or not
     */
    void HTTP2_Request(bool orig, unsigned stream, std::string& method,
                       std::string& authority, std::string&  host,
                       std::string& path,  BroString*  unescaped,
                       bool push=false);
    /**
     * void HTTP2_Analyzer::HTTP2_Reply(bool orig, unsigned stream, Val *status)
     *
     * Description: Notification to Bro that an HTTP2 Reply event
     * has occurred.
     *
     *
     * @param orig      Flag indicating whether the stream came from the
     *                  originator or receiver.
     * @param stream    unique identifier for the stream.
     * @param status    reply status code
     */
    void HTTP2_Reply(bool orig, unsigned stream, uint16_t status);
    /**
     * void HTTP2_Analyzer::HTTP2_StreamStart(bool orig, unsigned stream)
     *
	 * Description: Notification to Bro that an HTTP2 Stream has
	 * been created.
     *
     *
     * @param orig      Flag indicating whether the stream came from the
     *                  originator or receiver.
     * @param stream    unique identifier for the stream.
     */
    void HTTP2_StreamStart(bool orig, unsigned stream);
    /**
     * void HTTP2_Analyzer::HTTP2_StreamEnd(bool orig, unsigned stream)
     *
	 * Description: Notification to Bro that an HTTP2 Stream has
	 * ended.
     *
     *
     * @param orig      Flag indicating whether the stream came from the
     *                  originator or receiver.
     * @param stream    unique identifier for the stream.
     */
    void HTTP2_StreamEnd(unsigned stream, RecordVal* stream_stats);
    /**
     * Description: Notification to Bro that an HTTP2 Header event
     * has occurred.
     *
     *
     * @param orig      Flag indicating whether the stream came from the
     *                  originator or receiver.
     * @param stream    unique identifier for the stream.
     * @param name      the name of the header
     * @param value     the value of the header
     *
     */
    void HTTP2_Header(bool orig, unsigned stream, std::string& name, std::string& value);
    /**
     * void HTTP2_Analyzer::HTTP2_AllHeaders(bool orig, unsigned stream, HTTP2_HeaderList *hlist)
     *
     * Description: Notification to Bro that an HTTP2 All Headers event
     * has occurred.
     *
     *
     * @param orig      Flag indicating whether the stream came from the
     *                  originator or receiver.
     * @param stream    unique identifier for the stream.
     * @param hlist     reference to list of header name value pairs.
     */
    void HTTP2_AllHeaders(bool orig, unsigned stream, TableVal* hlist);
    /**
     * void HTTP2_Analyzer::HTTP2_BeginEntity(bool orig, unsigned
     * stream, std::string contentType)
     *
     * Description: Notification to Bro that an HTTP2 Message Entity
     * has been created.
     *
     *
     * @param orig      Flag indicating whether the stream came from the
     *                  originator or receiver.
     * @param stream    unique identifier for the stream.
     * @param contentType   description of the message body content
     *                      (e.g. application, text, html)
     */
    void HTTP2_BeginEntity(bool orig, unsigned stream, std::string& contentType);
    /**
     * void HTTP2_Analyzer::HTTP2_EndEntity(bool orig, unsigned stream)
     *
     * Description: Notification to Bro that an HTTP2 Message Entity
     * has completed processing.
     *
     *
     * @param orig      Flag indicating whether the stream came from the
     *                  originator or receiver.
     * @param stream    unique identifier for the stream.
     */
    void HTTP2_EndEntity(bool orig, unsigned stream);
    /**
     * void HTTP2_Analyzer::HTTP2_EntityData(bool orig, unsigned stream, int len, const char *data)
     *
     * Description: Notification to Bro that an HTTP2 Message Entity
     * block has been processed.
     *
     *
     * @param orig      Flag indicating whether the stream came from the
     *                  originator or receiver.
     * @param stream    unique identifier for the stream.
     * @param len       length of the entity message data
     * @param data      reference to the data
     */
    void HTTP2_EntityData(bool orig, unsigned stream, int len, const char* data);
    /**
     * void HTTP2_Analyzer::HTTP2_ContentType(bool orig, unsigned
     * stream, std::string contentType)
     *
     * Description: Notification to Bro that an HTTP2 Message Entity
     * content type has been updated.
     *
     *
     * @param orig          Flag indicating whether the stream came from the
     *                      originator or receiver.
     * @param stream        unique identifier for the stream.
     * @param contentType   description of the message body content
     *                      (e.g. application, text, html)
     */
    void HTTP2_ContentType(bool orig, unsigned stream, std::string& contentType);
    /**
     * void HTTP2_Analyzer::HTTP2_Data_Event(bool orig,
     *                                       unsigned stream,
     *                                       std::string
     *                                       encodingType)
     *
     * Description: Notification to Bro that an HTTP2 Message Entity
     * data event has occured. (i.e. a block of entity message body
     * data has been posted to the file manager)
     *
     *
     * @param orig          Flag indicating whether the stream came
     *                      from the originator or receiver.
     * @param stream        unique identifier for the stream.
     * @param encodingType  The encoding type of the data message.
     */
    void HTTP2_Data_Event(bool orig, unsigned stream, uint32_t len, const char* data);
    /**
	 * void HTTP2_Analyzer::HTTP2_Header_Event(bool orig, unsigned
	 * stream, uint32_t len, const char *headerData)
     *
	 * Description: Notification to Bro that an HTTP2 Header frame
	 * has been received.
     *
     * @param orig          Flag indicating whether the stream came
     *                      from the originator or receiver.
     * @param stream        unique identifier for the stream.
     * @param len           length of the frame header.
     * @param headerData    contents of the frame header.
     */
    void HTTP2_Header_Event(bool orig, unsigned stream, uint32_t len, const char* headerData);
    /**
     * void HTTP2_Analyzer::HTTP2_Priority_Event(bool orig, unsigned stream, bool exclusive, unsigned priStream, unsigned weight)
     *
     * Description: Notification to Bro that an HTTP2 Priority frame
     * has been received.
     *
     * @param orig      Flag indicating whether the stream came from the
     *                  originator or receiver.
     * @param stream    unique identifier for the stream.
	 * @param exclusive indication of whether or not the priority is
	 *  				exclusive.
	 * @param priStream the stream id associated with the stream
	 *					that the receiving stream depends on.
	 * @param weight    used to determine the relative proportion of
	 *  				available resources that are assigned to
	 *  				streams dependent on the same stream.
     */
    void HTTP2_Priority_Event(bool orig, unsigned stream, bool exclusive, unsigned priStream, unsigned weight);
    /**
     * void HTTP2_Analyzer::HTTP2_RstStream_Event(bool orig, unsigned stream, const char *error)
     *
     * Description: Notification to Bro that an HTTP2 Reset Stream
     * frame has been received.
     *
     *
     * @param orig      Flag indicating whether the stream came from the
     *                  originator or receiver.
     * @param stream    unique identifier for the stream.
     * @param error     reason for the reset stream event.
     */
    void HTTP2_RstStream_Event(bool orig, unsigned stream, const std::string& error);
    /**
     * void HTTP2_Analyzer::HTTP2_Settings_Event(bool orig, unsigned stream, RecordVal* settingsRecord)
     *
     * Description: Notification to Bro that an HTTP2 Settings frame
     * has been received.
     *
     *
	 * @param orig            Flag indicating whether the stream
	 *  				      came from the originator or receiver.
     * @param stream          unique identifier for the stream.
     * @param settingsRecord  current settings configuration.
     */
    void HTTP2_Settings_Event(bool orig, uint32_t stream, RecordVal* settingsRecord);
    /**
     * void HTTP2_Analyzer::HTTP2_PushPromise_Event(bool orig, unsigned stream, unsigned pushStream)
     *
     * Description: Notification to Bro that an HTTP2 Push Promise
     * frame has been received.
     *
     *
	 * @param orig        Flag indicating whether the stream came
	 *  				  from the originator or receiver.
	 * @param stream      unique identifier for the stream, for
	 *  				  which the push promised was received on.
	 * @param pushStream  unique identifier for the stream, for
	 *  				  which the push promise was made.
     * @param len         length of the frame header.
     * @param headerData  contents of the frame header.
     */
    void HTTP2_PushPromise_Event(bool orig, unsigned stream, unsigned pushStream, uint32_t len, const char* headerData);
    /**
     * void HTTP2_Analyzer::HTTP2_Ping_Event(bool orig, unsigned stream, const char *data)
     *
     * Description: Notification to Bro that an HTTP2 Ping frame
     * has been received.
     *
     *
     * @param orig      Flag indicating whether the stream came from the
     *                  originator or receiver.
     * @param stream    unique identifier for the stream.
     * @param length    length of the opaque data
     * @param data      opaque data
     */
    void HTTP2_Ping_Event(bool orig, unsigned stream, uint8_t length, const char* data);
    /**
     * void HTTP2_Analyzer::HTTP2_GoAway_Event(bool orig, unsigned stream, unsigned lastStream, const char *error)
     *
     * Description: Notification to Bro that an HTTP2 Go Away frame
     * has been received.
     *
     *
	 * @param orig        Flag indicating whether the stream came
	 *  				  from the originator or receiver.
     * @param stream      unique identifier for the stream.
	 * @param lastStream  unique identifier for the last valid
	 *  				  stream.
	 * @param error       reason for the goaway event.
	 * @param length      length of debug data.
	 * @param data        debug data.
	 *
     */
    void HTTP2_GoAway_Event(bool orig, unsigned stream, unsigned lastStream, const std::string& error, uint32_t length, const char* data);
    /**
     * void HTTP2_Analyzer::HTTP2_WindowUpdate_Event(bool orig, unsigned stream, unsigned increment)
     *
     * Description: Notification to Bro that an HTTP2 Window Update
     * frame has been received.
     *
     *
     * @param orig      Flag indicating whether the stream came from the
     *                  originator or receiver.
     * @param stream    unique identifier for the stream.
	 * @param increment change to the flow control window size.
     */
    void HTTP2_WindowUpdate_Event(bool orig, unsigned stream, unsigned increment);
    /**
     * void HTTP2_Analyzer::HTTP2_Continuation_Event(bool orig, unsigned stream)
     *
     * Description: Notification to Bro that an HTTP2 Continuation
     * frame has been received.
     *
     *
	 * @param orig        Flag indicating whether the stream came
	 *  				  from the originator or receiver.
	 * @param stream      unique identifier for the stream.
     * @param len         length of the frame header.
     * @param headerData  contents of the frame header.
     */
    void HTTP2_Continuation_Event(bool orig, unsigned stream, uint32_t len, const char* headerData);
    /**
     * void HTTP2_Analyzer::HTTP2_Event(std::string& category,
     * std::string& detail)
     *
     * Description: Indication that an HTTP2 event has occured.
     *
     *
     * @param category  description of the category of event
     * @param detail    event details
     */
    void HTTP2_Event(std::string& category, std::string& detail);

protected:

    bool had_gap;
    bool connectionActive;
    bool protocol_errored;

private:

    // Inflater Management
    void initInflaters();
    void deleteInflaters();

    // Stream Management
    void initStreams();
    void destroyStreams();
    HTTP2_Stream* getStream(uint32_t stream_id, bool orig);
    void removeStream(HTTP2_Stream* s);
    void flushStreams(uint32_t id);

	// Packet fragmentation management.
    void initReassemblers(void);
    void destroyReassemblers(void);

    double request_version, reply_version;

    /**
     * bool connectionPrefaceDetected(int len, const u_char *data)
     *
     * Description: Indication of whether or not the HTTP2
     * connection preface has been detected within the supplied data
     * stream.
     *
     *
     * @param len  length of data array
     * @param data reference to data stream.
     *
     * @return bool indication of detection.
     */
    bool connectionPrefaceDetected(int len, const u_char* data);

    /**
     * void analyzer/http2/HTTP2_Analyzer::handleFrameEvents(HTTP2_Frame *frame, bool orig, uint32_t stream_id)
     *
	 * Description: Manages Posting of Bro events associated with
	 * incoming frames on non-stream0 streams.
     *
	 * @param frame   handle to frame, to which event should be
	 *  			  associated.
	 * @param orig    Flag indicating whether the stream came from
	 *  			  the originator or receiver.
	 * @param stream  unique identifier for the stream.
     */
    void handleFrameEvents(HTTP2_Frame* frame, bool orig, uint32_t stream_id);

    // Stream 0 functions
    void handleStream0(HTTP2_Frame* frame, bool orig);
    void handleSettings(HTTP2_Settings_Frame* frame, bool orig);
    void handleGoAway(HTTP2_GoAway_Frame* frame, bool orig);
    void handlePing(HTTP2_Ping_Frame* frame, bool orig);
    void handleWindowUpdate(HTTP2_WindowUpdate_Frame* frame, bool orig);

    // Connection State
    uint32_t headerTableSize;
    bool pushEnabled;
    uint32_t maxFrameSize;
    uint32_t initialWindowSize;
    int64_t maxConcurrentStreams;
    int64_t maxHeaderListSize;
    uint32_t lastStreams[2];
    uint32_t goAwayStream;

    HTTP2_FrameReassembler* reassemblers;
    nghttp2_hd_inflater* inflaters[2];
    std::unordered_map<uint32_t, HTTP2_Stream*> streams;
};

} } // namespace analyzer::*

#endif
