#ifndef ANALYZER_PROTOCOL_HTTP2_HTTP2_FRAME_REASSEMBLER_H
#define ANALYZER_PROTOCOL_HTTP2_HTTP2_FRAME_REASSEMBLER_H

#include <vector>
#include "debug.h"
#include "HTTP2_Frame.h"

#include "util.h"

namespace analyzer { namespace http2 {

static constexpr size_t MIN_BUFFER_SIZE = 65535;
static constexpr size_t MAX_BUFFER_SIZE = 33554430; // ~32MB!!!
/**
 * class HTTP2_FrameReassembler
 * 
 * Description: class used to manage packet fragment reassembly and processing. 
 *
 */
class HTTP2_FrameReassembler{
public:
    HTTP2_FrameReassembler(void);
    ~HTTP2_FrameReassembler(void);


    /**
     * void analyzer/http2/HTTP2_FrameReassembler::resizeBuffer(uint32_t size)
     * 
     * Description: Function to resize the internal assembly buffer
     * Should be called/used when a settings frame updates
     * the maximum frame size, note that internal buffer starts out
     * at 65535 (see above) which is four times the default by spec
     * so if the size specified is less than that it will not increase
     * requests made from calling class should be two times the new
     * max frame size to allow for multiple frames in memory to be
     * somewhat safe. Even then an overflow situation could occur
     * triggering a fatal error
     *
     * 
     * @param size 
     */
    void resizeBuffer(uint32_t size);

    /**
     * std::vector<HTTP2_Frame*> analyzer/http2/HTTP2_FrameReassembler::process(const uint8_t *data, uint32_t len)
     * 
     * Description: Given raw packet data attempts to extract frames
     * from it Meant to be used per side (orig or not orig), so two
     * must be used to handle a full bi-directional transaction
     *
     * 
     * @param data reference to incoming packet
     * @param len length of the incoming packet
     * 
     * @return std::vector<HTTP2_Frame*> vector of HTTP2_Frame pointers
     *
     * Note! that if an error occurs the last frame pointer
     * could be nullptr. Frame re-assembly errors should be considered
     * fatal since this is a binary protocol, inability to decode a frame
     * means all subsequent frames are forfeit
     */
    std::vector<HTTP2_Frame*> process(const uint8_t* data, uint32_t len);

private:
    // Is packet stream currently fragmented?
    bool fragmentedPacket; 
    uint8_t* buffer;
    uint32_t bufferLen;
    uint32_t bufferSize;
    uint32_t copyLen;

    /**
     * HTTP2_Frame* analyzer/http2/HTTP2_FrameReassembler::loadFrame(HTTP2_FrameHeader *fh, uint8_t *payload, uint32_t len)
     * 
     * Description: Factory function that generates a frame from the 
     * given data. 
     *
     * 
     * @param fh 
     * @param payload 
     * @param len 
     * 
     * @return HTTP2_Frame pointer 
     *
     * If an error occurs in attempting to craft frame, it will return nullptr
     * This should be considered a fatal error
     */
    HTTP2_Frame* loadFrame(HTTP2_FrameHeader* fh, uint8_t* payload, uint32_t len);

    /**
     * void analyzer/http2/HTTP2_FrameReassembler::allocateBuffer(void)
     * 
     * Description: Allocates and initializes the data buffer, 
     * if it has not already been done.
     *
     * 
     * @param void 
     */
    void allocateBuffer(void);
    /**
     * void analyzer/http2/HTTP2_FrameReassembler::setBuffer(uint8_t *data, uint32_t len)
     * 
     * Description: Stores incoming fragment in data buffer.
     * Configures FrameReassembler for packet fragment assembly.
     *
     * 
     * @param data 
     * @param len 
     */
    void setBuffer(uint8_t* data, uint32_t len);
    /**
     * void analyzer/http2/HTTP2_FrameReassembler::appendBuffer(uint8_t *data, uint32_t len)
     * 
     * Description: Adds a new packet fragment to the data buffer.
     *
     * 
     * @param data 
     * @param len 
     */
    void appendBuffer(uint8_t* data, uint32_t len);
    /**
     * void analyzer/http2/HTTP2_FrameReassembler::clearBuffer(void)
     * 
     * Description: Resets data buffer indexing to start of data
     * buffer and configures FrameReassembler for unfragmented
     * packet processing.
     *
     * 
     * @param void 
     */
    void clearBuffer(void);

};

} } // namespace analyzer::* 

#endif
