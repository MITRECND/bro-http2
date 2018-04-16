#include <vector>
#include <string.h>
#include "HTTP2_FrameReassembler.h"
#include "nghttp2.h"
#include "nghttp2ver.h"
#include "debug.h"
#include "Reporter.h"

using namespace analyzer::mitrecnd;

HTTP2_FrameReassembler::HTTP2_FrameReassembler()
{
    this->buffer = NULL;
    this->bufferLen = 0;
    this->bufferSize = MIN_BUFFER_SIZE;
    this->fragmentedPacket = false;
    this->copyLen = 0;
}

HTTP2_FrameReassembler::~HTTP2_FrameReassembler(void)
{
    if(this->buffer) {
        free(this->buffer);
    }
}

void HTTP2_FrameReassembler::resizeBuffer(uint32_t size)
{
    if (size <= MAX_BUFFER_SIZE){
        if (size > this->bufferSize){
            uint32_t newSize = sizeof(uint8_t) * size;
            if (this->buffer){
                this->buffer = (uint8_t*) realloc(this->buffer, newSize);
            }
            this->bufferSize = newSize;
        }
    } else {
        // Not much to be done
        // Leave the buffer as is, if the data being
        // reassembled is too big, the assembly sequence will
        // punt upstream
    }
}

void HTTP2_FrameReassembler::allocateBuffer(void)
{
    if (!this->buffer){
        this->buffer = (uint8_t*) malloc(sizeof(uint8_t) * this->bufferSize);
        this->bufferLen = 0;
    }
}

void HTTP2_FrameReassembler::setBuffer(uint8_t* data, uint32_t len)
{
    this->allocateBuffer();
    memcpy(this->buffer, data, len);
    this->fragmentedPacket = true;
    this->bufferLen = len;
}

void HTTP2_FrameReassembler::appendBuffer(uint8_t* data, uint32_t len)
{
    memcpy(this->buffer + this->bufferLen, data, len);
    this->bufferLen += len;
}

void HTTP2_FrameReassembler::clearBuffer(void)
{
    this->bufferLen = 0;
    this->fragmentedPacket = false;
}

vector<HTTP2_Frame*> HTTP2_FrameReassembler::process(const uint8_t* data, uint32_t len)
{
    vector<HTTP2_Frame*> processed_frames;
    uint8_t* cursor = (uint8_t*) data;
    uint32_t dataLen = len;

    while (dataLen > 0) {
        // Currently not dealing with fragmented data
        if (!this->fragmentedPacket) {
            // Data too small for even a frame header
            if (dataLen < FRAME_HEADER_LENGTH) {
                this->setBuffer(cursor, dataLen);
                dataLen = 0;
                this->copyLen = 0; // Not sure how big frame is yet!
            }else { // dataLen >= FRAME_HEADER_LENGTH
                HTTP2_FrameHeader* fh = new HTTP2_FrameHeader(cursor);
                uint32_t frame_length = FRAME_HEADER_LENGTH + fh->getLen();

                if (dataLen >= frame_length) { // Full frame in data
                    HTTP2_Frame* frame = this->loadFrame(fh, cursor + FRAME_HEADER_LENGTH, fh->getLen());
                    processed_frames.push_back(frame);
                    if (!frame) {
                        // There was an issue processing a frame
                        // break out and return immediately so analyzer can handle issue
                        // inability to process a frame from a stream is a fatal error
                        break;
                    }
                    cursor += frame_length;
                    dataLen -= frame_length;
                }else{ // Not enough for full frame, must buffer up data
                    delete fh; // clean up
                    this->setBuffer(cursor, dataLen);
                    dataLen = 0;
                    // How much do we need to copy to complete the frame.
                    this->copyLen = frame_length - this->bufferLen;
                }
            }
        } else { // Fragmented data in buffer
            // Copy data into buffer to deal with it
            if ((this->bufferLen + dataLen) > this->bufferSize){
                // The buffer size is tracked by the traffic so it should be 2x the max frame size
                // running into this situation shouldn't happen so consider it a fatal error
                DEBUG_ERR("Fragmented Data Buffer Overflow :%d!\n",(this->bufferLen + dataLen));
                processed_frames.push_back(nullptr);
                break;
            } else {
                uint32_t oldBufferLen = this->bufferLen;
                
                // Selectively copy data to minimize bytes copied
                if ((this->copyLen == 0) || (this->copyLen >= dataLen)){
                    // If we don't know how much to copy yet or the amount we 
                    // need is more than supplied then just copy what is available.
                    this->appendBuffer(cursor, dataLen);
                }
                else{
                    // Only copy what is needed to complete the frame. The excess 
                    // just gets flushed, so why waste the copies.
                    this->appendBuffer(cursor, copyLen);
                }

                if (this->bufferLen < FRAME_HEADER_LENGTH) { // still too small?
                    dataLen = 0;
                } else {
                    HTTP2_FrameHeader* fh = new HTTP2_FrameHeader(this->buffer);
                    uint32_t frame_length = FRAME_HEADER_LENGTH + fh->getLen();

                    if (this->bufferLen >= frame_length){ // Full frame in buffer
                        HTTP2_Frame* frame = this->loadFrame(fh, this->buffer + FRAME_HEADER_LENGTH, fh->getLen());
                        processed_frames.push_back(frame);
                        if (!frame){
                            // There was an issue processing a frame
                            // break out and return immediately so analyzer can handle issue
                            // inability to process a frame from a stream is a fatal error
                            break;
                        }
                        // Determine if any data left in buffer
                        uint32_t diff = frame_length - oldBufferLen;
                        // oldBufferLen should always be smaller than the frame length
                        // double-check! 
                        if (frame_length <= oldBufferLen ) {
                            DEBUG_ERR("Fragmented Frame Processing Error! frame_length:%d Old Buffer Length:%d\n", frame_length, oldBufferLen);
                            processed_frames.push_back(nullptr);
                            break;
                        }
                        cursor += diff;
                        dataLen -= diff;
                        this->clearBuffer();
                    }else{ // Not enough for full frame, must buffer up data
                        delete fh; // clean up
                        dataLen = 0;
                        // How much do we need to copy to complete the frame.
                        this->copyLen = frame_length - this->bufferLen;
                    }
                }
            }
        }
    }

    return processed_frames;
}

HTTP2_Frame* HTTP2_FrameReassembler::loadFrame(HTTP2_FrameHeader* fh, uint8_t* payload, uint32_t len)
{
    HTTP2_Frame* frame = nullptr;

    switch (fh->getType()) {
        case NGHTTP2_DATA:
            frame = new HTTP2_Data_Frame(fh, payload, len);
            break;
        case NGHTTP2_HEADERS:
            frame = new HTTP2_Header_Frame(fh, payload, len);
            break;
        case NGHTTP2_PRIORITY:
            frame = new HTTP2_Priority_Frame(fh, payload, len);
            break;
        case NGHTTP2_RST_STREAM:
            frame = new HTTP2_RstStream_Frame(fh, payload, len);
            break;
        case NGHTTP2_SETTINGS:
            frame = new HTTP2_Settings_Frame(fh, payload, len);
            break;
        case NGHTTP2_PUSH_PROMISE:
            frame = new HTTP2_PushPromise_Frame(fh, payload, len);
            break;
        case NGHTTP2_PING:
            frame = new HTTP2_Ping_Frame(fh, payload, len);
            break;
        case NGHTTP2_GOAWAY:
            frame = new HTTP2_GoAway_Frame(fh, payload, len);
            break;
        case NGHTTP2_WINDOW_UPDATE:
            frame = new HTTP2_WindowUpdate_Frame(fh, payload, len);
            break;
        case NGHTTP2_CONTINUATION:
            frame = new HTTP2_Continuation_Frame(fh, payload, len);
            break;
        default:
            DEBUG_ERR("Invalid Frame Type!: %d\n", fh->getType());
            break;
    }

    if(frame && !frame->validate()){
        delete frame;
        frame = nullptr;
    }

    return frame;
}
