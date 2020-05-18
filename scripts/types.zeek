export {
    type http2_settings_unrecognized_table: table[count] of count;

    type http2_settings: record {
                                    HEADER_TABLE_SIZE: count &optional;
                                    ENABLE_PUSH: bool &optional;
                                    MAX_CONCURRENT_STREAMS: count &optional;
                                    INITIAL_WINDOW_SIZE: count &optional;
                                    MAX_FRAME_SIZE: count &optional;
                                    MAX_HEADER_LIST_SIZE: count &optional;
                                    UNRECOGNIZED_SETTINGS: http2_settings_unrecognized_table;

    };

    type http2_stream_stat: record {
                                    request_body_length: count;
                                    response_body_length: count;
    };
}
