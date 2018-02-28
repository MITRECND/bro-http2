##! Implements base functionality for http2 analysis.
##! Generates the http2.log file.

module HTTP2;

export {
    redef enum Log::ID += { LOG };

    ## This setting changes if passwords used in Basic-Auth are captured or
    ## not.
    const default_capture_password = F &redef;

    type Info: record {
        ## Timestamp for when the event happened.
        ts:             time    &log;
        ## Unique ID for the connection.
        uid:            string  &log;
        ## The connection's 4-tuple of endpoint addresses/ports.
        id:     conn_id &log;

        ## Unique ID for the stream.
        stream_id:          count  &log &optional;
        
        ## Verb used in the HTTP request (GET, POST, HEAD, etc.).
        method:                  string    &log &optional;
        ## Value of the HOST header.
        host:                    string    &log &optional;
        ## URI used in the request.
        uri:                     string    &log &optional;
        ## Value of the "referer" header.  The comment is deliberately
        ## misspelled like the standard declares, but the name used here
        ## is "referrer" spelled correctly.
        referrer:                string    &log &optional;
        ## Value of the version portion of the request.
        version:                string     &log &optional;
        ## Value of the User-Agent header from the client.
        user_agent:              string    &log &optional;
        ## Actual uncompressed content size of the data transferred from
        ## the client.
        request_body_len:        count     &log &default=0;
        ## Actual uncompressed content size of the data transferred from
        ## the server.
        response_body_len:       count     &log &default=0;
        ## Status code returned by the server.
        status_code:             count     &log &optional;
        ## Status message returned by the server.
        status_msg:              string    &log &optional;
        ## Last seen 1xx informational reply code returned by the server.
        info_code:               count     &log &optional;
        ## Last seen 1xx informational reply message returned by the server.
        info_msg:                string    &log &optional;
        ## A set of indicators of various attributes discovered and
        ## related to a particular request/response pair.
        #tags:                    set[Tags] &log;

        ## Encoding Type.
        encoding:           string  &log &optional;

        ## Username if basic-auth is performed for the request.
        username:                string    &log &optional;
        ## Password if basic-auth is performed for the request.
        password:                string    &log &optional;

        ## Determines if the password will be captured for this request.
        capture_password:        bool      &default=default_capture_password;

        ## All of the headers that may indicate if the request was proxied.
        proxied:                 set[string] &log &optional;

        ## Indicates if this request can assume 206 partial content in
        ## response.
        range_request:           bool      &default=F;

        ## Whether this was a push transaction
        push:                    bool      &log &default=F;
    };

    type Streams: record {
        streams:     table[count] of Info;
        has_data: set[count];
    };

    ## Event that can be handled to access the http2 record as it is sent on
    ## to the loggin framework.
    global log_http2: event(rec: Info);

    const ports = { 80/tcp, 443/tcp } &redef;
}

# Add the http state tracking fields to the connection record.
redef record connection += {
    http2:          Info  &optional;
    http2_streams:  Streams &optional;
};


event bro_init() &priority=5
{
    Log::create_stream(HTTP2::LOG, [$columns=Info, $ev=log_http2, $path="http2"]);
    Analyzer::register_for_ports(Analyzer::ANALYZER_HTTP2, ports);
}


function code_in_range(c: count, min: count, max: count) : bool
{
    return c >= min && c <= max;
}

function setup_http2(c: connection)
{
    if ( ! c?$http2_streams ) {
        local s: Streams;
        c$http2_streams = s;

        #Also setup http2 so other scripts know this is an http2 connection
        local h: Info;
        c$http2 = h;
        c$http2$ts = network_time();
        c$http2$uid = c$uid;
        c$http2$id = c$id;
    }

}

function setup_http2_stream(c: connection, stream: count): Info
{
    setup_http2(c);
    if (stream !in c$http2_streams$streams) {
        local s: Info;
        s$ts = network_time();
        s$uid = c$http2$uid;
        s$id = c$http2$id;
        s$stream_id = stream;
        c$http2_streams$streams[stream] = s;
        return c$http2_streams$streams[stream];
    }
    else {
        return c$http2_streams$streams[stream];
   }
}

event http2_stream_start(c: connection, is_orig: bool, stream: count) &priority=5
{
    setup_http2_stream(c, stream);
    c$http2_streams$streams[stream]$stream_id = stream;
}

event http2_request(c: connection, is_orig: bool, stream: count, method: string, 
                    authority: string, host: string, original_URI: string,
                    unescaped_URI: string, version: string, push: bool) &priority=5
{
    add c$http2_streams$has_data[stream];
    c$http2_streams$streams[stream]$method = method;
    c$http2_streams$streams[stream]$host = host;
    c$http2_streams$streams[stream]$uri = unescaped_URI;
    c$http2_streams$streams[stream]$version = version;
    c$http2_streams$streams[stream]$push = push;

    if ( method !in HTTP::http_methods )
        event conn_weird("unknown_HTTP2_method", c, method);
}

event http2_reply(c: connection, is_orig: bool, stream: count, version: string,
                  code: count, reason: string) &priority=5
{
    add c$http2_streams$has_data[stream];
    if ( code_in_range(code, 100, 199) ) {
        c$http2_streams$streams[stream]$info_code = code;
        c$http2_streams$streams[stream]$info_msg = reason;
    } else {
        c$http2_streams$streams[stream]$status_code = code;
        c$http2_streams$streams[stream]$status_msg = reason;
    }
    c$http2_streams$streams[stream]$version = version;
}

event http2_stream_end(c: connection, stream: count, stats: http2_stream_stat) &priority=5
{
    c$http2_streams$streams[stream]$request_body_len = stats$request_body_length;
    c$http2_streams$streams[stream]$response_body_len = stats$response_body_length;
    Log::write(HTTP2::LOG, c$http2_streams$streams[stream]);
    delete c$http2_streams$streams[stream];
    delete c$http2_streams$has_data[stream];
}

event http2_header(c: connection, is_orig: bool, stream: count, name: string, value: string) &priority=5
{
    if ( is_orig ) # client headers
        {
        if ( name == "REFERER" )
            c$http2_streams$streams[stream]$referrer = value;

        else if ( name == "HOST" )
            # The split is done to remove the occasional port value that shows up here.
            c$http2_streams$streams[stream]$host = split_string1(value, /:/)[0];

        else if ( name == "RANGE" )
            c$http2_streams$streams[stream]$range_request = T;

        else if ( name == "USER-AGENT" )
            c$http2_streams$streams[stream]$user_agent = value;

        else if ( name in HTTP::proxy_headers )
                {
                if ( ! c$http2_streams$streams[stream]?$proxied )
                    c$http2_streams$streams[stream]$proxied = set();
                add c$http2_streams$streams[stream]$proxied[fmt("%s -> %s", name, value)];
                }

        else if ( name == "AUTHORIZATION" || name == "PROXY-AUTHORIZATION" )
            {
            if ( /^[bB][aA][sS][iI][cC] / in value )
                {
                local userpass = decode_base64_conn(c$id, sub(value, /[bB][aA][sS][iI][cC][[:blank:]]/, ""));
                local up = split_string(userpass, /:/);
                if ( |up| >= 2 )
                    {
                    c$http2_streams$streams[stream]$username = up[0];
                    if ( c$http2_streams$streams[stream]$capture_password )
                        c$http2_streams$streams[stream]$password = up[1];
                    }
                else
                    {
                    c$http2_streams$streams[stream]$username = fmt("<problem-decoding> (%s)", value);
                    if ( c$http2_streams$streams[stream]$capture_password )
                        c$http2_streams$streams[stream]$password = userpass;
                    }
                }
            }
        } else {

        if ( name == "CONTENT-ENCODING" )
            {
                c$http2_streams$streams[stream]$encoding = value;
            }
        }

}

event connection_state_remove(c: connection)
{
    if (!c?$http2_streams) {
        return;
    }

    for (stream in c$http2_streams$streams) {
        if (stream in c$http2_streams$has_data) {
            Log::write(HTTP2::LOG, c$http2_streams$streams[stream]);
        }
    }

}
