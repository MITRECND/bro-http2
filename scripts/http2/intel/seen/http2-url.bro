@load base/frameworks/intel
@load ../../utils
@load policy/frameworks/intel/seen/where-locations


export {
    redef enum Intel::Where += {
        HTTP2::IN_URL,
    };
}

# Priority is set to 6 since the code in main deletes the data!
event http2_stream_end(c: connection, stream: count, stats: http2_stream_stat) &priority=6
{
    if (!c?$http2_streams || !c$http2_streams?$has_data){
        return;
    }

    if (stream in c$http2_streams$has_data && stream in c$http2_streams$streams) {
        Intel::seen([$indicator=HTTP2::build_url(c$http2_streams$streams[stream]),
                     $indicator_type=Intel::URL,
                     $conn=c,
                     $where=HTTP2::IN_URL]);
    }
}

# In case this was an unfinished connection
event connection_state_remove(c: connection) &priority=6
{
    if (!c?$http2_streams || !c$http2_streams?$has_data) {
        return;
    }

    for (stream in c$http2_streams$streams) {
        if (stream in c$http2_streams$has_data) {
            Intel::seen([$indicator=HTTP2::build_url(c$http2_streams$streams[stream]),
                         $indicator_type=Intel::URL,
                         $conn=c,
                         $where=HTTP2::IN_URL]);
        }
    }
}
