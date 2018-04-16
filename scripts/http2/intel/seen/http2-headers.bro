@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations
@load base/utils/addrs

export {
    redef enum Intel::Where += {
        HTTP2::IN_AUTHORITY,
        HTTP2::IN_REFERRER_HEADER,
        HTTP2::IN_X_FORWARDED_FOR_HEADER,
        HTTP2::IN_USER_AGENT_HEADER
    };
}

event http2_request(c: connection, is_orig: bool, stream: count, method: string, authority: string, host: string, original_URI: string, unescaped_URI: string, version: string, push: bool) {
    if (is_valid_ip(host)) {
        Intel::seen([$host=to_addr(host),
                     $indicator_type=Intel::ADDR,
                     $conn=c,
                     $where=HTTP2::IN_AUTHORITY]);
    } else {
        Intel::seen([$indicator=host,
                     $indicator_type=Intel::DOMAIN,
                     $conn=c,
                     $where=HTTP2::IN_AUTHORITY]);
    }
}

event http2_header(c: connection, is_orig: bool, stream: count, name: string, value: string) {
    if (is_orig) {
        switch (name) {
            case "REFERER":
                Intel::seen([$indicator=sub(value, /^.*:\/\//, ""),
                             $indicator_type=Intel::URL,
                             $conn=c,
                             $where=HTTP::IN_REFERRER_HEADER]);
                break;
            case "X-FORWARDED-FOR":
                if (is_valid_ip(value)) {
                    local addrs = extract_ip_addresses(value);
                    for (i in addrs) {
                        Intel::seen([$host=to_addr(addrs[i]),
                                     $indicator_type=Intel::ADDR,
                                     $conn=c,
                                     $where=HTTP2::IN_X_FORWARDED_FOR_HEADER]);
                    }
                }
                break;
            case "USER-AGENT":
                Intel::seen([$indicator=value,
                             $indicator_type=Intel::SOFTWARE,
                             $conn=c,
                             $where=HTTP2::IN_USER_AGENT_HEADER]);
                break;
        }
    }
}
