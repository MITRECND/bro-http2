@load ./main
@load ./utils
@load base/utils/conn-ids
@load base/frameworks/files

module HTTP2;

export {
	## Default file handle provider for HTTP2.
	global get_file_handle: function(c: connection, is_orig: bool): string;

	## Default file describer for HTTP2.
	global describe_file: function(f: fa_file): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	if ( ! c?$http2 )
		return "";

    return cat(Analyzer::ANALYZER_HTTP2, is_orig, c$id$orig_h, build_url(c$http2));
	}

function describe_file(f: fa_file): string
	{
	# This shouldn't be needed, but just in case...
	if ( f$source != "HTTP2" )
		return "";

	for ( cid in f$conns )
		{
		if ( f$conns[cid]?$http2 )
			return build_url_http2(f$conns[cid]$http2);
		}
	return "";
	}

event zeek_init() &priority=5
	{
	Files::register_protocol(Analyzer::ANALYZER_HTTP2,
	                         [$get_file_handle = HTTP2::get_file_handle,
	                          $describe        = HTTP2::describe_file]);
	}


