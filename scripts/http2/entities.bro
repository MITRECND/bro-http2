##! Analysis and logging for MIME entities found in HTTP sessions.

@load base/utils/files
@load base/utils/strings
@load base/utils/files
@load ./main

module Http2;

export {
	type Entity: record {
		## Filename for the entity if discovered from a header.
		filename: string &optional;
	};

	redef record Info += {
		## An ordered vector of file unique IDs.
		orig_fuids:      vector of string &log &optional;

		## An ordered vector of filenames from the client.
		orig_filenames:  vector of string &log &optional;

		## An ordered vector of mime types.
		orig_mime_types: vector of string &log &optional;

		## An ordered vector of file unique IDs.
		resp_fuids:      vector of string &log &optional;

		## An ordered vector of filenames from the server.
		resp_filenames:  vector of string &log &optional;

		## An ordered vector of mime types.
		resp_mime_types: vector of string &log &optional;

		## The current entity.
		current_entity:  Entity           &optional;
		## Current number of MIME entities in the HTTP2 request message
		## body.
		orig_mime_depth: count            &default=0;
		## Current number of MIME entities in the HTTP2 response message
		## body.
		resp_mime_depth: count            &default=0;
	};

	redef record fa_file += {
		http2: HTTP2::Info &optional;
	};
}

##event http_begin_entity(c: connection, is_orig: bool) &priority=10
##	{
##	set_state(c, is_orig);
##
##	if ( is_orig )
##		++c$http$orig_mime_depth;
##	else
##		++c$http$resp_mime_depth;
##
##	c$http$current_entity = Entity();
##	}

##event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
##	{
##	if ( name == "CONTENT-DISPOSITION" &&
##	     /[fF][iI][lL][eE][nN][aA][mM][eE]/ in value )
##		{
##		c$http$current_entity$filename = extract_filename_from_content_disposition(value);
##		}
##	else if ( name == "CONTENT-TYPE" &&
##	          /[nN][aA][mM][eE][:blank:]*=/ in value )
##		{
##		c$http$current_entity$filename = extract_filename_from_content_disposition(value);
##		}
##	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
	if ( f$source == "HTTP2" && c?$http2 ) 
		{
		f$http2 = c$http;

		if ( c$http2?$current_entity && c$http2$current_entity?$filename )
			f$info$filename = c$http2$current_entity$filename;

		if ( f$is_orig )
			{
			if ( ! c$http2?$orig_fuids )
				c$http2$orig_fuids = string_vec(f$id);
			else
				c$http2$orig_fuids[|c$http2$orig_fuids|] = f$id;

			if ( f$info?$filename )
				{
				if ( ! c$http2?$orig_filenames )
					c$http2$orig_filenames = string_vec(f$info$filename);
				else
					c$http2$orig_filenames[|c$http2$orig_filenames|] = f$info$filename;
				}
			}

		else
			{
			if ( ! c$http2?$resp_fuids )
				c$http2$resp_fuids = string_vec(f$id);
			else
				c$http2$resp_fuids[|c$http2$resp_fuids|] = f$id;

			if ( f$info?$filename )
				{
				if ( ! c$http2?$resp_filenames )
					c$http2$resp_filenames = string_vec(f$info$filename);
				else
					c$http2$resp_filenames[|c$http2$resp_filenames|] = f$info$filename;
				}

			}
		}
	}

event file_sniff(f: fa_file, meta: fa_metadata) &priority=5
	{
	if ( ! f?$http2 || ! f?$is_orig )
		return;

	if ( ! meta?$mime_type )
		return;

	if ( f$is_orig )
		{
		if ( ! f$http2?$orig_mime_types )
			f$http2$orig_mime_types = string_vec(meta$mime_type);
		else
			f$http2$orig_mime_types[|f$http2$orig_mime_types|] = meta$mime_type;
		}
	else
		{
		if ( ! f$http2?$resp_mime_types )
			f$http2$resp_mime_types = string_vec(meta$mime_type);
		else
			f$http2$resp_mime_types[|f$http2$resp_mime_types|] = meta$mime_type;
		}
	}

##event http_end_entity(c: connection, is_orig: bool) &priority=5
##	{
##	if ( c?$http && c$http?$current_entity ) 
##		delete c$http$current_entity;
##	}
##
##
##
##
##
##
