# Zeek HTTP2 Analyzer Plugin

This plugin provides an HTTP2 ([RFC 7540](https://tools.ietf.org/html/rfc7540))
decoder/analyzer for [Zeek](https://www.zeek.org/) 3.0.x and 3.1.x. If you need
this capability for older instances of Zeek (Bro), i.e., 2.6.x or older, please
refer to the last `0.4.x` release of this plugin.

The events exposed attempt to mimic the events exposed by the native HTTP analyzer

------

## Installation

### Requirements

#### Nghttp2

Nghttp2 1.11.0 or greater is required. The plugin uses the decompression
libraries and some portions of the API used are not supported prior to that
version.

    nghttp2 Library - https://github.com/nghttp2/nghttp2

On CentOS 7:

    # sudo yum install libnghttp2-devel

On Ubuntu 16.04:

The version of `libnghttp-dev` on Ubuntu's apt repositories is too
old (version 1.7.1 as of when this was written) so you must install the library
manually from the [repo](https://github.com/nghttp2/nghttp2/releases/latest).

#### Brotli

Brotli is required as it is used quite often by popular websites and the
analyzer automatically attempts to decompress data frames. No pre-compiled
packages could be found for the brotli library so it will need to be manually
built and installed. The library can be found at
<https://github.com/google/brotli>. The latest release can be found at
<https://github.com/google/brotli/releases/latest>. After downloading the latest
release, follow these steps to compile and install the library:

    tar -zxvf <release file>
    cd brotli-<version>
    mkdir build && cd build
    ../configure-cmake
    make
    make test
    make install

### Manual Installation

To manually build and install the plugin:

    cd <HTTP2 Plugin Directory>
    rm -r build # Only if build exists
    ./configure --zeek-dist=</path/to/zeek/source>
    make
    make test
    make install

### Zeek Package Manager

The Zeek Package Manager can be used to install
this plugin in multiple ways:

* From the repo clone directory:

      # zkg install .

* Using the github repo directly:

      # zkg install https://github.com/MITRECND/bro-http2

* Using the official source:

      # zkg install zeek/mitrecnd/bro-http2

__NOTE__ If you had an older version of zkg or the original bro package manager
installed, the path might show up as `bro/mitrecnd/bro-http2`. Please use that
path or update your zkg configuration located, by default, in `~/.zkg/config`.

#### Installing Older Versions

If you are still running an older version of Zeek (Bro 2.6.x and older), you
can install a previous version of the plugin using zkg, utilizing the `--version`
argument.

      # zkg install zeek/mitrecnd/bro-http2 --version 0.4.2

## Usage

You should see the following output from zeek if successfully installed:

    > zeek -NN mitrecnd::HTTP2
    mitrecnd::HTTP2 - Hypertext Transfer Protocol Version 2 analyzer (dynamic, version 0.5.0)
        [Analyzer] HTTP2 (ANALYZER_HTTP2, enabled)
        [Event] http2_request
        [Event] http2_reply
        [Event] http2_stream_start
        [Event] http2_stream_end
        [Event] http2_header
        [Event] http2_all_headers
        [Event] http2_begin_entity
        [Event] http2_end_entity
        [Event] http2_entity_data
        [Event] http2_content_type
        [Event] http2_event
        [Event] http2_data_event
        [Event] http2_header_event
        [Event] http2_priority_event
        [Event] http2_rststream_event
        [Event] http2_settings_event
        [Event] http2_pushpromise_event
        [Event] http2_ping_event
        [Event] http2_goaway_event
        [Event] http2_windowupdate_event
        [Event] http2_continuation_event
        [Type] http2_settings_unrecognized_table
        [Type] http2_settings
        [Type] http2_stream_stat

To use/load the http2 analyzer, add the following to your config
(e.g., local.zeek):

    @load http2

The analyzer will create a new log file called "http2.log"

To use/load the http2 intel framework extensions add the following
to your config:

    @load http2/intel
