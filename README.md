# Bro HTTP2 Analyzer Plugin

__NOTE!!__ If you are currently running versions 0.1 or 0.2, you will need to
delete the old plugin since the namespace of the plugin has changed (from
"http2::HTTP2" to "mitrecnd::HTTP2"). Instructions on how to do so are
outlined below.

This plugin provides an HTTP2 ([RFC 7540](https://tools.ietf.org/html/rfc7540))
decoder/analyzer for [Bro](https://www.bro.org/).

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
https://github.com/google/brotli. The latest release can be found at
https://github.com/google/brotli/releases/latest. After downloading the latest
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
    ./configure --bro-dist=</path/to/bro/source>
    make
    make test
    make install


__NOTE!!__ If you are upgrading the plugin from versions 0.1 or 0.2 please
delete the following directory from your bro install before starting or
restarting your cluster:

    <bro_install_root>/lib/bro/plugins/http2_HTTP2


### Bro Package Manager

The Bro Package Manager can be used to install
this plugin in multiple ways:

* From the repo clone directory:
```
    # bro-pkg install .
```

* Using the github repo directly:
```
    # bro-pkg install https://github.com/MITRECND/bro-http2
```

* Using the official source (FUTURE):
```
    # bro-pkg install bro/mitrecnd/bro-http2
```

## Usage

You should see the following output from bro if successfully installed:

```
    > bro -NN mitrecnd::HTTP2
    mitrecnd::HTTP2 - Hypertext Transfer Protocol Version 2 analyzer (dynamic, version 0.4)
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
```


To use/load the http2 analyzer, add the following to your config
(e.g., local.bro):

    @load http2

The analyzer will create a new log file called "http2.log"

To use/load the http2 intel framework extensions add the following
to your config:

    @load http2/intel
