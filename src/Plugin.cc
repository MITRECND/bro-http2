#include "Plugin.h"
#include "HTTP2.h"

namespace plugin { namespace mitrecnd_HTTP2 { Plugin plugin; }}

using namespace plugin::mitrecnd_HTTP2;

plugin::Configuration Plugin::Configure()
    {
    AddComponent(new ::analyzer::Component("HTTP2", ::analyzer::mitrecnd::HTTP2_Analyzer::InstantiateAnalyzer));

    plugin::Configuration config;
    config.description = "Hypertext Transfer Protocol Version 2 analyzer";
    config.name = "mitrecnd::HTTP2";
    config.version.major = 0;
    config.version.minor = 2;
    return config;
    }
