#include "Plugin.h"
#include "HTTP2.h"
#include "zeek/analyzer/Component.h"

namespace plugin::mitrecnd_HTTP2 { Plugin plugin; }

using namespace plugin::mitrecnd_HTTP2;

zeek::plugin::Configuration Plugin::Configure()
    {
    AddComponent(new ::zeek::analyzer::Component("HTTP2", analyzer::mitrecnd::HTTP2_Analyzer::InstantiateAnalyzer));

    zeek::plugin::Configuration config;
    config.description = "Hypertext Transfer Protocol Version 2 analyzer";
    config.name = "mitrecnd::HTTP2";
    config.version.major = 0;
    config.version.minor = 6;
    config.version.patch = 0;
    return config;
    }
