#include "plugin/Plugin.h"

#include "HTTP2.h"

namespace plugin {
namespace http2_HTTP2 {

class Plugin : public plugin::Plugin {
public:
    plugin::Configuration Configure()
        {
        AddComponent(new ::analyzer::Component("HTTP2",::analyzer::http2::HTTP2_Analyzer::InstantiateAnalyzer));

        plugin::Configuration config;
        config.name = "mitrecnd::HTTP2";
        config.version.major = 0;
        config.version.minor = 2;
        config.description = "Hypertext Transfer Protocol Version 2 analyzer";
        return config;
        }
} plugin;

}
}
