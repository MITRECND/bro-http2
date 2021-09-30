#ifndef BRO_PLUGIN_MITRECND_HTTP2
#define BRO_PLUGIN_MITRECND_HTTP2

#include <zeek/plugin/Plugin.h>

namespace plugin::mitrecnd_HTTP2 {

class Plugin : public zeek::plugin::Plugin
{
protected:
    // Overridden from plugin::Plugin.
    zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

}


#endif

