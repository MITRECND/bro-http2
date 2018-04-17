#ifndef BRO_PLUGIN_MITRECND_HTTP2
#define BRO_PLUGIN_MITRECND_HTTP2

#include <plugin/Plugin.h>

namespace plugin {
namespace mitrecnd_HTTP2 {

class Plugin : public ::plugin::Plugin
{
protected:
    // Overridden from plugin::Plugin.
    plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif

