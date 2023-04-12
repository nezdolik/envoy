#include "source/extensions/geoip_providers/maxmind/config.h"

#include "envoy/extensions/geoip_providers/maxmind.pb.h"


#include "source/common/common/utility.h"
#include "source/extensions/filters/http/geoip/geoip_provider_config.h"

namespace Envoy {
namespace Extensions {
namespace GeoipProviders {
namespace Maxmind {

MaxmindProviderFactory::MaxmindProviderFactory() : FactoryBase("envoy.geoip_providers.maxmind") {}

DriverSharedPtr MaxmindProviderFactory::createProviderDriverTyped(
    const Common::FactoryBase<envoy::extensions::geoip_providers::MaxMindConfig& proto_config,
    Envoy::Extensions::HttpFilters::Geoip::ProviderFactoryContext& context) {
  return std::make_shared<Driver>();
}

/**
 * Static registration for the Maxmind provider. @see RegisterFactory.
 */
LEGACY_REGISTER_FACTORY(MaxmindProviderFactory, ProviderFactoryBase, "envoy.geoip_providers.maxmind");

} // namespace Maxmind
} // namespace GeoipProviders
} // namespace Extensions
} // namespace Envoy
