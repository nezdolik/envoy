#pragma once

#include "envoy/extensions/geoip_providers/maxmind.pb.h"

#include "source/common/protobuf/protobuf.h"

namespace Envoy {
namespace Extensions {
namespace GeoipProviders {
namespace Maxmind {

using DriverSharedPtr = Envoy::Extensions::HttpFilters::Geoip::DriverSharedPtr;
//todo (nezdolik) shorted long type names
class MaxmindProviderFactory : public ProviderFactoryBase<envoy::extensions::geoip_providers::MaxMindConfig> {
public:
  MaxmindProviderFactory() = default;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<MaxMindConfig>();
  }

  std::string name() const override { return "envoy.geoip_providers.maxmind"; }

private:
  using MaxmindProviderConfig = envoy::extensions::geoip_providers::MaxMindConfig;
  // FactoryBase
  DriverSharedPtr
  createProviderDriverTyped(const Common::FactoryBase<envoy::extensions::geoip_providers::MaxMindConfig& proto_config,
                          Envoy::Extensions::HttpFilters::Geoip::ProviderFactoryContext& context) override;
};

} // namespace Maxmind
} // namespace GeoipProviders
} // namespace Extensions
} // namespace Envoy
