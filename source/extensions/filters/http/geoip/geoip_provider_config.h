#pragma once

#include "envoy/config/typed_config.h"
#include "envoy/extensions/filters/http/geoip/v3/geoip.pb.h"
#include "envoy/extensions/filters/http/geoip/v3/geoip.pb.validate.h"
#include "envoy/network/address.h"
#include "envoy/protobuf/message_validator.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Geoip {

struct LookupResult {
  // Actual result of the lookup. Will be set to absl::nullopt when database lookup yields an empty result.
  const absl::optional<std::string> lookup_result_;
  // Gelocation header name for which the lookup was invoked.
  const absl::optional<std::string> geo_header_;

  LookupResult(const absl::optional<std::string> lookup_result, const absl::optional<std::string> geo_header):
  lookup_result_(lookup_result_), geo_header_(geo_header) {};
};

// Async callbacks used for geolocation provider lookups.
using LookupGeoHeadersCallback = std::function<void(LookupResult&&)>;
using LookupGeoHeadersCallbackPtr = std::unique_ptr<LookupGeoHeadersCallback>;

class Driver {
public:
  virtual ~Driver() = default;

  /**
   *  Performs asyncronous lookup in the geolocation database.
   *
   *  @param cb supplies the filter callbacks to notify when lookup is complete.
   */
  virtual void lookup(const LookupGeoHeadersCallbackPtr& cb) const PURE;
};

using DriverSharedPtr = std::shared_ptr<Driver>;

/**
 * Context passed to geolocation providers to access server resources.
 */
class GeoipProviderFactoryContext {
public:
  virtual ~GeoipProviderFactoryContext() = default;

  /**
   * @return ProtobufMessage::ValidationVisitor& validation visitor for geolocation provider
   * configuration messages.
   */
  virtual ProtobufMessage::ValidationVisitor& messageValidationVisitor() PURE;
};

using GeoipProviderFactoryContextPtr = std::unique_ptr<GeoipProviderFactoryContext>;

/**
 * Implemented by each geolocation provider and registered via Registry::registerFactory() or the
 * convenience class RegisterFactory.
 */
class GeoipProviderFactory : public Config::TypedFactory {
public:
  ~GeoipProviderFactory() override = default;

  /**
   * Create a particular geolocation provider implementation. If the implementation is unable to
   * produce a geolocation provider with the provided parameters, it should throw an EnvoyException
   * in the case of general error or a Json::Exception if the json configuration is erroneous. The
   * returned pointer should always be valid.
   *
   *
   * @param config supplies the proto configuration for the geolocation provider
   * @param context supplies the factory context
   */
  virtual DriverSharedPtr createGeoipProviderDriver(const Protobuf::Message& config,
                                                    GeoipProviderFactoryContextPtr& context) PURE;

  std::string category() const override { return "envoy.geoip_providers"; }
};

} // namespace Geoip
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
