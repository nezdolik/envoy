#include "source/common/upstream/multiplexed_subscription_factory.h"

#include <assert.h>

#include "source/common/config/type_to_endpoint.h"
#include "source/common/config/utility.h"
#include <iostream>

namespace Envoy {
namespace Upstream {

MultiplexedSubscriptionFactory::MultiplexedSubscriptionFactory(
const LocalInfo::LocalInfo& local_info, Event::Dispatcher& dispatcher,
                          Upstream::ClusterManager& cm,
                          ProtobufMessage::ValidationVisitor& validation_visitor, Api::Api& api,
                          const Server::Instance& server)
    : Config::SubscriptionFactoryImpl(local_info, dispatcher, cm, validation_visitor, api, server){};

// Config::SubscriptionPtr MultiplexedSubscriptionFactory::subscriptionFromConfigSource(
//     const envoy::config::core::v3::ConfigSource& config, absl::string_view type_url,
//     Stats::Scope& scope, Config::SubscriptionCallbacks& callbacks,
//     Config::OpaqueResourceDecoder& resource_decoder, const Config::SubscriptionOptions& options) {
//   if (config.config_source_specifier_case() ==
//           envoy::config::core::v3::ConfigSource::kApiConfigSource &&
//       config.api_config_source().api_type() == envoy::config::core::v3::ApiConfigSource::GRPC) {
//     const envoy::config::core::v3::ApiConfigSource& api_config_source = config.api_config_source();
//     Config::Utility::checkTransportVersion(api_config_source);
//     Config::CustomConfigValidatorsPtr custom_config_validators =
//         std::make_unique<Config::CustomConfigValidatorsImpl>(validation_visitor_, server_,
//                                                              api_config_source.config_validators());
//     Config::GrpcMuxSharedPtr mux_to_use = getOrCreateMux(
//         Config::Utility::factoryForGrpcApiConfigSource(
//             cm_.grpcAsyncClientManager(), api_config_source, scope, /*skip_cluster_check*/ true)
//             ->createUncachedRawAsyncClient(),
//         Config::sotwGrpcMethod(type_url), api_.randomGenerator(), api_config_source, scope,
//         Config::Utility::parseRateLimitSettings(api_config_source), custom_config_validators);

//     Config::SubscriptionStats stats = Config::Utility::generateStats(scope);
//     return std::make_unique<Config::GrpcSubscriptionImpl>(
//         mux_to_use, callbacks, resource_decoder, stats, type_url, dispatcher_,
//         Config::Utility::configSourceInitialFetchTimeout(config), /*is_aggregated*/ false, options);
//   }
//   return cm_.subscriptionFactory().subscriptionFromConfigSource(config, type_url, scope, callbacks,
//                                                                 resource_decoder, options);
// }

// Config::SubscriptionPtr MultiplexedSubscriptionFactory::collectionSubscriptionFromUrl(
//     const xds::core::v3::ResourceLocator&, const envoy::config::core::v3::ConfigSource&,
//     absl::string_view, Stats::Scope&, Config::SubscriptionCallbacks&,
//     Config::OpaqueResourceDecoder&) {
//   PANIC("not implemented");
// }

Config::GrpcMuxSharedPtr MultiplexedSubscriptionFactory::getOrCreateMux(
    const envoy::config::core::v3::ApiConfigSource& config_source,
                 absl::string_view type_url, Stats::Scope& scope,
                 Config::CustomConfigValidatorsPtr& custom_config_validators) {
  std::cerr<< "****MultiplexedSubscriptionFactory::getOrCreateMux" <<std::endl;
  if (config_source.api_type() == envoy::config::core::v3::ApiConfigSource::GRPC ||
    config_source.api_type() == envoy::config::core::v3::ApiConfigSource::DELTA_GRPC) {
      std::cerr<< "*****MultiplexedSubscriptionFactory envoy::config::core::v3::ApiConfigSource::GRPC" <<std::endl;
        const uint64_t mux_key = MessageUtil::hash(config_source.grpc_services(0));
    if (muxes_.find(mux_key) == muxes_.end()) {
      muxes_.emplace(std::make_pair(mux_key, Config::SubscriptionFactoryImpl::getOrCreateMux(config_source, type_url, scope, custom_config_validators)));
    }
    return muxes_.at(mux_key);
  } else {
    std::cerr<< "*****MultiplexedSubscriptionFactory envoy::config::core::v3::ApiConfigSource::NON GRPC" <<std::endl;
    return Config::SubscriptionFactoryImpl::getOrCreateMux(config_source, type_url, scope, custom_config_validators);
  }
}

} // namespace Upstream
} // namespace Envoy
