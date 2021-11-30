#include "source/common/upstream/eds_subscription_factory.h"
#include "source/common/config/utility.h"

namespace Envoy {
namespace Upstream {
Config::GrpcMux& EdsSubscriptionFactory::getOrCreateMux(
    const LocalInfo::LocalInfo& local_info, Grpc::RawAsyncClientPtr async_client,
    Event::Dispatcher& dispatcher, const Protobuf::MethodDescriptor& service_method,
    Random::RandomGenerator& random, const envoy::config::core::v3::ApiConfigSource& config_source,
    Stats::Scope& scope, const Config::RateLimitSettings& rate_limit_settings) {
  const uint64_t mux_key = MessageUtil::hash(config_source.grpc_services(0));
  if (muxes_.find(mux_key) == muxes_.end()) {
    muxes_.emplace(std::make_pair(
        mux_key,
        std::make_unique<Config::GrpcMuxImpl>(local_info, std::move(async_client), dispatcher,
                                              service_method, random, scope, rate_limit_settings, config_source.set_node_on_first_message_only())));
  }
  return *(muxes_.at(mux_key));
}

Config::SubscriptionPtr
EdsSubscriptionFactory::subscriptionFromConfigSource(
    const envoy::config::core::v3::ConfigSource& config, absl::string_view type_url, Config::SubscriptionCallbacks& callbacks,
    Config::OpaqueResourceDecoder& resource_decoder, const Config::SubscriptionOptions& options, 
    const LocalInfo::LocalInfo& local_info, Event::Dispatcher& dispatcher, Upstream::ClusterManager& cm, 
    Random::RandomGenerator& random, Stats::Scope& scope,
    std::function<Config::SubscriptionPtr*()>,
    const std::string& grpc_method) {
  if (config.config_source_specifier_case() ==
          envoy::config::core::v3::ConfigSource::kApiConfigSource &&
      config.api_config_source().api_type() == envoy::config::core::v3::ApiConfigSource::GRPC) {
    const envoy::config::core::v3::ApiConfigSource& api_config_source = config.api_config_source();

    Config::GrpcMux& mux_to_use = getOrCreateMux(
        local_info,
        Config::Utility::factoryForGrpcApiConfigSource(cm.grpcAsyncClientManager(),
                                                       api_config_source, scope, /*skip_cluster_check*/ true)
            ->createUncachedRawAsyncClient(),
        dispatcher, *Protobuf::DescriptorPool::generated_pool()->FindMethodByName(grpc_method),
        random, api_config_source, scope,
        Config::Utility::parseRateLimitSettings(api_config_source));

    Config::SubscriptionStats stats = Config::Utility::generateStats(scope);
   return std::make_unique<Config::GrpcSubscriptionImpl>(mux_to_use, callbacks, resource_decoder, stats, 
   type_url, dispatcher, Config::Utility::configSourceInitialFetchTimeout(config), /*is_aggregated*/ false, options);
  }

  return cm.subscriptionFactory().subscriptionFromConfigSource(config, type_url, scope, callbacks, 
  resource_decoder, options);
}
} // namespace Upstream
} // namespace Envoy