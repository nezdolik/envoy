#include "source/common/upstream/eds_subscription_factory.h"
#include "source/common/config/new_grpc_mux_impl.h"
#include "source/common/config/utility.h"
#include <iostream>

namespace Envoy {
namespace Upstream {
Config::GrpcMuxSharedPtr EdsSubscriptionFactory::getOrCreateMux(
    const LocalInfo::LocalInfo& local_info, Grpc::RawAsyncClientPtr async_client,
    Event::Dispatcher& dispatcher, const Protobuf::MethodDescriptor& service_method,
    Random::RandomGenerator& random, const envoy::config::core::v3::ApiConfigSource& config_source,
    Stats::Scope& scope, const Config::RateLimitSettings& rate_limit_settings) {
  const uint64_t mux_key = MessageUtil::hash(config_source.grpc_services(0));
  std::cerr << "***EdsSubscriptionFactory::getOrCreateMux 1010101" << std::endl;
  if (muxes_.find(mux_key) == muxes_.end()) {

            // mux = std::make_shared<Config::NewGrpcMuxImpl>(
            // Config::Utility::factoryForGrpcApiConfigSource(cm_.grpcAsyncClientManager(),
            //                                                api_config_source, scope, true)
            //     ->createUncachedRawAsyncClient(),
            // dispatcher_, deltaGrpcMethod(type_url), api_.randomGenerator(), scope,
            // Utility::parseRateLimitSettings(api_config_source), local_info_);
    /*
      NewGrpcMuxImpl(Grpc::RawAsyncClientPtr&& async_client, Event::Dispatcher& dispatcher,
                 const Protobuf::MethodDescriptor& service_method, Random::RandomGenerator& random,
                 Stats::Scope& scope, const RateLimitSettings& rate_limit_settings,
                 const LocalInfo::LocalInfo& local_info);
    */
    muxes_.emplace(std::make_pair(
        mux_key,
        std::make_shared<Config::NewGrpcMuxImpl>(std::move(async_client), dispatcher,
                                              service_method, random, scope, rate_limit_settings, local_info)));
        // std::make_shared<Config::NewGrpcMuxImpl>(local_info, std::move(async_client), dispatcher,
        //                                       service_method, random, scope, rate_limit_settings, config_source.set_node_on_first_message_only())));
  }
  return muxes_.at(mux_key);
}


Config::SubscriptionPtr
EdsSubscriptionFactory::subscriptionFromConfigSource(
    const envoy::config::core::v3::ConfigSource& config, absl::string_view type_url, Config::SubscriptionCallbacks& callbacks,
    Config::OpaqueResourceDecoder& resource_decoder, const Config::SubscriptionOptions& options, Server::Configuration::TransportSocketFactoryContextImpl& factory_context, 
    Stats::Scope& scope,
    const std::string& grpc_method) {
  std::cerr << "***EdsSubscriptionFactory::subscriptionFromConfigSource 999" << std::endl;
  Event::Dispatcher& dispatcher = factory_context.mainThreadDispatcher();
  if (config.config_source_specifier_case() ==
          envoy::config::core::v3::ConfigSource::kApiConfigSource &&
      config.api_config_source().api_type() == envoy::config::core::v3::ApiConfigSource::GRPC) {
    const envoy::config::core::v3::ApiConfigSource& api_config_source = config.api_config_source();

    Config::GrpcMuxSharedPtr mux_to_use = getOrCreateMux(
        factory_context.localInfo(),
        Config::Utility::factoryForGrpcApiConfigSource(factory_context.clusterManager().grpcAsyncClientManager(),
                                                       api_config_source, scope, /*skip_cluster_check*/ true)
            ->createUncachedRawAsyncClient(),
        dispatcher, *Protobuf::DescriptorPool::generated_pool()->FindMethodByName(grpc_method),
        factory_context.api().randomGenerator(),
        api_config_source, scope,
        Config::Utility::parseRateLimitSettings(api_config_source));

    Config::SubscriptionStats stats = Config::Utility::generateStats(scope);
   return std::make_unique<Config::GrpcSubscriptionImpl>(mux_to_use, callbacks, resource_decoder, stats, 
   type_url, dispatcher, Config::Utility::configSourceInitialFetchTimeout(config), /*is_aggregated*/ false, options);
  }

  return factory_context.clusterManager().subscriptionFactory().subscriptionFromConfigSource(config, type_url, scope, callbacks, 
  resource_decoder, options);
}
} // namespace Upstream
} // namespace Envoy