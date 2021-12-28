#pragma once

#include "source/common/upstream/eds_subscription_factory.h"


namespace Envoy {
namespace Upstream {
class MockEdsSubscriptionFactory : public EdsSubscriptionFactory {
  MOCK_METHOD(Config::GrpcMuxSharedPtr, getOrCreateMux,
               (const LocalInfo::LocalInfo&,
                                  Grpc::RawAsyncClientPtr, Event::Dispatcher&,
                                  const Protobuf::MethodDescriptor&,
                                  Random::RandomGenerator&,
                                  const envoy::config::core::v3::ApiConfigSource&,
                                  Stats::Scope&,
                                  const Config::RateLimitSettings&));

  MOCK_METHOD(Config::SubscriptionPtr, subscriptionFromConfigSource,
      (const envoy::config::core::v3::ConfigSource&, absl::string_view, Config::SubscriptionCallbacks&,
      Config::OpaqueResourceDecoder&, const Config::SubscriptionOptions&, Server::Configuration::TransportSocketFactoryContextImpl&,
      Stats::Scope&,
      const std::string&));
};

} // namespace Upstream

} // namespace Envoy