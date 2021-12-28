#pragma once

#include "envoy/config/core/v3/base.pb.h"
#include "envoy/config/subscription.h"
#include "envoy/stats/scope.h"

#include "source/common/config/grpc_mux_impl.h"
#include "source/common/config/grpc_subscription_impl.h"
#include "source/common/config/subscription_factory_impl.h"
#include "source/common/config/utility.h"
#include "source/common/protobuf/protobuf.h"
#include "source/server/transport_socket_config_impl.h"

/**
 * EdsSubscriptionFactory is used for instantiation of EDS subscriptions so as to minimize the
 * number of open grpc connections used by thses subscriptions. This is done by sharing a grpc
 * multiplexer between subscriptions handled by the same config server. Please see
 * https://github.com/envoyproxy/envoy/issues/2943 for additional information and related issues.
 *
 * TODO (dmitri-d, nezdolik): This implementation should be generalized to cover RDS.
 */

namespace Envoy {
namespace Upstream {
class EdsSubscriptionFactory {
public:

virtual ~EdsSubscriptionFactory() = default;

Config::SubscriptionPtr
subscriptionFromConfigSource(
      const envoy::config::core::v3::ConfigSource& config, absl::string_view type_url, Config::SubscriptionCallbacks& callbacks,
      Config::OpaqueResourceDecoder& resource_decoder, const Config::SubscriptionOptions& options, Server::Configuration::TransportSocketFactoryContextImpl& factory_context,
      Stats::Scope& scope,
      const std::string& grpc_method);

protected:
  Config::GrpcMuxSharedPtr getOrCreateMux(const LocalInfo::LocalInfo& local_info,
                                  Grpc::RawAsyncClientPtr async_client, Event::Dispatcher& dispatcher,
                                  const Protobuf::MethodDescriptor& service_method,
                                  Random::RandomGenerator& random,
                                  const envoy::config::core::v3::ApiConfigSource& config_source,
                                  Stats::Scope& scope,
                                  const Config::RateLimitSettings& rate_limit_settings);

private:
  absl::flat_hash_map<uint64_t, Config::GrpcMuxSharedPtr> muxes_;
};
} // namespace Upstream
} // namespace Envoy