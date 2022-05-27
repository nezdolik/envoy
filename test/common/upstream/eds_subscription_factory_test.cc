#include <memory>

#include "envoy/common/exception.h"
#include "envoy/stats/scope.h"

#include "source/common/upstream/eds_subscription_factory.h"

#include "test/mocks/config/mocks.h"
#include "test/mocks/local_info/mocks.h"
#include "test/mocks/runtime/mocks.h"
#include "test/mocks/stats/mocks.h"
#include "test/mocks/upstream/mocks.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

namespace Envoy {
namespace Upstream {

class EdsSubscriptionFactoryForTesting : public EdsSubscriptionFactory {
public:
  EdsSubscriptionFactoryForTesting(const LocalInfo::LocalInfo& local_info, Event::Dispatcher& dispatcher, 
  Upstream::ClusterManager& cm, Api::Api& api): EdsSubscriptionFactory(local_info, dispatcher, cm, api){};

  Config::GrpcMux& testGetOrCreateMux(
                                  Grpc::RawAsyncClientPtr async_client,
                                  const Protobuf::MethodDescriptor& service_method,
                                  Random::RandomGenerator& random,
                                  const envoy::config::core::v3::ApiConfigSource& config_source,
                                  Stats::Scope& scope,
                                  const Config::RateLimitSettings& rate_limit_settings) {

    return EdsSubscriptionFactory::getOrCreateMux(std::move(async_client),
                                                  service_method, random, config_source, scope,
                                                  rate_limit_settings);
  }
};

class EdsSubscriptionFactoryTest : public ::testing::Test {
public:
  EdsSubscriptionFactoryTest()
      : method_descriptor_(*Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
            "envoy.api.v3.EndpointDiscoveryService.StreamEndpoints")) {}

  Upstream::MockClusterManager cm_;
  Event::MockDispatcher dispatcher_;
  NiceMock<Random::MockRandomGenerator> random_;
  Config::MockSubscriptionCallbacks<envoy::api::v2::ClusterLoadAssignment> callbacks_;
  Stats::MockIsolatedStatsStore stats_store_;
  NiceMock<Api::MockApi> api_;
  NiceMock<LocalInfo::MockLocalInfo> local_info_;
  Grpc::MockAsyncClient* async_client_;
  const Protobuf::MethodDescriptor& method_descriptor_;
  Config::RateLimitSettings rate_limit_settings_;
};

// Verify the same mux instance is returned when the same management servers are used.
TEST_F(EdsSubscriptionFactoryTest, ShouldReturnSameMux) {
  envoy::api::v3::core::ConfigSource config1;
  config1.mutable_api_config_source()->add_grpc_services()->mutable_envoy_grpc()->set_cluster_name(
      "primary_eds_cluster");
  envoy::api::v3::core::ConfigSource config2;
  config2.mutable_api_config_source()->add_grpc_services()->mutable_envoy_grpc()->set_cluster_name(
    "primary_eds_cluster");
  config2.mutable_api_config_source()->add_grpc_services()->mutable_envoy_grpc()->set_cluster_name(
  "fallback_eds_cluster");
  auto factory = EdsSubscriptionFactoryForTesting(local_info_, dispatcher_, cm_, api_);

  EXPECT_CALL(dispatcher_, createTimer_(_));
  Config::GrpcMux& first_mux = factory.testGetOrCreateMux(
      std::make_unique<Grpc::MockAsyncClient>(), method_descriptor_,
      random_, config1.api_config_source(), stats_store_, rate_limit_settings_);
  Config::GrpcMux& second_mux = factory.testGetOrCreateMux(
      std::make_unique<Grpc::MockAsyncClient>(), method_descriptor_,
      random_, config2.api_config_source(), stats_store_, rate_limit_settings_);
  EXPECT_EQ(&first_mux, &second_mux);
}

// // Verify that a new mux instance is created if a different config_source is used
// TEST_F(EdsSubscriptionFactoryTest, ShouldReturnDifferentMuxes) {
//   EdsSubscriptionFactoryForTesting factory;

//   EXPECT_CALL(dispatcher_, createTimer_(_)).Times(2);
//   envoy::api::v2::core::ConfigSource first_config;
//   first_config.mutable_api_config_source()
//       ->add_grpc_services()
//       ->mutable_envoy_grpc()
//       ->set_cluster_name("first_cluster");
//   Config::GrpcMux& first_mux = factory.testGetOrCreateMux(
//       local_info_, std::make_unique<Grpc::MockAsyncClient>(), dispatcher_, method_descriptor_,
//       random_, first_config.api_config_source(), stats_store_, rate_limit_settings_);
//   envoy::api::v2::core::ConfigSource second_config;
//   second_config.mutable_api_config_source()
//       ->add_grpc_services()
//       ->mutable_envoy_grpc()
//       ->set_cluster_name("second_cluster");
//   Config::GrpcMux& second_mux = factory.testGetOrCreateMux(
//       local_info_, std::make_unique<Grpc::MockAsyncClient>(), dispatcher_, method_descriptor_,
//       random_, second_config.api_config_source(), stats_store_, rate_limit_settings_);
//   EXPECT_NE(&first_mux, &second_mux);
// }

// // Verify that muxes managed by EdsSubscriptionFactory are used when ApiConfigSource::GRPC api type
// // is used
// TEST_F(EdsSubscriptionFactoryTest, ShouldUseGetOrCreateMuxWhenApiConfigSourceIsUsed) {
//   EdsSubscriptionFactoryForTesting factory;

//   envoy::api::v2::core::ConfigSource config;
//   config.mutable_api_config_source()->set_api_type(envoy::api::v2::core::ApiConfigSource::GRPC);
//   config.mutable_api_config_source()->add_grpc_services()->mutable_envoy_grpc()->set_cluster_name(
//       "first_cluster");

//   NiceMock<Grpc::MockAsyncClientFactory>* async_client_factory{
//       new NiceMock<Grpc::MockAsyncClientFactory>()};
//   EXPECT_CALL(*async_client_factory, create()).WillOnce(Invoke([] {
//     return std::make_unique<NiceMock<Grpc::MockAsyncClient>>();
//   }));

//   NiceMock<Grpc::MockAsyncClientManager> async_client_manager;
//   EXPECT_CALL(async_client_manager, factoryForGrpcService(_, _, _))
//       .WillOnce(Invoke(
//           [async_client_factory](const envoy::api::v2::core::GrpcService&, Stats::Scope&, bool) {
//             return Grpc::AsyncClientFactoryPtr(async_client_factory);
//           }));
//   EXPECT_CALL(cm_, grpcAsyncClientManager()).WillOnce(ReturnRef(async_client_manager));
//   EXPECT_CALL(dispatcher_, createTimer_(_));

//   auto subscription = factory.subscriptionFromConfigSource(
//       config, local_info_, dispatcher_, cm_, random_, stats_store_, nullptr,
//       "envoy.api.v2.EndpointDiscoveryService.FetchEndpoints",
//       "envoy.api.v2.EndpointDiscoveryService.StreamEndpoints");

//   Config::GrpcMux& expected_mux = factory.testGetOrCreateMux(
//       local_info_, std::make_unique<Grpc::MockAsyncClient>(), dispatcher_, method_descriptor_,
//       random_, config.api_config_source(), stats_store_, rate_limit_settings_);

//   Config::Subscription<envoy::api::v2::ClusterLoadAssignment>& eds_subscription = *subscription;
//   EXPECT_EQ(&expected_mux,
//             &(dynamic_cast<
//                   Config::GrpcManagedMuxSubscriptionImpl<envoy::api::v2::ClusterLoadAssignment>&>(
//                   eds_subscription)
//                   .grpcMux()));
// }

// // Verify that super-class subscriptionFromConfigSource() is called when a non ApiConfigSource::GRPC
// // api type is used
// TEST_F(EdsSubscriptionFactoryTest, ShouldCallConfigSubscriptionFactory) {
//   EdsSubscriptionFactory factory;
//   NiceMock<Config::MockGrpcMux> grpc_mux;

//   envoy::api::v2::core::ConfigSource config;
//   config.mutable_ads();

//   EXPECT_CALL(cm_, adsMux).WillOnce(ReturnRef(grpc_mux));
//   factory.subscriptionFromConfigSource(config, local_info_, dispatcher_, cm_, random_, stats_store_,
//                                        nullptr, "", "");
// }

} // namespace Upstream
} // namespace Envoy