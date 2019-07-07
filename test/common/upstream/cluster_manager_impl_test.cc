#include <memory>
#include <string>
#include <iostream>

#include "envoy/admin/v2alpha/config_dump.pb.h"
#include "envoy/api/v2/core/base.pb.h"
#include "envoy/network/listen_socket.h"
#include "envoy/upstream/upstream.h"

#include "common/api/api_impl.h"
#include "common/config/utility.h"
#include "common/http/context_impl.h"
#include "common/network/socket_option_factory.h"
#include "common/network/socket_option_impl.h"
#include "common/network/transport_socket_options_impl.h"
#include "common/network/utility.h"
#include "common/protobuf/utility.h"
#include "common/singleton/manager_impl.h"
#include "common/upstream/cluster_factory_impl.h"
#include "common/upstream/cluster_manager_impl.h"

#include "extensions/transport_sockets/tls/context_manager_impl.h"

#include "test/common/upstream/utility.h"
#include "test/mocks/access_log/mocks.h"
#include "test/mocks/api/mocks.h"
#include "test/mocks/http/mocks.h"
#include "test/mocks/local_info/mocks.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/protobuf/mocks.h"
#include "test/mocks/runtime/mocks.h"
#include "test/mocks/secret/mocks.h"
#include "test/mocks/server/mocks.h"
#include "test/mocks/tcp/mocks.h"
#include "test/mocks/thread_local/mocks.h"
#include "test/mocks/upstream/mocks.h"
#include "test/test_common/simulated_time_system.h"
#include "test/test_common/threadsafe_singleton_injector.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::InSequence;
using testing::Invoke;
using testing::Mock;
using testing::NiceMock;
using testing::Pointee;
using testing::Return;
using testing::ReturnNew;
using testing::ReturnRef;
using testing::SaveArg;

namespace Envoy {
namespace Upstream {
namespace {

// The tests in this file are split between testing with real clusters and some with mock clusters.
// By default we setup to call the real cluster creation function. Individual tests can override
// the expectations when needed.
class TestClusterManagerFactory : public ClusterManagerFactory {
public:
  TestClusterManagerFactory() : api_(Api::createApiForTest(stats_)) {
    ON_CALL(*this, clusterFromProto_(_, _, _, _))
        .WillByDefault(Invoke(
            [&](const envoy::api::v2::Cluster& cluster, ClusterManager& cm,
                Outlier::EventLoggerSharedPtr outlier_event_logger,
                bool added_via_api) -> std::pair<ClusterSharedPtr, ThreadAwareLoadBalancer*> {
              auto result = ClusterFactoryImplBase::create(
                  cluster, cm, stats_, tls_, dns_resolver_, ssl_context_manager_, runtime_, random_,
                  dispatcher_, log_manager_, local_info_, admin_, singleton_manager_,
                  outlier_event_logger, added_via_api, validation_visitor_, *api_);
              // Convert from load balancer unique_ptr -> raw pointer -> unique_ptr.
              return std::make_pair(result.first, result.second.release());
            }));
  }

  Http::ConnectionPool::InstancePtr
  allocateConnPool(Event::Dispatcher&, HostConstSharedPtr host, ResourcePriority, Http::Protocol,
                   const Network::ConnectionSocket::OptionsSharedPtr& options) override {
    return Http::ConnectionPool::InstancePtr{allocateConnPool_(host, options)};
  }

  Tcp::ConnectionPool::InstancePtr
  allocateTcpConnPool(Event::Dispatcher&, HostConstSharedPtr host, ResourcePriority,
                      const Network::ConnectionSocket::OptionsSharedPtr&,
                      Network::TransportSocketOptionsSharedPtr) override {
    return Tcp::ConnectionPool::InstancePtr{allocateTcpConnPool_(host)};
  }

  std::pair<ClusterSharedPtr, ThreadAwareLoadBalancerPtr>
  clusterFromProto(const envoy::api::v2::Cluster& cluster, ClusterManager& cm,
                   Outlier::EventLoggerSharedPtr outlier_event_logger,
                   bool added_via_api) override {
    auto result = clusterFromProto_(cluster, cm, outlier_event_logger, added_via_api);
    return std::make_pair(result.first, ThreadAwareLoadBalancerPtr(result.second));
  }

  CdsApiPtr createCds(const envoy::api::v2::core::ConfigSource&, ClusterManager&) override {
    return CdsApiPtr{createCds_()};
  }

  ClusterManagerPtr
  clusterManagerFromProto(const envoy::config::bootstrap::v2::Bootstrap& bootstrap) override {
    return ClusterManagerPtr{clusterManagerFromProto_(bootstrap)};
  }

  Secret::SecretManager& secretManager() override { return secret_manager_; }

  MOCK_METHOD1(clusterManagerFromProto_,
               ClusterManager*(const envoy::config::bootstrap::v2::Bootstrap& bootstrap));
  MOCK_METHOD2(allocateConnPool_,
               Http::ConnectionPool::Instance*(HostConstSharedPtr host,
                                               Network::ConnectionSocket::OptionsSharedPtr));
  MOCK_METHOD1(allocateTcpConnPool_, Tcp::ConnectionPool::Instance*(HostConstSharedPtr host));
  MOCK_METHOD4(clusterFromProto_,
               std::pair<ClusterSharedPtr, ThreadAwareLoadBalancer*>(
                   const envoy::api::v2::Cluster& cluster, ClusterManager& cm,
                   Outlier::EventLoggerSharedPtr outlier_event_logger, bool added_via_api));
  MOCK_METHOD0(createCds_, CdsApi*());

  Stats::IsolatedStoreImpl stats_;
  NiceMock<ThreadLocal::MockInstance> tls_;
  std::shared_ptr<NiceMock<Network::MockDnsResolver>> dns_resolver_{
      new NiceMock<Network::MockDnsResolver>};
  NiceMock<Runtime::MockLoader> runtime_;
  NiceMock<Runtime::MockRandomGenerator> random_;
  NiceMock<Event::MockDispatcher> dispatcher_;
  Extensions::TransportSockets::Tls::ContextManagerImpl ssl_context_manager_{
      dispatcher_.timeSource()};
  NiceMock<LocalInfo::MockLocalInfo> local_info_;
  NiceMock<Server::MockAdmin> admin_;
  NiceMock<Secret::MockSecretManager> secret_manager_;
  NiceMock<AccessLog::MockAccessLogManager> log_manager_;
  Singleton::ManagerImpl singleton_manager_{Thread::threadFactoryForTest().currentThreadId()};
  NiceMock<ProtobufMessage::MockValidationVisitor> validation_visitor_;
  Api::ApiPtr api_;
};

// Helper to intercept calls to postThreadLocalClusterUpdate.
class MockLocalClusterUpdate {
public:
  MOCK_METHOD3(post, void(uint32_t priority, const HostVector& hosts_added,
                          const HostVector& hosts_removed));
};

class MockLocalHostsRemoved {
public:
  MOCK_METHOD1(post, void(const HostVector&));
};

// A test version of ClusterManagerImpl that provides a way to get a non-const handle to the
// clusters, which is necessary in order to call updateHosts on the priority set.
class TestClusterManagerImpl : public ClusterManagerImpl {
public:
  using ClusterManagerImpl::ClusterManagerImpl;

  TestClusterManagerImpl(const envoy::config::bootstrap::v2::Bootstrap& bootstrap,
                         ClusterManagerFactory& factory, Stats::Store& stats,
                         ThreadLocal::Instance& tls, Runtime::Loader& runtime,
                         Runtime::RandomGenerator& random, const LocalInfo::LocalInfo& local_info,
                         AccessLog::AccessLogManager& log_manager,
                         Event::Dispatcher& main_thread_dispatcher, Server::Admin& admin,
                         Api::Api& api, Http::Context& http_context)
      : ClusterManagerImpl(bootstrap, factory, stats, tls, runtime, random, local_info, log_manager,
                           main_thread_dispatcher, admin, validation_visitor_, api, http_context) {}

  std::map<std::string, std::reference_wrapper<Cluster>> activeClusters() {
    std::map<std::string, std::reference_wrapper<Cluster>> clusters;
    for (auto& cluster : active_clusters_) {
      clusters.emplace(cluster.first, *cluster.second->cluster_);
    }
    return clusters;
  }

  NiceMock<ProtobufMessage::MockValidationVisitor> validation_visitor_;
};

// Override postThreadLocalClusterUpdate so we can test that merged updates calls
// it with the right values at the right times.
class MockedUpdatedClusterManagerImpl : public TestClusterManagerImpl {
public:
  MockedUpdatedClusterManagerImpl(
      const envoy::config::bootstrap::v2::Bootstrap& bootstrap, ClusterManagerFactory& factory,
      Stats::Store& stats, ThreadLocal::Instance& tls, Runtime::Loader& runtime,
      Runtime::RandomGenerator& random, const LocalInfo::LocalInfo& local_info,
      AccessLog::AccessLogManager& log_manager, Event::Dispatcher& main_thread_dispatcher,
      Server::Admin& admin, Api::Api& api, MockLocalClusterUpdate& local_cluster_update,
      MockLocalHostsRemoved& local_hosts_removed, Http::Context& http_context)
      : TestClusterManagerImpl(bootstrap, factory, stats, tls, runtime, random, local_info,
                               log_manager, main_thread_dispatcher, admin, api, http_context),
        local_cluster_update_(local_cluster_update), local_hosts_removed_(local_hosts_removed) {}

protected:
  void postThreadLocalClusterUpdate(const Cluster&, uint32_t priority,
                                    const HostVector& hosts_added,
                                    const HostVector& hosts_removed) override {
    local_cluster_update_.post(priority, hosts_added, hosts_removed);
  }

  void postThreadLocalHostRemoval(const Cluster&, const HostVector& hosts_removed) override {
    local_hosts_removed_.post(hosts_removed);
  }

  MockLocalClusterUpdate& local_cluster_update_;
  MockLocalHostsRemoved& local_hosts_removed_;
};

envoy::config::bootstrap::v2::Bootstrap parseBootstrapFromV2Yaml(const std::string& yaml) {
  envoy::config::bootstrap::v2::Bootstrap bootstrap;
  TestUtility::loadFromYaml(yaml, bootstrap);
  return bootstrap;
}

//std::string clustersJson(const std::vector<std::string>& clusters) {
//  return fmt::sprintf("\"clusters\": [%s]", StringUtil::join(clusters, ","));
//}

class ClusterManagerImplTest : public testing::Test {
public:
  ClusterManagerImplTest()
      : api_(Api::createApiForTest()), http_context_(factory_.stats_.symbolTable()) {}

  void create(const envoy::config::bootstrap::v2::Bootstrap& bootstrap) {
    cluster_manager_ = std::make_unique<TestClusterManagerImpl>(
        bootstrap, factory_, factory_.stats_, factory_.tls_, factory_.runtime_, factory_.random_,
        factory_.local_info_, log_manager_, factory_.dispatcher_, admin_, *api_, http_context_);
  }

  void createWithLocalClusterUpdate(const bool enable_merge_window = true) {
    std::string yaml = R"EOF(
  static_resources:
    clusters:
    - name: cluster_1
      connect_timeout: 0.250s
      type: STATIC
      lb_policy: RING_HASH
      hosts:
      - socket_address:
          address: "127.0.0.1"
          port_value: 11001
      - socket_address:
          address: "127.0.0.1"
          port_value: 11002
  )EOF";
    const std::string merge_window_enabled = R"EOF(
      common_lb_config:
        update_merge_window: 3s
  )EOF";
    const std::string merge_window_disabled = R"EOF(
      common_lb_config:
        update_merge_window: 0s
  )EOF";

    yaml += enable_merge_window ? merge_window_enabled : merge_window_disabled;

    const auto& bootstrap = parseBootstrapFromV2Yaml(yaml);

    cluster_manager_ = std::make_unique<MockedUpdatedClusterManagerImpl>(
        bootstrap, factory_, factory_.stats_, factory_.tls_, factory_.runtime_, factory_.random_,
        factory_.local_info_, log_manager_, factory_.dispatcher_, admin_, *api_,
        local_cluster_update_, local_hosts_removed_, http_context_);
  }

  void createWithLocalClusterUpdateRingHash(const bool enable_merge_window = true) {
    std::string yaml = R"EOF(
	static_resources:
		clusters:
		- name: redis_cluster
			lb_policy: RING_HASH
			ring_hash_lb_config:
				minimum_ring_size: 125
			connect_timeout: 0.250s
			type: STATIC
			load_assignment:
				endpoints:
					- lb_endpoints:
						- endpoint:
								address:
									socket_address:
										address: 127.0.0.1
										port_value: 8000
						- endpoint:
								address:
									socket_address:
										address: 127.0.0.1
										port_value: 8001
  )EOF";
        const std::string merge_window_enabled = R"EOF(
      common_lb_config:
        update_merge_window: 3s
  )EOF";
        const std::string merge_window_disabled = R"EOF(
      common_lb_config:
        update_merge_window: 0s
  )EOF";

        yaml += enable_merge_window ? merge_window_enabled : merge_window_disabled;

        const auto& bootstrap = parseBootstrapFromV2Yaml(yaml);

        cluster_manager_ = std::make_unique<MockedUpdatedClusterManagerImpl>(
                bootstrap, factory_, factory_.stats_, factory_.tls_, factory_.runtime_, factory_.random_,
                factory_.local_info_, log_manager_, factory_.dispatcher_, admin_, *api_,
                local_cluster_update_, local_hosts_removed_, http_context_);
    }

  void checkStats(uint64_t added, uint64_t modified, uint64_t removed, uint64_t active,
                  uint64_t warming) {
    EXPECT_EQ(added, factory_.stats_.counter("cluster_manager.cluster_added").value());
    EXPECT_EQ(modified, factory_.stats_.counter("cluster_manager.cluster_modified").value());
    EXPECT_EQ(removed, factory_.stats_.counter("cluster_manager.cluster_removed").value());
    EXPECT_EQ(active,
              factory_.stats_
                  .gauge("cluster_manager.active_clusters", Stats::Gauge::ImportMode::NeverImport)
                  .value());
    EXPECT_EQ(warming,
              factory_.stats_
                  .gauge("cluster_manager.warming_clusters", Stats::Gauge::ImportMode::NeverImport)
                  .value());
  }

  void checkConfigDump(const std::string& expected_dump_yaml) {
    auto message_ptr = admin_.config_tracker_.config_tracker_callbacks_["clusters"]();
    const auto& clusters_config_dump =
        dynamic_cast<const envoy::admin::v2alpha::ClustersConfigDump&>(*message_ptr);

    envoy::admin::v2alpha::ClustersConfigDump expected_clusters_config_dump;
    TestUtility::loadFromYaml(expected_dump_yaml, expected_clusters_config_dump);
    EXPECT_EQ(expected_clusters_config_dump.DebugString(), clusters_config_dump.DebugString());
  }

  envoy::api::v2::core::Metadata buildMetadata(const std::string& version) const {
    envoy::api::v2::core::Metadata metadata;

    if (version != "") {
      Envoy::Config::Metadata::mutableMetadataValue(
          metadata, Config::MetadataFilters::get().ENVOY_LB, "version")
          .set_string_value(version);
    }

    return metadata;
  }

  Event::SimulatedTimeSystem time_system_;
  Api::ApiPtr api_;
  NiceMock<TestClusterManagerFactory> factory_;
  std::unique_ptr<TestClusterManagerImpl> cluster_manager_;
  AccessLog::MockAccessLogManager log_manager_;
  NiceMock<Server::MockAdmin> admin_;
  MockLocalClusterUpdate local_cluster_update_;
  MockLocalHostsRemoved local_hosts_removed_;
  Http::ContextImpl http_context_;
};





// Tests that all the HC/weight/metadata changes are delivered in one go, as long as
// there's no hosts changes in between.
// Also tests that if hosts are added/removed between mergeable updates, delivery will
// happen and the scheduled update will be cancelled.
TEST_F(ClusterManagerImplTest, RingHashHostsChanged) {
	std::cerr << "RingHashHostsChanged start" << std::endl;
  createWithLocalClusterUpdate();

//
//  // Ensure we see the right set of added/removed hosts on every call.
//  EXPECT_CALL(local_cluster_update_, post(_, _, _))
//      .WillOnce(Invoke([](uint32_t priority, const HostVector& hosts_added,
//                          const HostVector& hosts_removed) -> void {
//        // 1st removal.
//        EXPECT_EQ(0, priority);
//        EXPECT_EQ(0, hosts_added.size());
//        EXPECT_EQ(1, hosts_removed.size());
//      }))
//      .WillOnce(Invoke([](uint32_t priority, const HostVector& hosts_added,
//                          const HostVector& hosts_removed) -> void {
//        // Triggered by the 2 HC updates, it's a merged update so no added/removed
//        // hosts.
//        EXPECT_EQ(0, priority);
//        EXPECT_EQ(0, hosts_added.size());
//        EXPECT_EQ(0, hosts_removed.size());
//      }))
//      .WillOnce(Invoke([](uint32_t priority, const HostVector& hosts_added,
//                          const HostVector& hosts_removed) -> void {
//        // 1st removed host added back.
//        EXPECT_EQ(0, priority);
//        EXPECT_EQ(1, hosts_added.size());
//        EXPECT_EQ(0, hosts_removed.size());
//      }))
//      .WillOnce(Invoke([](uint32_t priority, const HostVector& hosts_added,
//                          const HostVector& hosts_removed) -> void {
//        // 1st removed host removed again, plus the 3 HC/weight/metadata updates that were
//        // waiting for delivery.
//        EXPECT_EQ(0, priority);
//        EXPECT_EQ(0, hosts_added.size());
//        EXPECT_EQ(1, hosts_removed.size());
//      }));
//
//  EXPECT_CALL(local_hosts_removed_, post(_))
//      .Times(2)
//      .WillRepeatedly(
//          Invoke([](const auto& hosts_removed) { EXPECT_EQ(1, hosts_removed.size()); }));
//
  //Event::MockTimer* timer = new NiceMock<Event::MockTimer>(&factory_.dispatcher_);
  Cluster& cluster = cluster_manager_->activeClusters().begin()->second;
  HostVectorSharedPtr hosts(
      new HostVector(cluster.prioritySet().hostSetsPerPriority()[0]->hosts()));
  HostsPerLocalitySharedPtr hosts_per_locality = std::make_shared<HostsPerLocalityImpl>();
  HostVector hosts_added;
  HostVector hosts_removed;

//
//  // The first update should be applied immediately, since it's not mergeable.
  hosts_removed.push_back((*hosts)[0]);
			std::cerr << "***sending update" << std::endl;
			cluster.prioritySet().updateHosts(
      0,
      updateHostsParams(hosts, hosts_per_locality,
                        std::make_shared<const HealthyHostVector>(*hosts), hosts_per_locality),
      {}, hosts_added, hosts_removed, absl::nullopt);

	ASSERT(false);
//  EXPECT_EQ(1, factory_.stats_.counter("cluster_manager.cluster_updated").value());
//  EXPECT_EQ(0, factory_.stats_.counter("cluster_manager.cluster_updated_via_merge").value());
//  EXPECT_EQ(0, factory_.stats_.counter("cluster_manager.update_merge_cancelled").value());
//
//  // These calls should be merged, since there are no added/removed hosts.
//  hosts_removed.clear();
//  cluster.prioritySet().updateHosts(
//      0,
//      updateHostsParams(hosts, hosts_per_locality,
//                        std::make_shared<const HealthyHostVector>(*hosts), hosts_per_locality),
//      {}, hosts_added, hosts_removed, absl::nullopt);
//  cluster.prioritySet().updateHosts(
//      0,
//      updateHostsParams(hosts, hosts_per_locality,
//                        std::make_shared<const HealthyHostVector>(*hosts), hosts_per_locality),
//      {}, hosts_added, hosts_removed, absl::nullopt);
//  EXPECT_EQ(1, factory_.stats_.counter("cluster_manager.cluster_updated").value());
//  EXPECT_EQ(0, factory_.stats_.counter("cluster_manager.cluster_updated_via_merge").value());
//  EXPECT_EQ(0, factory_.stats_.counter("cluster_manager.update_merge_cancelled").value());
//
//  // Ensure the merged updates were applied.
//  timer->callback_();
//  EXPECT_EQ(1, factory_.stats_.counter("cluster_manager.cluster_updated").value());
//  EXPECT_EQ(1, factory_.stats_.counter("cluster_manager.cluster_updated_via_merge").value());
//  EXPECT_EQ(0, factory_.stats_.counter("cluster_manager.update_merge_cancelled").value());
//
//  // Add the host back, the update should be immediately applied.
//  hosts_removed.clear();
//  hosts_added.push_back((*hosts)[0]);
//  cluster.prioritySet().updateHosts(
//      0,
//      updateHostsParams(hosts, hosts_per_locality,
//                        std::make_shared<const HealthyHostVector>(*hosts), hosts_per_locality),
//      {}, hosts_added, hosts_removed, absl::nullopt);
//  EXPECT_EQ(2, factory_.stats_.counter("cluster_manager.cluster_updated").value());
//  EXPECT_EQ(1, factory_.stats_.counter("cluster_manager.cluster_updated_via_merge").value());
//  EXPECT_EQ(0, factory_.stats_.counter("cluster_manager.update_merge_cancelled").value());
//
//  // Now emit 3 updates that should be scheduled: metadata, HC, and weight.
//  hosts_added.clear();
//
//  (*hosts)[0]->metadata(buildMetadata("v1"));
//  cluster.prioritySet().updateHosts(
//      0,
//      updateHostsParams(hosts, hosts_per_locality,
//                        std::make_shared<const HealthyHostVector>(*hosts), hosts_per_locality),
//      {}, hosts_added, hosts_removed, absl::nullopt);
//
//  (*hosts)[0]->healthFlagSet(Host::HealthFlag::FAILED_EDS_HEALTH);
//  cluster.prioritySet().updateHosts(
//      0,
//      updateHostsParams(hosts, hosts_per_locality,
//                        std::make_shared<const HealthyHostVector>(*hosts), hosts_per_locality),
//      {}, hosts_added, hosts_removed, absl::nullopt);
//
//  (*hosts)[0]->weight(100);
//  cluster.prioritySet().updateHosts(
//      0,
//      updateHostsParams(hosts, hosts_per_locality,
//                        std::make_shared<const HealthyHostVector>(*hosts), hosts_per_locality),
//      {}, hosts_added, hosts_removed, absl::nullopt);
//
//  // Updates not delivered yet.
//  EXPECT_EQ(2, factory_.stats_.counter("cluster_manager.cluster_updated").value());
//  EXPECT_EQ(1, factory_.stats_.counter("cluster_manager.cluster_updated_via_merge").value());
//  EXPECT_EQ(0, factory_.stats_.counter("cluster_manager.update_merge_cancelled").value());
//
//  // Remove the host again, should cancel the scheduled update and be delivered immediately.
//  hosts_removed.push_back((*hosts)[0]);
//  cluster.prioritySet().updateHosts(
//      0,
//      updateHostsParams(hosts, hosts_per_locality,
//                        std::make_shared<const HealthyHostVector>(*hosts), hosts_per_locality),
//      {}, hosts_added, hosts_removed, absl::nullopt);
//
//  EXPECT_EQ(3, factory_.stats_.counter("cluster_manager.cluster_updated").value());
//  EXPECT_EQ(1, factory_.stats_.counter("cluster_manager.cluster_updated_via_merge").value());
//  EXPECT_EQ(1, factory_.stats_.counter("cluster_manager.update_merge_cancelled").value());
}




} // namespace
} // namespace Upstream
} // namespace Envoy
