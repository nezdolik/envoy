#include "envoy/extensions/resource_monitors/downstream_connections/v3/downstream_connections.pb.h"
#include "envoy/extensions/resource_monitors/downstream_connections/v3/downstream_connections.pb.validate.h"
#include "envoy/registry/registry.h"

#include "source/extensions/resource_monitors/downstream_connections/config.h"
#include "source/server/resource_monitor_config_impl.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/server/options.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace ResourceMonitors {
namespace DownstreamConnections {
namespace {

TEST(ActiveDownstreamConnectionsMonitorFactoryTest, CreateMonitor) {
  auto factory =
      Registry::FactoryRegistry<Server::Configuration::ProactiveResourceMonitorFactory>::getFactory(
          "envoy.resource_monitors.downstream_connections");
  EXPECT_NE(factory, nullptr);

  envoy::extensions::resource_monitors::downstream_connections::v3::DownstreamConnectionsConfig
      config;
  config.set_max_active_downstream_connections(std::numeric_limits<uint64_t>::max());
  Event::MockDispatcher dispatcher;
  Api::ApiPtr api = Api::createApiForTest();
  Server::MockOptions options;
  Server::Configuration::ResourceMonitorFactoryContextImpl context(
      dispatcher, options, *api, ProtobufMessage::getStrictValidationVisitor());
  auto monitor = factory->createProactiveResourceMonitor(config, context);
  EXPECT_NE(monitor, nullptr);
}

} // namespace
} // namespace DownstreamConnections
} // namespace ResourceMonitors
} // namespace Extensions
} // namespace Envoy
