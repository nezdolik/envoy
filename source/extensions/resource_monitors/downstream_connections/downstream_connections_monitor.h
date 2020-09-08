#pragma once

#include "envoy/config/resource_monitor/downstream_connections/v3/downstream_connections.pb.h"
#include "envoy/server/resource_monitor.h"
#include "envoy/stats/stats.h"

#include "absl/container/node_hash_map.h"

namespace Envoy {
namespace Extensions {
namespace ResourceMonitors {
namespace DownstreamConnectionsMonitor {

/**
 * Downstream connections monitor with a statically configured maximum.
 */
class DownstreamConnectionsMonitor : public Server::ResourceMonitor {
public:
  DownstreamConnectionsMonitor(
      const envoy::config::resource_monitor::fixed_heap::v3::DownstreamConnectionsConfig& config, const Stats::ThreadLocalStoreImpl& stats_store);

  void updateResourceUsage(Server::ResourceMonitor::Callbacks& callbacks) override;

private:
  std::atomic<uint64_t> global_total_downstream_conns_;
  const uint64_t max_downstream_conns_;
  Stats::ThreadLocalStoreImpl stats_store_;
};

} // namespace DownstreamConnectionsMonitor
} // namespace ResourceMonitors
} // namespace Extensions
} // namespace Envoy
