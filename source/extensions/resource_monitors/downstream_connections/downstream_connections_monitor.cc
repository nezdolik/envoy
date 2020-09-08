#pragma once

#include "extensions/resource_monitors/downstream_connections/downstream_connections_monitor.h"

#include <thread>

#include "envoy/config/resource_monitor/downstream_connections/v3/downstream_connections.pb.h"

#include "common/common/assert.h"

// tbd

namespace Envoy {
namespace Extensions {
namespace ResourceMonitors {
namespace DownstreamConnectionsMonitor {

DownstreamConnectionsMonitor::DownstreamConnectionsMonitor(
    const envoy::config::resource_monitor::fixed_heap::v3::DownstreamConnectionsConfig& config, const Stats::ThreadLocalStoreImpl& stats_store)
    : max_downstream_conns_(config.max_downstream_connections()),
      global_total_downstream_conns_(0),
      stats_store(stats_store) {
  ASSERT(max_downstream_conns_ > 0);
}

void DownstreamConnectionsMonitor::updateResourceUsage(
    Server::ResourceMonitor::Callbacks& callbacks) {
  Server::ResourceUsage usage;
  //auto tls = 
  // usage.resource_pressure_ = static_cast<double>(global_total_downstream_conns_.load()) /
  //                            static_cast<double>(max_downstream_conns_);
  callbacks.onSuccess(usage);
}

} // namespace DownstreamConnectionsMonitor
} // namespace ResourceMonitors
} // namespace Extensions
} // namespace Envoy
