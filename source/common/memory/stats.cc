#include "source/common/memory/stats.h"

#include <cstdint>

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"

#if defined(TCMALLOC)

#include "tcmalloc/malloc_extension.h"

namespace Envoy {
namespace Memory {

uint64_t Stats::totalCurrentlyAllocated() {
  return tcmalloc::MallocExtension::GetNumericProperty("generic.current_allocated_bytes")
      .value_or(0);
}

uint64_t Stats::totalCurrentlyReserved() {
  // In Google's tcmalloc the semantics of generic.heap_size has
  // changed: it doesn't include unmapped bytes.
  return tcmalloc::MallocExtension::GetNumericProperty("generic.heap_size").value_or(0) +
         tcmalloc::MallocExtension::GetNumericProperty("tcmalloc.pageheap_unmapped_bytes")
             .value_or(0);
}

uint64_t Stats::totalThreadCacheBytes() {
  return tcmalloc::MallocExtension::GetNumericProperty("tcmalloc.current_total_thread_cache_bytes")
      .value_or(0);
}

uint64_t Stats::totalPageHeapFree() {
  return tcmalloc::MallocExtension::GetNumericProperty("tcmalloc.pageheap_free_bytes").value_or(0);
}

uint64_t Stats::totalPageHeapUnmapped() {
  return tcmalloc::MallocExtension::GetNumericProperty("tcmalloc.pageheap_unmapped_bytes")
      .value_or(0);
}

uint64_t Stats::totalPhysicalBytes() {
  return tcmalloc::MallocExtension::GetProperties()["generic.physical_memory_used"].value;
}

void Stats::dumpStatsToLog() {
  ENVOY_LOG_MISC(debug, "TCMalloc stats:\n{}", tcmalloc::MallocExtension::GetStats());
}

Allocator::~Allocator() {
  {
    absl::MutexLock guard(&mutex_);
    terminating_ = true;
  }
  if (tcmalloc_thread_) {
    tcmalloc_thread_->join();
  }
}

void Allocator::configureBackgroundMemoryRelease() {
  ASSERT(!tcmalloc_thread_);
  if (background_release_rate_ > 0) {
    tcmalloc::MallocExtension::SetBackgroundReleaseRate(
        tcmalloc::MallocExtension::BytesPerSecond{background_release_rate_});
    ENVOY_LOG_MISC(info, "Configured tcmalloc with background release rate: {} bytes per second",
                   background_release_rate_);
    // `ProcessBackgroundActions` routine needs to be invoked for background memory release to be
    // operative. https://github.com/google/tcmalloc/blob/master/tcmalloc/malloc_extension.h#L635
    tcmalloc_thread_ = thread_factory_.createThread(
        [this]() -> void { tcmallocProcessBackgroundActionsThreadRoutine(); },
        Thread::Options{"TcmallocProcessBackgroundActions"});
  }
}

void Allocator::tcmallocProcessBackgroundActionsThreadRoutine() {
  ENVOY_LOG_MISC(debug, "Started tcmallocProcessBackgroundActionsThreadRoutine");
  while (true) {
    absl::MutexLock guard(&mutex_);
    if (terminating_) {
      return;
    } else {
      if (tcmalloc::MallocExtension::NeedsProcessBackgroundActions()) {
        tcmalloc::MallocExtension::ProcessBackgroundActions();
      } else {
        ENVOY_LOG_MISC(info, "Current platform does not suport tcmalloc background actions");
      }
    }
  }
}

} // namespace Memory
} // namespace Envoy

#elif defined(GPERFTOOLS_TCMALLOC)

#include "gperftools/malloc_extension.h"

namespace Envoy {
namespace Memory {

uint64_t Stats::totalCurrentlyAllocated() {
  size_t value = 0;
  MallocExtension::instance()->GetNumericProperty("generic.current_allocated_bytes", &value);
  return value;
}

uint64_t Stats::totalCurrentlyReserved() {
  size_t value = 0;
  MallocExtension::instance()->GetNumericProperty("generic.heap_size", &value);
  return value;
}

uint64_t Stats::totalThreadCacheBytes() {
  size_t value = 0;
  MallocExtension::instance()->GetNumericProperty("tcmalloc.current_total_thread_cache_bytes",
                                                  &value);
  return value;
}

uint64_t Stats::totalPageHeapFree() {
  size_t value = 0;
  MallocExtension::instance()->GetNumericProperty("tcmalloc.pageheap_free_bytes", &value);
  return value;
}

uint64_t Stats::totalPageHeapUnmapped() {
  size_t value = 0;
  MallocExtension::instance()->GetNumericProperty("tcmalloc.pageheap_unmapped_bytes", &value);
  return value;
}

uint64_t Stats::totalPhysicalBytes() {
  size_t value = 0;
  MallocExtension::instance()->GetNumericProperty("generic.total_physical_bytes", &value);
  return value;
}

void Stats::dumpStatsToLog() {
  constexpr int buffer_size = 100000;
  auto buffer = std::make_unique<char[]>(buffer_size);
  MallocExtension::instance()->GetStats(buffer.get(), buffer_size);
  ENVOY_LOG_MISC(debug, "TCMalloc stats:\n{}", buffer.get());
}

}

Allocator::~Allocator() {
  MallocExtension::instance()->SetBackgroundProcessActionsEnabled(false);
  if (tcmalloc_thread_) {
    tcmalloc_thread_->join();
  }
}

void Allocator::configureBackgroundMemoryRelease() {
  RELEASE_ASSERT(!tcmalloc_thread_);
  if (background_release_rate_ > 0) {
    MallocExtension::instance()->SetBackgroundReleaseRate(
        MallocExtension::instance()->BytesPerSecond{background_release_rate_});
    ENVOY_LOG_MISC(info, "Configured tcmalloc with background release rate: {} bytes per second",
                   background_release_rate_);
    // `ProcessBackgroundActions` routine needs to be invoked for background memory release to be
    // operative. https://github.com/google/tcmalloc/blob/master/tcmalloc/malloc_extension.h#L635
    tcmalloc_thread_ = thread_factory_.createThread(
        []() -> void { tcmallocProcessBackgroundActionsThreadRoutine(); },
        Thread::Options{"TcmallocProcessBackgroundActions"});
  }
}

void Allocator::tcmallocProcessBackgroundActionsThreadRoutine() {
  ENVOY_LOG_MISC(debug, "Started tcmallocProcessBackgroundActionsThreadRoutine");
  if (MallocExtension::instance()->NeedsProcessBackgroundActions()) {
    // When linked against TCMalloc, this method does not return.
    // https://github.com/google/tcmalloc/blob/master/tcmalloc/malloc_extension.h#L619
    MallocExtension::instance()->ProcessBackgroundActions();
  } else {
    ENVOY_LOG_MISC(info, "Current platform does not suport tcmalloc background actions");
  }
}

} // namespace Memory
} // namespace Envoy

#else

namespace Envoy {
namespace Memory {

uint64_t Stats::totalCurrentlyAllocated() { return 0; }
uint64_t Stats::totalThreadCacheBytes() { return 0; }
uint64_t Stats::totalCurrentlyReserved() { return 0; }
uint64_t Stats::totalPageHeapUnmapped() { return 0; }
uint64_t Stats::totalPageHeapFree() { return 0; }
uint64_t Stats::totalPhysicalBytes() { return 0; }
void Stats::dumpStatsToLog() {}
void Allocator::configureBackgroundMemoryRelease() {}
void Allocator::tcmallocProcessBackgroundActionsThreadRoutine() {}

} // namespace Memory
} // namespace Envoy

#endif // #if defined(TCMALLOC)
