#include "source/extensions/filters/http/ip_tagging/ip_tagging_loader.h"

#include "envoy/extensions/filters/http/ip_tagging/v3/ip_tagging.pb.h"
#include "envoy/extensions/filters/http/ip_tagging/v3/ip_tagging.pb.validate.h"

#include "source/common/protobuf/utility.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IpTagging {

IpTagsProvider::IpTagsProvider(const std::string& ip_tags_path, IpTagsLoader& tags_loader,
                               IpTagsReloadSuccessCb reload_success_cb,
                               IpTagsReloadErrorCb reload_error_cb, Event::Dispatcher& dispatcher,
                               Api::Api& api, Singleton::InstanceSharedPtr owner)
    : ip_tags_path_(ip_tags_path), tags_loader_(tags_loader), reload_success_cb_(reload_success_cb),
      reload_error_cb_(reload_error_cb), tags_(tags_loader_.loadTags(ip_tags_path_)),
      ip_tags_reload_dispatcher_(api.allocateDispatcher("ip_tags_reload_routine")),
      ip_tags_file_watcher_(dispatcher.createFilesystemWatcher()), owner_(owner) {
  if (ip_tags_path.empty()) {
    throw EnvoyException("Cannot load tags from empty file path.");
  }
  ip_tags_reload_thread_ = api.threadFactory().createThread(
      [this]() -> void {
        ENVOY_LOG_MISC(debug, "Started ip_tags_reload_routine");
        THROW_IF_NOT_OK(
            ip_tags_file_watcher_->addWatch(ip_tags_path_, Filesystem::Watcher::Events::MovedTo,
                                            [this](uint32_t) { return onIpTagsFileUpdate(); }));
        ip_tags_reload_dispatcher_->run(Event::Dispatcher::RunType::RunUntilExit);
      },
      Thread::Options{std::string("ip_tags_reload_routine")});
}

IpTagsProvider::~IpTagsProvider() {
  ENVOY_LOG(debug, "Shutting down ip tags provider");
  ip_tags_reload_dispatcher_->exit();
  if (ip_tags_reload_thread_) {
    ip_tags_reload_thread_->join();
    ip_tags_reload_thread_.reset();
  }
};

LcTrieSharedPtr IpTagsProvider::ipTags() const ABSL_LOCKS_EXCLUDED(ip_tags_mutex_) {
  absl::ReaderMutexLock lock(&ip_tags_mutex_);
  return tags_;
};

absl::Status IpTagsProvider::onIpTagsFileUpdate() {
  LcTrieSharedPtr reloaded_tags = tags_loader_.loadTags(ip_tags_path_);
  return ipTagsReload(reloaded_tags);
}

absl::Status IpTagsProvider::ipTagsReload(const LcTrieSharedPtr reloaded_tags) {
  if (reloaded_tags) {
    updateIpTags(reloaded_tags);
    reload_success_cb_();
  } else {
    reload_error_cb_();
  }
  return absl::OkStatus();
}

void IpTagsProvider::updateIpTags(const LcTrieSharedPtr reloaded_tags)
    ABSL_LOCKS_EXCLUDED(ip_tags_mutex_) {
  absl::MutexLock lock(&ip_tags_mutex_);
  tags_ = reloaded_tags;
}

IpTagsLoader::IpTagsLoader(Api::Api& api, ProtobufMessage::ValidationVisitor& validation_visitor,
                           Stats::StatNameSetPtr& stat_name_set)
    : api_(api), validation_visitor_(validation_visitor), stat_name_set_(stat_name_set) {}

LcTrieSharedPtr IpTagsLoader::loadTags(const std::string& ip_tags_path) {
  if (!ip_tags_path.empty()) {
    if (!absl::EndsWith(ip_tags_path, MessageUtil::FileExtensions::get().Yaml) &&
        !absl::EndsWith(ip_tags_path, MessageUtil::FileExtensions::get().Json)) {
      throw EnvoyException("Unsupported file format, unable to parse ip tags from file.");
    }
    auto file_or_error = api_.fileSystem().fileReadToEnd(ip_tags_path);
    if (file_or_error.status().ok()) {
      IpTagFileProto ip_tags_proto;
      if (absl::EndsWith(ip_tags_path, MessageUtil::FileExtensions::get().Yaml)) {
        try {
          MessageUtil::loadFromYaml(file_or_error.value(), ip_tags_proto, validation_visitor_);
        } catch (const EnvoyException& e) {
          ENVOY_LOG_MISC(warn, "failed to parse ip tags file: {}", e.what());
          return nullptr;
        }
      } else if (absl::EndsWith(ip_tags_path, MessageUtil::FileExtensions::get().Json)) {
        try {
          MessageUtil::loadFromJson(file_or_error.value(), ip_tags_proto, validation_visitor_);
        } catch (const EnvoyException& e) {
          ENVOY_LOG_MISC(warn, "failed to parse ip tags file: {}", e.what());
          return nullptr;
        }
      }
      return parseIpTags(ip_tags_proto.ip_tags());
    } else {
      return nullptr;
    }
  }
  return nullptr;
}

LcTrieSharedPtr IpTagsLoader::parseIpTags(
    const Protobuf::RepeatedPtrField<envoy::data::ip_tagging::v3::IPTag>& ip_tags) {
  std::vector<std::pair<std::string, std::vector<Network::Address::CidrRange>>> tag_data;
  tag_data.reserve(ip_tags.size());
  for (const auto& ip_tag : ip_tags) {
    std::vector<Network::Address::CidrRange> cidr_set;
    cidr_set.reserve(ip_tag.ip_list().size());
    for (const envoy::config::core::v3::CidrRange& entry : ip_tag.ip_list()) {
      absl::StatusOr<Network::Address::CidrRange> cidr_or_error =
          Network::Address::CidrRange::create(entry);
      if (cidr_or_error.status().ok()) {
        cidr_set.emplace_back(std::move(cidr_or_error.value()));
      } else {
        throw EnvoyException(
            fmt::format("invalid ip/mask combo '{}/{}' (format is <ip>/<# mask bits>)",
                        entry.address_prefix(), entry.prefix_len().value()));
      }
    }
    tag_data.emplace_back(ip_tag.ip_tag_name(), cidr_set);
    stat_name_set_->rememberBuiltin(absl::StrCat(ip_tag.ip_tag_name(), ".hit"));
  }
  return std::make_shared<Network::LcTrie::LcTrie<std::string>>(tag_data);
    }


  IpTagsRegistrySingleton::IpTagsRegistrySingleton() { std::cerr << "****Create " << std::endl; };

  std::shared_ptr<IpTagsProvider> IpTagsRegistrySingleton::get(const std::string& ip_tags_path, IpTagsLoader& tags_loader,
                                      IpTagsReloadSuccessCb reload_success_cb,
                                      IpTagsReloadErrorCb reload_error_cb, Api::Api& api,
                                      Event::Dispatcher& dispatcher,
                                      std::shared_ptr<IpTagsRegistrySingleton> singleton) {
    std::shared_ptr<IpTagsProvider> ip_tags_provider;
    const uint64_t key = std::hash<std::string>()(ip_tags_path);
    absl::MutexLock lock(&mu_);
    auto it = ip_tags_registry_.find(key);
    std::cerr << "****Found provider " << std::endl;
    if (it != ip_tags_registry_.end()) {
      if (std::shared_ptr<IpTagsProvider> provider = it->second.lock()) {
        std::cerr << "****Returning existing provider " << std::endl;
        ip_tags_provider = provider;
      } else {
        ip_tags_provider =
            std::make_shared<IpTagsProvider>(ip_tags_path, tags_loader, reload_success_cb,
                                             reload_error_cb, dispatcher, api, singleton);
        ip_tags_registry_[key] = ip_tags_provider;
      }
    } else {
      std::cerr << "****Creating new provider " << std::endl;
      ip_tags_provider =
          std::make_shared<IpTagsProvider>(ip_tags_path, tags_loader, reload_success_cb,
                                           reload_error_cb, dispatcher, api, singleton);
      ip_tags_registry_[key] = ip_tags_provider;
    }
    return ip_tags_provider;
  }


SINGLETON_MANAGER_REGISTRATION(ip_tags_registry);

std::shared_ptr<IpTagsRegistrySingleton> IpTagsRegistrySingleton::getInstance(Server::Configuration::FactoryContext& context) {
  if (instance_) {
    return instance_;
  } else {
      return context.serverFactoryContext().singletonManager().getTyped<IpTagsRegistrySingleton>(
          SINGLETON_MANAGER_REGISTERED_NAME(ip_tags_registry),
          [] { return std::make_shared<IpTagsRegistrySingleton>(); });
  }
}

} // namespace IpTagging
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
