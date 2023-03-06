#include "source/extensions/filters/http/geoip/geoip_filter.h"

#include "envoy/extensions/filters/http/geoip/v3/geoip.pb.h"

#include "source/common/http/utility.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Geoip {

GeoipFilterConfig::GeoipFilterConfig(
    const envoy::extensions::filters::http::geoip::v3::Geoip& config,
    const std::string& stat_prefix, Stats::Scope& scope, Runtime::Loader& runtime)
    : scope_(scope), runtime_(runtime), stat_name_set_(scope.symbolTable().makeSet("Geoip")),
      stats_prefix_(stat_name_set_->add(stat_prefix + "geoip")),
      total_(stat_name_set_->add("total")), use_xff_(config.use_xff()),
      xff_num_trusted_hops_(config.xff_num_trusted_hops()) {
  auto geo_headers_to_add = config.geo_headers_to_add();
  geo_headers_ = processGeoHeaders({geo_headers_to_add.country(), geo_headers_to_add.city(), geo_headers_to_add.region(), geo_headers_to_add.asn()});
  geo_anon_headers_ = processGeoHeaders({geo_headers_to_add.is_anon(), geo_headers_to_add.anon_vpn(), geo_headers_to_add.anon_hosting(), geo_headers_to_add.anon_tor(), geo_headers_to_add.anon_proxy()});
  if (geo_headers_.empty() && geo_anon_headers_.empty()) {
    throw EnvoyException("No geolocation headers configured");
  }
}

absl::flat_hash_set<std::string> GeoipFilterConfig::processGeoHeaders(const absl::flat_hash_set<absl::string_view>& headers) {
  absl::flat_hash_set<std::string> geo_headers;
  for (auto header : headers) {
    if (!configured_geo_header.empty()) {
      stat_name_set_->rememberBuiltin(absl::StrCat(configured_geo_header, ".hit"));
      stat_name_set_->rememberBuiltin(absl::StrCat(configured_geo_header, ".total"));
      geo_headers.insert(std::string(configured_geo_header));
    }
  }
  return geo_headers;
}

void GeoipFilterConfig::incCounter(Stats::StatName name) {
  Stats::SymbolTable::StoragePtr storage = scope_.symbolTable().join({stats_prefix_, name});
  scope_.counterFromStatName(Stats::StatName(storage.get())).inc();
}

GeoipFilter::GeoipFilter(GeoipFilterConfigSharedPtr config, DriverSharedPtr driver)
    : config_(config), driver_(std::move(driver)) {}

GeoipFilter::~GeoipFilter() = default;

void GeoipFilter::onDestroy() {}

Http::FilterHeadersStatus GeoipFilter::decodeHeaders(Http::RequestHeaderMap& headers, bool) {
  // Save request headers for later header manipulation once geolocation lookups are complete.
  request_headers_ = &headers;

  Network::Address::InstanceConstSharedPtr remote_address;
  if (config_->use_xff() && config_->xffNumTrustedHops() > 0) {
    remote_address =
        Envoy::Http::Utility::getLastAddressFromXFF(headers, config_->xffNumTrustedHops()).address_;
  }
  // If `config_->use_xff() == false` or xff header has not been populated for some reason.
  if (!remote_address) {
    remote_address = decoder_callbacks_->streamInfo().downstreamAddressProvider().remoteAddress();
  }

  ASSERT(driver_, "No driver is available to perform geolocation lookup");

  // Capturing weak_ptr to GeoipFilter so that filter can be safely accessed in the posted callback.
  // This is a safe measure to protect against the case when filter gets deleted before the callback is run.
  GeoipFilterWeakPtr self = weak_from_this();

  driver_->lookup([self, &dispatcher = decoder_callbacks_->dispatcher()](LookupResult&& result) {
    dispatcher.post([self, result = std::move(result)]() {
      if (GeoipFilterSharedPtr filter = self.lock) {
        filter->onLookupComplete(result);
      }
    });
  });
  /*

  // The dispatcher needs to be captured because there's no guarantee that
  // decoder_callbacks_->dispatcher() is thread-safe.
  lookup_->getHeaders([self, &request_headers,
                       &dispatcher = decoder_callbacks_->dispatcher()](LookupResult&& result) {
    // The callback is posted to the dispatcher to make sure it is called on the worker thread.
    // The lambda passed to dispatcher.post() needs to be copyable as it will be used to
    // initialize a std::function. Therefore, it cannot capture anything non-copyable.
    // LookupResult is non-copyable as LookupResult::headers_ is a unique_ptr, which is
    // non-copyable. Hence, "result" is decomposed when captured, and re-instantiated inside the
    // lambda so that "result.headers_" can be captured as a raw pointer, then wrapped in a
    // unique_ptr when the result is re-instantiated.
    dispatcher.post([self, &request_headers, status = result.cache_entry_status_,
                     headers_raw_ptr = result.headers_.release(),
                     range_details = std::move(result.range_details_),
                     content_length = result.content_length_,
                     has_trailers = result.has_trailers_]() mutable {
      // Wrap the raw pointer in a unique_ptr before checking to avoid memory leaks.
      Http::ResponseHeaderMapPtr headers = absl::WrapUnique(headers_raw_ptr);
      if (CacheFilterSharedPtr cache_filter = self.lock()) {
        cache_filter->onHeaders(
            LookupResult{status, std::move(headers), content_length, range_details, has_trailers},
            request_headers);
      }
    });
  });
  */

  // Stop the iteration for headers for the current filter and the filters following.
  return allLookupsComplete() ? Http::FilterHeadersStatus::Continue
                              : Http::FilterHeadersStatus::StopIteration;
}

Http::FilterDataStatus GeoipFilter::decodeData(Buffer::Instance&, bool) {
  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus GeoipFilter::decodeTrailers(Http::RequestTrailerMap&) {
  return Http::FilterTrailersStatus::Continue;
}

void GeoipFilter::setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}

void GeoipFilter::onLookupComplete(const absl::optional<std::string>& lookup_result,
                                   const absl::optional<std::string>& geo_header) {
  ASSERT(request_headers_);
  ASSERT(num_lookups_to_perform_ > 0);
  --num_lookups_to_perform_;
  if (lookup_result) {
    request_headers_->setCopy(Http::LowerCaseString(geo_header.value()), lookup_result.value());
    config_->incHit(geo_header.value());
  }
  config_->incTotal(geo_header.value());

  ENVOY_LOG(debug, "Geoip filter: finished decoding geolocation headers");
  decoder_callbacks_->continueDecoding();

}

//TBD this may be removed
bool GeoipFilter::allLookupsComplete() {
  return all_lookups_invoked_ && num_lookups_to_perform_ == 0;
}

} // namespace Geoip
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
