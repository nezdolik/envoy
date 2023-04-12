#pragma once

#include "source/extensions/filters/http/geop/geoip_provider_config.h"


namespace Envoy {
namespace Extensions {
namespace GeoipProviders {
namespace Maxmind {

using MaxmindDbOptRef = OptRef<MMDB_s>;

class GeoipProvider: public Envoy::Extensions::HttpFilters::Geoip::Driver {

public:
GeoipProvider(absl::flat_hash_set<std::string> geo_headers, absl::flat_hash_set<std::string> geo_anon_headers_, GeoipFilterConfigSharedPtr config):
geo_headers_(geo_headers), geo_anon_headers_(geo_anon_headers),config_(config){
    maxmind_db = initMaxMindDb();
};

private:
absl::flat_hash_set<std::string> geo_headers_;
absl::flat_hash_set<std::string> geo_anon_headers_;
ProviderConfigSharedPtr config_;
MaxmindDbOptRef maxmind_db;

MaxmindDbOptRef initMaxMindDb() {};
}

} // namespace Maxmind
} // namespace GeoipProviders
} // namespace Extensions
} // namespace Envoy