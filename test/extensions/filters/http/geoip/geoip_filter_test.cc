#include "envoy/extensions/filters/http/geoip/v3/geoip.pb.h"

#include "source/common/network/address_impl.h"
#include "source/common/network/utility.h"
#include "source/extensions/filters/http/geoip/geoip_filter.h"

#include "test/extensions/filters/http/geoip/mocks.h"
#include "test/mocks/http/mocks.h"
#include "test/mocks/runtime/mocks.h"
#include "test/mocks/stats/mocks.h"
#include "test/test_common/registry.h"
#include "test/test_common/test_runtime.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::DoAll;
using testing::ReturnRef;
using testing::SaveArg;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Geoip {
namespace {

MATCHER_P2(HasExpectedHeader, expected_header, expected_value, "") {
  auto request_headers = static_cast<Http::TestRequestHeaderMapImpl>(arg);
  EXPECT_TRUE(request_headers.has(expected_header));
  EXPECT_EQ(
      expected_value,
      request_headers.get(Http::LowerCaseString(expected_header))[0]->value().getStringView());
  return true;
}

class GeoipFilterTest : public testing::Test {
public:
  GeoipFilterTest()
      : dummy_factory_(new DummyGeoipProviderFactory()), dummy_driver_(dummy_factory_->getDriver()),
        empty_response_(absl::nullopt), dummy_city_("dummy_city"), dummy_country_("dummy_country"),
        dummy_region_("dummy_region"), dummy_asn_("dummy_asn"), dummy_anon_response_("true") {}

  void initializeFilter(const std::string& yaml) {
    ON_CALL(filter_callbacks_, dispatcher()).WillByDefault(::testing::ReturnRef(*dispatcher_));
    envoy::extensions::filters::http::geoip::v3::Geoip config;
    TestUtility::loadFromYaml(yaml, config);
    config_ = std::make_shared<GeoipFilterConfig>(config, "prefix.", stats_, runtime_);
    filter_ = std::make_unique<GeoipFilter>(config_, dummy_driver_);
    filter_->setDecoderFilterCallbacks(filter_callbacks_);
  }

  void initializeProviderFactory() {
    TestScopedRuntime scoped_runtime;
    scoped_runtime.mergeValues(
        {{"envoy.reloadable_features.no_extension_lookup_by_name", "false"}});
    Registry::InjectFactory<GeoipProviderFactory> registered(*dummy_factory_);
  }

  void expectStats(const std::string& geo_header) {
    EXPECT_CALL(stats_, counter(absl::StrCat("prefix.geoip.", geo_header, ".total")));
    EXPECT_CALL(stats_, counter(absl::StrCat("prefix.geoip.", geo_header, ".hit")));
  }

  ~GeoipFilterTest() override { filter_->onDestroy(); }

  NiceMock<Stats::MockStore> stats_;
  GeoipFilterConfigSharedPtr config_;
  std::unique_ptr<GeoipFilter> filter_;
  std::unique_ptr<DummyGeoipProviderFactory> dummy_factory_;
  MockDriverSharedPtr dummy_driver_;
  NiceMock<Http::MockStreamDecoderFilterCallbacks> filter_callbacks_;
  NiceMock<Runtime::MockLoader> runtime_;
  Api::ApiPtr api_ = Api::createApiForTest();
  Event::DispatcherPtr dispatcher_ = api_->allocateDispatcher("test_thread");
  absl::optional<std::string> empty_response_;
  absl::optional<std::string> dummy_city_;
  absl::optional<std::string> dummy_country_;
  absl::optional<std::string> dummy_region_;
  absl::optional<std::string> dummy_asn_;
  absl::optional<std::string> dummy_anon_response_;
  LookupRequest captured_rq_;
  LookupGeoHeadersCallback captured_cb_;
};

TEST_F(GeoipFilterTest, NoXffSuccessfulLookup) {
  initializeProviderFactory();
  const std::string external_request_yaml = R"EOF(
    geo_headers_to_add:
      city: "x-geo-city"
    provider:
        name: "envoy.geoip_providers.dummy"
)EOF";
  initializeFilter(external_request_yaml);
  Http::TestRequestHeaderMapImpl request_headers;
  expectStats("x-geo-city");
  Network::Address::InstanceConstSharedPtr remote_address =
      Network::Utility::parseInternetAddress("1.2.3.4");
  filter_callbacks_.stream_info_.downstream_connection_info_provider_->setRemoteAddress(
      remote_address);
  EXPECT_CALL(*dummy_driver_, lookup(_,_)).WillRepeatedly(DoAll(SaveArg<0>(&captured_rq_), SaveArg<1>(&captured_cb_),Invoke([this]() {
    captured_cb_(LookupResult{{"x-geo-city",absl::make_optional("dummy-city")}});
  })));
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration,
            filter_->decodeHeaders(request_headers, false));
  EXPECT_CALL(filter_callbacks_, continueDecoding());
  const absl::flat_hash_map<std::string, absl::optional<std::string>> result = {{"x-geo-city", dummy_city_}};
  dispatcher_->run(Event::Dispatcher::RunType::Block);
  //filter_->onLookupComplete(std::move(result));
  EXPECT_EQ(1, request_headers.size());
  ::testing::Mock::VerifyAndClearExpectations(&filter_callbacks_);
  //EXPECT_THAT(request_headers, HasExpectedHeader( "x-geo-city", "dummy_city"));
  //EXPECT_EQ("1.2.3.4:0", captured_address_->asString());
}

// TEST_F(GeoipFilterTest, UseXffSuccessfulLookup) {
//   initializeProviderFactory();
//   const std::string external_request_yaml = R"EOF(
//     use_xff: true
//     xff_num_trusted_hops: 1
//     geo_headers_to_add:
//       region: "x-geo-region"
//     provider:
//         name: "envoy.geoip_providers.dummy"
// )EOF";
//   initializeFilter(external_request_yaml);
//   Http::TestRequestHeaderMapImpl request_headers;
//   request_headers.addCopy("x-forwarded-for", "10.0.0.1,10.0.0.2");
//   expectStats("x-geo-region");
//   Network::Address::InstanceConstSharedPtr remote_address =
//       Network::Utility::parseInternetAddress("1.2.3.4");
//   filter_callbacks_.stream_info_.downstream_connection_info_provider_->setRemoteAddress(
//       remote_address);
//   EXPECT_EQ(Http::FilterHeadersStatus::StopIteration,
//             filter_->decodeHeaders(request_headers, false));
//   EXPECT_CALL(filter_callbacks_, continueDecoding());
//   filter_->onLookupComplete(dummy_region_, "x-geo-region");
//   EXPECT_EQ(2, request_headers.size());
//   EXPECT_THAT(request_headers, HasExpectedHeader( "x-geo-region", "dummy_region"));
//   EXPECT_EQ("10.0.0.1:0", captured_address_->asString());
// }

// TEST_F(GeoipFilterTest, GeoHeadersOverridenForIncomingRequest) {
//   initializeProviderFactory();
//   const std::string external_request_yaml = R"EOF(
//     geo_headers_to_add:
//       region: "x-geo-region"
//       city:   "x-geo-city"
//     provider:
//         name: "envoy.geoip_providers.dummy"
// )EOF";
//   initializeFilter(external_request_yaml);
//   Http::TestRequestHeaderMapImpl request_headers;
//   request_headers.addCopy("x-geo-region", "ngnix_region");
//   request_headers.addCopy("x-geo-city", "ngnix_city");
//   std::map<std::string, std::string> geo_headers = {{"x-geo-region", "dummy_region"},
//                                                     {"x-geo-city", "dummy_city"}};
//   for (auto iter = geo_headers.begin(); iter != geo_headers.end(); ++iter) {
//     auto& header = iter->first;
//     expectStats(header);
//   }
//   Network::Address::InstanceConstSharedPtr remote_address =
//       Network::Utility::parseInternetAddress("1.2.3.4");
//   filter_callbacks_.stream_info_.downstream_connection_info_provider_->setRemoteAddress(
//       remote_address);
//   EXPECT_CALL(*dummy_driver_, getCity(_, _, _))
//       .WillRepeatedly(DoAll(SaveArg<0>(&captured_address_), Invoke([this]() {
//                               filter_->onLookupComplete(dummy_city_, "x-geo-city");
//                             })));
//   EXPECT_CALL(*dummy_driver_, getRegion(_, _, _))
//       .WillRepeatedly(DoAll(SaveArg<0>(&captured_address_), Invoke([this]() {
//                               filter_->onLookupComplete(dummy_region_, "x-geo-region");
//                             })));
//   EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(request_headers, false));
//   EXPECT_THAT(request_headers, HasExpectedHeader( "x-geo-city", "dummy_city"));
//   EXPECT_EQ(2, request_headers.size());
//   EXPECT_EQ("1.2.3.4:0", captured_address_->asString());
// }

// TEST_F(GeoipFilterTest, AllHeadersPropagatedCorrectly) {
//   initializeProviderFactory();
//   const std::string external_request_yaml = R"EOF(
//     geo_headers_to_add:
//       region:       "x-geo-region"
//       country:      "x-geo-country"
//       city:         "x-geo-city"
//       asn:          "x-geo-asn"
//       is_anon:      "x-geo-anon"
//       anon_vpn:     "x-geo-anon-vpn"
//       anon_hosting: "x-geo-anon-hosting"
//       anon_tor:     "x-geo-anon-tor"
//       anon_proxy:   "x-geo-anon-proxy"
//     provider:
//         name: "envoy.geoip_providers.dummy"
// )EOF";
//   initializeFilter(external_request_yaml);
//   Http::TestRequestHeaderMapImpl request_headers;
//   std::map<std::string, std::string> geo_headers = {{"x-geo-region", "dummy_region"},
//                                                     {"x-geo-city", "dummy_city"},
//                                                     {"x-geo-country", "dummy_country"},
//                                                     {"x-geo-asn", "dummy_asn"},
//                                                     {"x-geo-anon", "true"},
//                                                     {"x-geo-anon-vpn", "true"},
//                                                     {"x-geo-anon-hosting", "true"},
//                                                     {"x-geo-anon-tor", "true"},
//                                                     {"x-geo-anon-proxy", "true"}};
//   for (auto iter = geo_headers.begin(); iter != geo_headers.end(); ++iter) {
//     auto& header = iter->first;
//     expectStats(header);
//   }
//   Network::Address::InstanceConstSharedPtr remote_address =
//       Network::Utility::parseInternetAddress("1.2.3.4");
//   filter_callbacks_.stream_info_.downstream_connection_info_provider_->setRemoteAddress(
//       remote_address);
//   EXPECT_EQ(Http::FilterHeadersStatus::StopIteration,
//             filter_->decodeHeaders(request_headers, false));
//   EXPECT_CALL(filter_callbacks_, continueDecoding());
//   filter_->onLookupComplete(dummy_region_, "x-geo-region");
//   filter_->onLookupComplete(dummy_country_, "x-geo-country");
//   filter_->onLookupComplete(dummy_city_, "x-geo-city");
//   filter_->onLookupComplete(dummy_asn_, "x-geo-asn");
//   filter_->onLookupComplete(dummy_anon_response_, "x-geo-anon");
//   filter_->onLookupComplete(dummy_anon_response_, "x-geo-anon-vpn");
//   filter_->onLookupComplete(dummy_anon_response_, "x-geo-anon-hosting");
//   filter_->onLookupComplete(dummy_anon_response_, "x-geo-anon-tor");
//   filter_->onLookupComplete(dummy_anon_response_, "x-geo-anon-proxy");
//   EXPECT_EQ(9, request_headers.size());
//   for (auto iter = geo_headers.begin(); iter != geo_headers.end(); ++iter) {
//     auto& header = iter->first;
//     auto& value = iter->second;
//     EXPECT_THAT(request_headers, HasExpectedHeader( header, value));
//   }
//   EXPECT_EQ("1.2.3.4:0", captured_address_->asString());
// }

// TEST_F(GeoipFilterTest, GeoHeaderNotAppendedOnEmptyLookup) {
//   initializeProviderFactory();
//   const std::string external_request_yaml = R"EOF(
//     geo_headers_to_add:
//       region: "x-geo-region"
//       city:   "x-geo-city"
//     provider:
//         name: "envoy.geoip_providers.dummy"
// )EOF";
//   initializeFilter(external_request_yaml);
//   Http::TestRequestHeaderMapImpl request_headers;
//   EXPECT_CALL(stats_, counter("prefix.geoip.x-geo-city.total"));
//   EXPECT_CALL(stats_, counter("prefix.geoip.x-geo-city.hit")).Times(0);
//   EXPECT_CALL(stats_, counter("prefix.geoip.x-geo-region.total"));
//   EXPECT_CALL(stats_, counter("prefix.geoip.x-geo-region.hit"));
//   Network::Address::InstanceConstSharedPtr remote_address =
//       Network::Utility::parseInternetAddress("1.2.3.4");
//   filter_callbacks_.stream_info_.downstream_connection_info_provider_->setRemoteAddress(
//       remote_address);
//   EXPECT_EQ(Http::FilterHeadersStatus::StopIteration,
//             filter_->decodeHeaders(request_headers, false));
//   EXPECT_CALL(filter_callbacks_, continueDecoding());
//   filter_->onLookupComplete(dummy_region_, "x-geo-region");
//   filter_->onLookupComplete(empty_response_, "x-geo-city");

//   EXPECT_EQ(1, request_headers.size());
//   EXPECT_THAT(request_headers, HasExpectedHeader( "x-geo-region", "dummy_region"));
//   EXPECT_EQ("1.2.3.4:0", captured_address_->asString());
// }

} // namespace
} // namespace Geoip
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
