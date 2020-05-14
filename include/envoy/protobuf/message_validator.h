#pragma once

#include "envoy/common/exception.h"
#include "envoy/common/pure.h"

#include "common/common/documentation_url.h"
#include "common/protobuf/protobuf.h"

#include "absl/strings/string_view.h"

namespace Envoy {
namespace ProtobufMessage {

namespace ValidationError {
const char deprecation_error[] =
    " If continued use of this field is absolutely necessary, "
    "see " ENVOY_DOC_URL_RUNTIME_OVERRIDE_DEPRECATED " for "
    "how to apply a temporary and highly discouraged override.";

/**
 * Exception class for reporting validation errors due to the presence of unknown
 * fields in a protobuf.
 */
class UnknownProtoFieldException : public EnvoyException {
public:
  UnknownProtoFieldException(const std::string& message) : EnvoyException(message) {}
};

/**
 * Exception class for reporting validation errors due to the presence of deprecated
 * fields in a protobuf.
 */
class DeprecatedProtoFieldException : public EnvoyException {
public:
  DeprecatedProtoFieldException(const std::string& message) : EnvoyException(message) {}
};

} // namespace ValidationError

enum ValidationType {
  UnknownFields,
  DeprecatedFields,
};

/**
 * Visitor interface for a Protobuf::Message. The methods of ValidationVisitor are invoked to
 * perform validation based on events encountered during or after the parsing of proto binary
 * or JSON/YAML.
 */
class ValidationVisitor {
public:
  virtual ~ValidationVisitor() = default;

  /**
   * Invoked when an unknown field is encountered.
   * @param description human readable description of the field
   */
  virtual void onUnknownField(absl::string_view description) PURE;

  /**
   * If true, skip this validation visitor in the interest of speed when
   * possible.
   **/
  virtual bool skipValidation() PURE;

  /**
   * Invoked when deprecated field is encountered.
   * @param description human readable description of the field
   */
  virtual void onDeprecatedField(absl::string_view description) PURE;
};

class ValidationContext {
public:
  virtual ~ValidationContext() = default;

  /**
   * @return ValidationVisitor& the validation visitor for static configuration.
   */
  virtual ValidationVisitor& staticValidationVisitor() PURE;

  /**
   * @return ValidationVisitor& the validation visitor for dynamic configuration.
   */
  virtual ValidationVisitor& dynamicValidationVisitor() PURE;
};

} // namespace ProtobufMessage
} // namespace Envoy
