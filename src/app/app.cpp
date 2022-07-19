// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/hash.h"
#include "ccf/historical_queries_adapter.h"
#include "ccf/http_query.h"
#include "ccf/json_handler.h"
#include "ccf/version.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <string>

#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "indexer.h"

namespace app
{
  // Key-value store types
  using Map = kv::Map<size_t, std::string>;
  static constexpr auto RECORDS = "records";
  
  struct Root
  {
    std::string time; // time of writing this entry
    size_t seqno;
    std::string digest; // root of the prefix tree recording last writer for all keys in all transactions in 0..seqno
  };
  using Roots = kv::Map<size_t, Root>;
  DECLARE_JSON_TYPE(Root);
  DECLARE_JSON_REQUIRED_FIELDS(Root, time, seqno, digest);
  static constexpr auto ROOTS = "roots";

  // API types
  struct Write
  {
    struct In
    {
      std::string msg;
    };

    using Out = void;
  };
  DECLARE_JSON_TYPE(Write::In);
  DECLARE_JSON_REQUIRED_FIELDS(Write::In, msg);

  struct ReadReceipt
  {
    struct Out
    {
      // std::size_t tx_id;
      // std::string time;
      std::vector<std::string> path; 
    };
  };
  DECLARE_JSON_TYPE(ReadReceipt::Out);
  DECLARE_JSON_REQUIRED_FIELDS(ReadReceipt::Out, /* tx_id, time, */ path);

  class AppHandlers : public ccf::UserEndpointRegistry
  {
  public:
    std::shared_ptr<PrefixTree> ptree = nullptr;
    // std::shared_ptr<ccf::indexing::LazyStrategy<PrefixTree>> ptree = nullptr;

    AppHandlers(ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context)
    {
      openapi_info.title = "CCF Sample C++ App";
      openapi_info.description =
        "This minimal CCF C++ application aims to be "
        "used as a template for CCF developers.";
      openapi_info.document_version = "0.0.1";

      ptree = std::make_shared<PrefixTree>(RECORDS);
      context.get_indexing_strategies().install_strategy(ptree);


      auto write = [this](auto& ctx, nlohmann::json&& params) {
        const auto parsed_query =
          http::parse_query(ctx.rpc_ctx->get_request_query());

        std::string error_reason;
        size_t id = 0;
        if (!http::get_query_value(parsed_query, "id", id, error_reason))
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            std::move(error_reason));
        }

        const auto in = params.get<Write::In>();
        if (in.msg.empty())
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            "Cannot record an empty log message.");
        }

        auto records_handle = ctx.tx.template rw<Map>(RECORDS);
        records_handle->put(id, in.msg);
        return ccf::make_success();
      };
      make_endpoint(
        "/log", HTTP_POST, ccf::json_adapter(write), ccf::no_auth_required)
        .set_auto_schema<Write::In, void>()
        .add_query_parameter<size_t>("id")
        .install();

  
      auto read = [this](auto& ctx, nlohmann::json&& params) {
        const auto parsed_query =
          http::parse_query(ctx.rpc_ctx->get_request_query());

        std::string error_reason;
        size_t id = 0;
        if (!http::get_query_value(parsed_query, "id", id, error_reason))
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            std::move(error_reason));
        }

        auto records_handle = ctx.tx.template ro<Map>(RECORDS);
        auto msg = records_handle->get(id);
        if (!msg.has_value())
        {
          return ccf::make_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            fmt::format("Cannot find record for id \"{}\".", id));
        }
        return ccf::make_success(msg.value());
      };
      make_read_only_endpoint(
        "/log",
        HTTP_GET,
        ccf::json_read_only_adapter(read),
        ccf::no_auth_required)
        .set_auto_schema<void, void>()
        .add_query_parameter<size_t>("id")
        .install();
 

      auto read_receipt = [this](auto& ctx, nlohmann::json&& params) {
        const auto parsed_query =
          http::parse_query(ctx.rpc_ctx->get_request_query());

        std::string error_reason;
        size_t id = 0;
        if (!http::get_query_value(parsed_query, "id", id, error_reason))
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            std::move(error_reason));
        }

        // TODO state logic to ensure ptree is synced with last committed Root
        auto path = tree_t::get_path(id, ptree->root);

        ReadReceipt::Out response;
        for (const auto& hash : path)
        {
          response.path.push_back(hash.to_string());
        }

        return ccf::make_success(response);
      };
      make_read_only_endpoint(
        "/read_receipt",
        HTTP_GET,
        ccf::json_read_only_adapter(read_receipt),
        ccf::no_auth_required)
        .set_auto_schema<void, ReadReceipt::Out>()
        .add_query_parameter<size_t>("id")
        .install();

      auto refresh = [this](auto& ctx, nlohmann::json&& params) {
        const auto parsed_query =
          http::parse_query(ctx.rpc_ctx->get_request_query());

        // TODO: we would normally sort & insert all cached leaves only at this point.

        // recompute root 
        hash_t digest;
        tree_t::root(ptree->root, digest); 

        Root fresh; 
        fresh.time = timestamp();
        fresh.seqno = ptree->n;
        fresh.digest = digest.to_string();

        LOG_INFO_FMT("PT: time={} seqno={} digest={}", fresh.time, fresh.seqno, fresh.digest);

        auto roots = ctx.tx.template rw<Roots>(ROOTS);
        roots->put(roots->size(), fresh);
        return ccf::make_success(fresh); //$ not getting this back; why? 
        };
      make_endpoint(
        "/refresh",
        HTTP_GET,
        ccf::json_adapter(refresh),
        ccf::no_auth_required)
        .set_auto_schema<void, Root>()
        .install();
    }
  };
} // namespace app

namespace ccfapp
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccfapp::AbstractNodeContext& context)
  {
    return std::make_unique<app::AppHandlers>(context);
  }
} // namespace ccfapp