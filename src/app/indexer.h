// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

//#define OPENSSL 1

#include "ccf/indexing/strategies/visit_each_entry_in_map.h"
#include "ptcpp.h"

namespace app
{
  using tree_t = pt::PTreeT<32,
    pt::openssl_sha256_index, 
    pt::openssl_sha256_leaf, 
    pt::openssl_sha256_node>; 

  using hash_t = pt::HashT<32>;

  std::string timestamp() 
  {
    //TODO use instead get_untrusted_host_time_v1
    std::time_t now = std::time(nullptr);
    return std::asctime(std::localtime(&now));
  };

  class PrefixTree : public ccf::indexing::strategies::VisitEachEntryInMap
  {
  public:
    PrefixTree(const std::string& map_name) :
      ccf::indexing::strategies::VisitEachEntryInMap(map_name, "IndexByValue")
    {}

    // for all transaction in 0..n-1, 
    // last[id] is the last writing transaction for id. 
    std::map<size_t, ccf::SeqNo> last = {}; 
    tree_t::position root = new pt::Leaf(0,0); // sadly we don't do empty trees.
    size_t n = 0;   

    // updating: we are getting callbacks on committed transactions.
    // committing: we committed n as next PT root index, but don't have the PT receipt yet.
    // issuing: we have everything we need to issue read receipts up to n.
    enum State { updating, waiting, issuing };
    State state = updating; 

  protected: 
    void visit_entry(
      const ccf::TxID& tx_id,
      const ccf::ByteVector& k,
      const ccf::ByteVector& v) override
    {
      size_t key = kv::Map<size_t, std::string>::KeySerialiser::from_serialised(k);
      size_t pos = tx_id.seqno;
      LOG_INFO_FMT("PT: Inserting {} -> {}", key, pos);
      last[key] = pos; 
      tree_t::insert(pt::Leaf(key,pos), &root);
    };
  };
}