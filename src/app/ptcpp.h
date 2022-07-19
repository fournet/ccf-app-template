// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <array>
#include <cassert>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <list>
#include <memory>
#include <sstream>
#include <stack>
#include <variant>
#include <vector>

#define HAVE_OPENSSL

#ifdef HAVE_OPENSSL
#  include <openssl/sha.h>
#endif

#ifdef HAVE_MBEDTLS
#  include <mbedtls/sha256.h>
#endif

#ifdef PTCPP_TRACE_ENABLED
// Hashes in the trace output are truncated to TRACE_HASH_SIZE bytes.
#  define TRACE_HASH_SIZE 3

#  ifndef PTCPP_TRACE
#    include <iostream>
#    define PTCPP_TOUT std::cout
#    define PTCPP_TRACE(X) \
      { \
        X; \
        PTCPP_TOUT.flush(); \
      };
#  endif
#else
#  define PTCPP_TRACE(X)
#endif

#define PTCPP_VERSION_MAJOR 1
#define PTCPP_VERSION_MINOR 0
#define PTCPP_VERSION_PATCH 0

namespace pt
{
  static inline uint32_t convert_endianness(uint32_t n)
  {
    const uint32_t sz = sizeof(uint32_t);
#if defined(htobe32)
    // If htobe32 happens to be a macro, use it.
    return htobe32(n);
#elif defined(__LITTLE_ENDIAN__) || defined(__LITTLE_ENDIAN)
    // Just as fast.
    uint32_t r = 0;
    for (size_t i = 0; i < sz; i++)
      r |= ((n >> (8 * ((sz - 1) - i))) & 0xFF) << (8 * i);
    return *reinterpret_cast<uint32_t*>(&r);
#else
    // A little slower, but works for both endiannesses.
    uint8_t r[8];
    for (size_t i = 0; i < sz; i++)
      r[i] = (n >> (8 * ((sz - 1) - i))) & 0xFF;
    return *reinterpret_cast<uint32_t*>(&r);
#endif
  }

  static inline void serialise_uint16_t(uint16_t n, std::vector<uint8_t>& bytes)
  {
    size_t sz = sizeof(uint16_t);
    bytes.reserve(bytes.size() + sz);
    for (uint64_t i = 0; i < sz; i++)
      bytes.push_back((n >> (8 * (sz - i - 1))) & 0xFF);
  }

  static inline uint64_t deserialise_uint16_t(
    const std::vector<uint8_t>& bytes, size_t& index)
  {
    uint16_t r = 0;
    uint64_t sz = sizeof(uint16_t);
    for (uint64_t i = 0; i < sz; i++)
      r |= static_cast<uint16_t>(bytes.at(index++)) << (8 * (sz - i - 1));
    return r;
  }

  static inline void serialise_uint64_t(uint64_t n, std::vector<uint8_t>& bytes)
  {
    size_t sz = sizeof(uint64_t);
    bytes.reserve(bytes.size() + sz);
    for (uint64_t i = 0; i < sz; i++)
      bytes.push_back((n >> (8 * (sz - i - 1))) & 0xFF);
  }

  static inline uint64_t deserialise_uint64_t(
    const std::vector<uint8_t>& bytes, size_t& index)
  {
    uint64_t r = 0;
    uint64_t sz = sizeof(uint64_t);
    for (uint64_t i = 0; i < sz; i++)
      r |= static_cast<uint64_t>(bytes.at(index++)) << (8 * (sz - i - 1));
    return r;
  }

  /// @brief Template for fixed-size hashes
  /// @tparam SIZE Size of the hash in number of bytes
  template <size_t SIZE>
  struct HashT
  {
    /// Holds the hash bytes
    uint8_t bytes[SIZE];

    /// @brief Constructs a Hash with all bytes set to zero
    HashT<SIZE>()
    {
      std::fill(bytes, bytes + SIZE, 0);
    }

    /// @brief Constructs a canonical representation of the first i bits of
    /// hash, padded with 10*
    HashT<SIZE> copy_prefix(const size_t i) const
    {
      HashT<SIZE> res;
      std::copy(this->bytes, this->bytes + i / 8 + 1, res.bytes);
      std::fill(res.bytes + i / 8 + 1, res.bytes + SIZE, 0);
      res.bytes[i / 8] &= (255 >> (8 - i % 8));
      res.set_bit(i, 1);
      return res;
    }

    /// @brief Constructs a Hash from a byte buffer
    /// @param bytes Buffer with hash value
    HashT<SIZE>(const uint8_t* bytes)
    {
      std::copy(bytes, bytes + SIZE, this->bytes);
    }

    /// @brief Constructs a Hash from an integer
    /// @param n0 provides the first bytes; the rest are zeros.
    HashT<SIZE>(const size_t n)
    {
      auto len = sizeof(size_t);
      if (len > SIZE)
        printf("invalid hash constructor %lu %lu\n", SIZE, n);
      else
      {
        std::memcpy(bytes, &n, len);
        std::fill(bytes + len, bytes + SIZE, 0);
      };
    }

    /// @brief Constructs a Hash from a string
    /// @param s String to read the hash value from
    HashT<SIZE>(const std::string& s)
    {
      if (s.length() != 2 * SIZE)
        throw std::runtime_error("invalid hash string");
      for (size_t i = 0; i < SIZE; i++)
      {
        int tmp;
        sscanf(s.c_str() + 2 * i, "%02x", &tmp);
        bytes[i] = tmp;
      }
    }

    /// @brief Deserialises a Hash from a vector of bytes
    /// @param bytes Vector to read the hash value from
    HashT<SIZE>(const std::vector<uint8_t>& bytes)
    {
      if (bytes.size() < SIZE)
        throw std::runtime_error("not enough bytes");
      deserialise(bytes);
    }

    /// @brief Deserialises a Hash from a vector of bytes
    /// @param bytes Vector to read the hash value from
    /// @param position Position of the first byte in @p bytes
    HashT<SIZE>(const std::vector<uint8_t>& bytes, size_t& position)
    {
      if (bytes.size() - position < SIZE)
        throw std::runtime_error("not enough bytes");
      deserialise(bytes, position);
    }

    /// @brief Deserialises a Hash from an array of bytes
    /// @param bytes Array to read the hash value from
    HashT<SIZE>(const std::array<uint8_t, SIZE>& bytes)
    {
      std::copy(bytes.data(), bytes.data() + SIZE, this->bytes);
    }

    /// @brief The size of the hash (in number of bytes)
    size_t size() const
    {
      return SIZE;
    }

    /// @brief Reads the ith bit of the hash
    inline bool bit(size_t i) const
    {
      return (bytes[i / 8] >> (i % 8)) & 1;
    }

    /// @brief Sets the ith bit of the hash
    inline void set_bit(size_t i, bool b)
    {
      uint8_t mask = 1 << i % 8;
      bytes[i / 8] = b ? (bytes[i / 8] | mask) : (bytes[i / 8] & ~mask);
    }

    /// @brief zeros out all bytes in the hash
    void zero()
    {
      std::fill(bytes, bytes + SIZE, 0);
    }

    /// @brief The size of the serialisation of the hash (in number of bytes)
    size_t serialised_size() const
    {
      return SIZE;
    }

    /// @brief Convert a hash to a hex-encoded string
    /// @param num_bytes The maximum number of bytes to convert
    /// @param lower_case Enables lower-case hex characters
    std::string to_string(size_t num_bytes = SIZE, bool lower_case = true) const
    {
      size_t num_chars = 2 * num_bytes;
      std::string r(num_chars, '_');
      for (size_t i = 0; i < num_bytes; i++)
        snprintf(
          const_cast<char*>(r.data() + 2 * i),
          num_chars + 1 - 2 * i,
          lower_case ? "%02x" : "%02X",
          bytes[i]);
      return r;
    }

    /// @brief Convert a hash to a [01]* string
    /// @param cut indicates how many bits to print
    std::string to_bitstring(size_t n = SIZE * 8) const
    {
      size_t m = std::min<size_t>(n, 70); // truncate for readability
      std::string r(m, '0');
      for (size_t i = 0; i < m; i++)
        r[i] = this->bit(i) ? '1' : '0';
      if (m < n)
        r += "...";
      return r;
    }

    /// @brief Hash assignment operator
    //HashT<SIZE> operator=(const HashT<SIZE>& other)
    //{
    //  std::copy(other.bytes, other.bytes + SIZE, bytes);
    //  return *this;
    //}

    /// @brief Hash equality operator
    bool operator==(const HashT<SIZE>& other) const
    {
      return memcmp(bytes, other.bytes, SIZE) == 0;
    }

    /// @brief Hash inequality operator
    bool operator!=(const HashT<SIZE>& other) const
    {
      return memcmp(bytes, other.bytes, SIZE) != 0;
    }

    /// @brief Serialises a hash
    /// @param buffer Buffer to serialise to
    void serialise(std::vector<uint8_t>& buffer) const
    {
      PTCPP_TRACE(PTCPP_TOUT << "> HashT::serialise " << std::endl);
      for (auto& b : bytes)
        buffer.push_back(b);
    }

    /// @brief Deserialises a hash
    /// @param buffer Buffer to read the hash from
    /// @param position Position of the first byte in @p bytes
    void deserialise(const std::vector<uint8_t>& buffer, size_t& position)
    {
      PTCPP_TRACE(PTCPP_TOUT << "> HashT::deserialise " << std::endl);
      if (buffer.size() - position < SIZE)
        throw std::runtime_error("not enough bytes");
      for (size_t i = 0; i < sizeof(bytes); i++)
        bytes[i] = buffer[position++];
    }

    /// @brief Deserialises a hash
    /// @param buffer Buffer to read the hash from
    void deserialise(const std::vector<uint8_t>& buffer)
    {
      size_t position = 0;
      deserialise(buffer, position);
    }

    /// @brief Conversion operator to vector of bytes
    operator std::vector<uint8_t>() const
    {
      std::vector<uint8_t> bytes;
      serialise(bytes);
      return bytes;
    }
  };


  /// @brief Template for Prefix Pt paths
  /// @tparam HASH_SIZE is the size of each hash output in number of bytes
  /// @tparam HASH_NODE re-hashes a prefix and two hashes.
  template <
    size_t HASH_SIZE,
    void HASH_NODE(
      const HashT<HASH_SIZE>& prefix,
      const HashT<HASH_SIZE>& left,
      const HashT<HASH_SIZE>& right,
      HashT<HASH_SIZE>& out)>
  struct PPathT
  {
  public:
    typedef HashT<HASH_SIZE> hash_t;
    std::vector<hash_t> path;

    void print()
    {
      printf("| %s | flags\n", path.at(0).to_string().c_str());
      for (size_t i = 1; i < path.size(); i++)
        printf("| %s |\n", path[i].to_string().c_str());
    }
    /// @brief Computes the root at the end of the path
    hash_t root(const hash_t index, const hash_t leaf) const
    {
      printf(
        "| %s | %s\n", leaf.to_string().c_str(), index.to_bitstring().c_str());

      size_t pos = 0;
      hash_t flags = path.at(pos++);
      hash_t hash = leaf;
      for (size_t i = 8 * HASH_SIZE - 1; i + 1 > 0;
           i--) // todo improve iteration
      {
        if (flags.bit(i))
        {
          hash_t prefix = index.copy_prefix(i);
          hash_t side = path.at(path.size() - pos++); // ugly reversal
          if (index.bit(i))
            HASH_NODE(prefix, side, hash, hash);
          else
            HASH_NODE(prefix, hash, side, hash);

          printf(
            "| %s | %s*\n",
            hash.to_string().c_str(),
            prefix.to_bitstring(i).c_str());
        }
      };
      if (pos != path.size())
        throw std::runtime_error("path is too long");
      return hash;
    }

    /// @brief Verifies that the root at the end of the path is expected
    /// @param expected_root The root hash that the elements on the path are
    /// expected to hash to.
    bool verify(const HashT<HASH_SIZE>& expected_root) const
    {
      return *root() == expected_root;
    }
  };

  /// @brief Placeholder for the prefix tree leaves.
  struct Leaf
  {
    size_t key;
    size_t value;

    Leaf(size_t k, size_t v)
    {
      key = k;
      value = v;
    };

    Leaf()
    {
      Leaf(0, 0);
    }
  };

  /// @brief Online prefix-tree-root computation, from a sorted stream of
  /// leaves.
  /// @note This yields the same hash as if we built a tree then computed its
  /// root, but uses much less memory.
  template <
    size_t HASH_SIZE,
    void HASH_KEY(size_t key, HashT<HASH_SIZE>& out),
    void HASH_LEAF(Leaf leaf, HashT<HASH_SIZE>& out),
    void HASH_NODE(
      const HashT<HASH_SIZE>& prefix,
      const HashT<HASH_SIZE>& left,
      const HashT<HASH_SIZE>& right,
      HashT<HASH_SIZE>& out)>
  struct StreamT
  {
  public:
    typedef HashT<HASH_SIZE> hash_t;
    typedef struct
    {
      size_t
        length; // prefix of a branch to be hashed with the rest of the stream
      hash_t hash; // root of the corresponding sub-tree
    } entry_t;

    // Index of the last leaf we hashed.
    hash_t index;

    // Stack for all already-hashed leaves,
    // ordered by strictly-increasing lengths.
    // with at most one entry for each length such that  index.bit[i] == 1
    std::vector<entry_t> stack;

    StreamT()
    {
      index.zero(); // starting from 0* for now
      stack = {};
    };

    // Debug-only.
    void print()
    {
      for (entry_t e : stack)
        printf(
          " %s | %s%s\n",
          e.hash.to_string().c_str(),
          index.to_bitstring(e.length).c_str(),
          (e.length < 256 ? "0*" : ""));
      printf("\n");
    };

    // Compresses the stack, now that we won't add any leaf with index p0*
    // where p is the lenght-prefix of the current index
    void compress(size_t length)
    {
      while (stack.size() >= 2 && stack[stack.size() - 2].length >= length)
      {
        entry_t last = stack.back();
        stack.pop_back();
        HashT prefix = index.copy_prefix(stack.back().length);
        HASH_NODE(prefix, stack.back().hash, last.hash, stack.back().hash);
        // printf("compressing %lu
        // %s*\n",length,prefix.to_bitstring(stack.back().length).c_str());
        // print();
      };
      if (stack.size() > 0 && stack.back().length > length)
        stack.back().length = length;
    };

    // Adds a leaf to the stack.
    // NB the hashed leaf key must be larger than the index.
    void add(Leaf& leaf)
    {
      hash_t next;
      HASH_KEY(leaf.key, next);
      size_t i = 0;
      while (i < HASH_SIZE * 8 && index.bit(i) == next.bit(i))
        i++;
      assert(i < HASH_SIZE * 8); // we expect leaves are passed in order!
      compress(i);

      index = next;
      entry_t top;
      top.length = 256;
      HASH_LEAF(leaf, top.hash);
      stack.push_back(top);

      // print();
    };

    void root(hash_t& out)
    {
      compress(0);
      out = stack.at(0).hash;
    };

    static void stream(size_t size, Leaf leaf[], hash_t& out)
    {
      auto s = StreamT();
      for (size_t i = 0; i < size; i++)
        s.add(leaf[i]);
      s.root(out);
    }
  };

  template <
    size_t HASH_SIZE,
    void HASH_KEY(size_t key, HashT<HASH_SIZE>& out),
    void HASH_LEAF(Leaf leaf, HashT<HASH_SIZE>& out),
    void HASH_NODE(
      const HashT<HASH_SIZE>& prefix,
      const HashT<HASH_SIZE>& left,
      const HashT<HASH_SIZE>& right,
      HashT<HASH_SIZE>& out)>
  struct PTreeT
  {
  public:
    typedef HashT<HASH_SIZE> hash_t;
    std::vector<hash_t> path;

    typedef StreamT<HASH_SIZE, HASH_KEY, HASH_LEAF, HASH_NODE> stream_t;

    static inline auto hash_key = HASH_KEY;
    static inline auto hash_leaf = HASH_LEAF;

    struct Node
    {
      /// @brief The longest prefix shared between all leaves in this subtree,
      /// of length 0..8*HASH_SIZE - 1, skewed towards 0
      uint8_t length;
      hash_t prefix;

      /// @brief The children, for now with explicit tagging between
      /// intermediate nodes and leaves
      std::variant<Node*, Leaf*> child[2];

      /// @brief The children hashes, when available
      hash_t chash[2];

      /// @brief Dirty flag for the hash
      /// @note The @p hash is only correct if this flag is false, otherwise
      /// it needs to be computed by calling hash() on the node.
      /// would a variant be better?
      bool dirty;

      static inline void vardel(std::variant<Node*, Leaf*> x)
      {
        if (x.index() == 0)
          delete (std::get<0>(x));
        else
          delete (std::get<1>(x));
      }

      ~Node()
      {
        // printf("deleting node\n");
        vardel(child[0]);
        vardel(child[1]);
      }
    };
    typedef std::variant<Node*, Leaf*> position;

    /// @brief Computes the root
    static void root(const position x, hash_t& out)
    {
      if (x.index() == 0)
      {
        auto node = std::get<Node*>(x);
        if (node->dirty)
        {
          root(node->child[0], node->chash[0]);
          root(node->child[1], node->chash[1]);
          node->dirty = 0;
        }
        HASH_NODE(node->prefix, node->chash[0], node->chash[1], out);
        // printf("| %s | %s*\n",
        // out.to_string().c_str(),node->prefix.to_bitstring(node->length).c_str());
      }
      else
      {
        auto leaf = std::get<Leaf*>(x);
        HASH_LEAF(*leaf, out);
        // printf("| %s | key=%lu value=%lu.\n", out.to_string().c_str(),
        // leaf->key, leaf->value);
      };
    }

    // TODO avoid copying prefix bytes
    static void get_prefix(size_t& length, hash_t& prefix, position x)
    {
      if (x.index() == 0)
      {
        auto node = std::get<Node*>(x);
        length = node->length;
        prefix = HashT<HASH_SIZE>(node->prefix.bytes);
      }
      else
      {
        auto leaf = std::get<Leaf*>(x);
        length = HASH_SIZE * 8;
        HASH_KEY(leaf->key, prefix);
      }
      // printf("prefix=%s\n",prefix.to_bitstring(length).c_str());
    };

    static void stats(
      position x, size_t hist[2 * HASH_SIZE], size_t depth = 0, int length = -1)
    {
      if (x.index() == 0)
      {
        auto node = std::get<Node*>(x);
        hist[HASH_SIZE * 8 + node->length - length]++;
        stats(node->child[0], hist, depth + 1, node->length);
        stats(node->child[1], hist, depth + 1, node->length);
      }
      else
        hist[depth]++;
    }

    static void print(position x, size_t depth = 0)
    {
      if (x.index() == 0)
      {
        auto node = std::get<Node*>(x);
        print(node->child[0], depth + 1);
        printf(
          "%3lu |%s*\n",
          depth,
          node->prefix.to_bitstring(node->length).c_str());
        print(node->child[1], depth + 1);
      }
      else
      {
        auto leaf = std::get<Leaf*>(x);
        hash_t index;
        HASH_KEY(leaf->key, index);
        printf(
          "%3lu |%s key=%lu value=%lu.\n",
          depth,
          index.to_bitstring().c_str(),
          leaf->key,
          leaf->value);
      }
    }

    /// @brief Inserts (or updates) an entry, ignoring hashes for now.
    static void insert(const Leaf leaf, position* pos)
    {
      hash_t index;
      HASH_KEY(leaf.key, index);
      // printf("index= %s\n",index.to_bitstring().c_str());
      size_t length;
      hash_t prefix;
      get_prefix(length, prefix, *pos);
      for (size_t i = 0; i < 8 * HASH_SIZE; i++)
      {
        bool b = index.bit(i);
        // printf("i=%2lu b=%d.\n",i,b);
        if (i == length) // usually no need to look at the prefix
        {
          // we matched this node's prefix, we insert the leaf below (recursive
          // case)
          auto node = std::get<Node*>(*pos);
          node->dirty = 1;
          pos = &(node->child[b]);
          get_prefix(length, prefix, *pos);
        }
        else if (prefix.bit(i) != b)
        {
          // we mismatched this node (or leaf), we create a node above with
          // prefix length i.
          Node* fresh = new Node();
          fresh->length = i;
          fresh->dirty = 1; // and don't initialize chash
          fresh->prefix = prefix.copy_prefix(i);
          fresh->child[b] = new Leaf(leaf);
          fresh->child[1 - b] = *pos;
          *pos = fresh;
          return;
        };
      }
      // we found an existing leaf; we update it.
      Leaf* found = std::get<Leaf*>(*pos);
      assert(found->key == leaf.key);
      found->value = leaf.value;
    }

    static void stream0(position x, stream_t& s)
    {
      if (x.index() == 0)
      {
        auto node = std::get<Node*>(x);
        stream0(node->child[0], s);
        stream0(node->child[1], s);
      }
      else
      {
        auto leaf = std::get<Leaf*>(x);
        hash_t index;
        HASH_KEY(leaf->key, index);
        // printf("    + %s key=%lu
        // value=%lu.\n",index.to_bitstring().c_str(),leaf->key, leaf->value);
        s.add(*leaf);
      }
    }

    static void extract(position x, Leaf l[], size_t& i)
    {
      if (x.index() == 0)
      {
        auto node = std::get<Node*>(x);
        extract(node->child[0], l, i);
        extract(node->child[1], l, i);
      }
      else
      {
        Leaf leaf = *std::get<Leaf*>(x);
        l[i++] = leaf;
        // printf("k=%4zu v=%4zu\n", (**l).key, (**l).value);
      }
    }

    static void stream(position x, hash_t& out)
    {
      auto s = stream_t();
      stream0(x, s);
      s.root(out);
    }

    static std::vector<hash_t> get_path(const size_t key, position x)
    {
      hash_t index;
      HASH_KEY(key, index);
      // printf("get_path(key=%lu)\n",key);

      size_t length;
      hash_t prefix;
      get_prefix(length, prefix, x);

      std::vector<hash_t> path = {hash_t()};
      for (size_t i = 0; i < 8 * HASH_SIZE; i++)
      {
        bool b = index.bit(i);
        if (i == length)
        {
          // we matched this node's prefix, we record the hash of its other
          // child (recursive case)
          auto node = std::get<Node*>(x);
          path[0].set_bit(i, 1);
          path.push_back(node->chash[1 - b]);
          x = node->child[b];
          get_prefix(length, prefix, x);
        }
        else if (prefix.bit(i) != b)
        {
          // we mismatched this node (or leaf)
          throw std::runtime_error("key not found");
        };
      }
      // we found an existing leaf (we could return it)
      Leaf* found = std::get<Leaf*>(x);
      assert(found->key == key);

      return path ;
    }
  };

#ifdef HAVE_OPENSSL
  /// @brief OpenSSL's SHA256 compression function
  /// @param l Left node hash
  /// @param r Right node hash
  /// @param out Output node hash
  /// @note Some versions of OpenSSL may not provide SHA256_Transform.
  static inline void sha256_compress_openssl(
    const HashT<32>& l, const HashT<32>& r, HashT<32>& out)
  {
    unsigned char block[32 * 2];
    memcpy(&block[0], l.bytes, 32);
    memcpy(&block[32], r.bytes, 32);

    SHA256_CTX ctx;
    if (SHA256_Init(&ctx) != 1)
      printf("SHA256_Init error");
    SHA256_Transform(&ctx, &block[0]);

    for (int i = 0; i < 8; i++)
      ((uint32_t*)out.bytes)[i] = convert_endianness(((uint32_t*)ctx.h)[i]);
  }

  /// @brief OpenSSL SHA256
  /// @param l Left node hash
  /// @param r Right node hash
  /// @param out Output node hash
  /// @note Some versions of OpenSSL may not provide SHA256_Transform.
  static inline void sha256_openssl(
    const pt::HashT<32>& l,
    const pt::HashT<32>& r,
    pt::HashT<32>& out)
  {
    uint8_t block[32 * 2];
    memcpy(&block[0], l.bytes, 32);
    memcpy(&block[32], r.bytes, 32);
    SHA256(block, sizeof(block), out.bytes);
  }
#endif

#ifdef HAVE_MBEDTLS
  /// @brief mbedTLS SHA256 compression function
  /// @param l Left node hash
  /// @param r Right node hash
  /// @param out Output node hash
  /// @note Technically, mbedtls_internal_sha256_process is marked for internal
  /// use only.
  static inline void sha256_compress_mbedtls(
    const HashT<32>& l, const HashT<32>& r, HashT<32>& out)
  {
    unsigned char block[32 * 2];
    memcpy(&block[0], l.bytes, 32);
    memcpy(&block[32], r.bytes, 32);

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, false);
    mbedtls_internal_sha256_process(&ctx, &block[0]);

    for (int i = 0; i < 8; i++)
      ((uint32_t*)out.bytes)[i] = htobe32(ctx.state[i]);
  }

  /// @brief mbedTLS SHA256
  /// @param l Left node hash
  /// @param r Right node hash
  /// @param out Output node hash
  static inline void sha256_mbedtls(
    const pt::HashT<32>& l,
    const pt::HashT<32>& r,
    pt::HashT<32>& out)
  {
    uint8_t block[32 * 2];
    memcpy(&block[0], l.bytes, 32);
    memcpy(&block[32], r.bytes, 32);
    mbedtls_sha256_ret(block, sizeof(block), out.bytes, false);
  }
#endif

#ifdef HAVE_OPENSSL
  // for testing only
  // template <size_t HASH_SIZE>
  static inline void openssl_sha256_index(size_t key, HashT<32>& out)
  {
    SHA256(reinterpret_cast<uint8_t*>(&key), sizeof(size_t), out.bytes);
  }

  static inline void openssl_sha256_leaf(Leaf leaf, HashT<32>& out)
  {
    const auto s = sizeof(size_t);
    uint8_t text[2 * s];
    std::memcpy(text, reinterpret_cast<uint8_t*>(&leaf.key), s);
    std::memcpy(text + s, reinterpret_cast<uint8_t*>(&leaf.value), s);
    SHA256(text, sizeof(text), out.bytes);
  }

  static inline void openssl_sha256_node(
    const HashT<32>& prefix,
    const HashT<32>& left,
    const HashT<32>& right,
    HashT<32>& out)
  {
    uint8_t text[3 * 32];
    std::memcpy(text, prefix.bytes, 32);
    std::memcpy(text + 32, left.bytes, 32);
    std::memcpy(text + 64, right.bytes, 32);
    SHA256(text, sizeof(text), out.bytes);
  }
#endif

  /*
  // for testing only
  // template <size_t HASH_SIZE>
  static inline void sha256_index(size_t key, HashT<8>& out)
  {
    HashT<32> left = HashT<32>(key);
    HashT<32> right = HashT<32>();
    HashT<32> hash;
    sha256_compress(left, right, hash);
    out = HashT<8>(hash); // truncating
  }

  static inline void sha256_leaf(Leaf leaf, HashT<8>& out)
  {
    HashT<32> left = HashT<32>(leaf.key);
    HashT<32> right = HashT<32>(leaf.value);
    HashT<32> hash;
    sha256_compress(left, right, hash);
    out = HashT<8>(hash); // truncating
  }

  static inline void sha256_node(
    const HashT<8>& prefix,
    const HashT<8>& left,
    const HashT<8>& right,
    HashT<8>& out)
  {
    HashT<32> left32 = HashT<32>();
    HashT<32> right32 = HashT<32>();
    HashT<32> hash;
    for (size_t i = 0; i < 8; i++)
    {
      left32.bytes[i] = prefix.bytes[i];
      left32.bytes[i + 8] = left.bytes[i];
      left32.bytes[i + 2 * 8] = right.bytes[i];
    }
    sha256_compress(left32, right32, hash);
    out = HashT<8>(hash); // truncating
  }
  */ 

};
