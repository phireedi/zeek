// See the file "COPYING" in the main distribution directory for copyright.

/**
 * Wrapper and helper functions for MD5/SHA digest algorithms.
 */

#pragma once

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sys/types.h> // for u_char
#include <cstdint>

#if ( OPENSSL_VERSION_NUMBER < 0x10100000L ) || defined(LIBRESSL_VERSION_NUMBER)
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy

inline void* EVP_MD_CTX_md_data(const EVP_MD_CTX* ctx)
	{
	return ctx->md_data;
	}
#endif

namespace zeek::detail
{

// if you add something here, note that you might have to make sure that the
// static_out member in calculate_digest is still long enough.
enum HashAlgorithm
	{
	Hash_MD5,
	Hash_SHA1,
	Hash_SHA224,
	Hash_SHA256,
	Hash_SHA384,
	Hash_SHA512
	};

inline const char* digest_print(const u_char* digest, size_t n)
	{
	static char buf[256]; // big enough for any of md5/sha1/sha256
	for ( size_t i = 0; i < n; ++i )
		snprintf(buf + i * 2, 3, "%02x", digest[i]);
	return buf;
	}

inline const char* md5_digest_print(const u_char digest[MD5_DIGEST_LENGTH])
	{
	return digest_print(digest, MD5_DIGEST_LENGTH);
	}

inline const char* sha1_digest_print(const u_char digest[SHA_DIGEST_LENGTH])
	{
	return digest_print(digest, SHA_DIGEST_LENGTH);
	}

inline const char* sha256_digest_print(const u_char digest[SHA256_DIGEST_LENGTH])
	{
	return digest_print(digest, SHA256_DIGEST_LENGTH);
	}

EVP_MD_CTX* hash_init(HashAlgorithm alg);

void hash_update(EVP_MD_CTX* c, const void* data, unsigned long len);

void hash_final(EVP_MD_CTX* c, u_char* md);

unsigned char* internal_md5(const unsigned char* data, unsigned long len, unsigned char* out);

/**
 * Calculates the selected digest.
 * @param Alg Digest algorithm to use.
 * @param data Data to hash.
 * @param len Length of data to hash.
 * @param out Buffer to write data to. If set to nullptr, a static buffer will be used
 * @return Buffer that the hash was written to. Length is deoendent on the chosen hash function.
 */
unsigned char* calculate_digest(HashAlgorithm Alg, const unsigned char* data, uint64_t len,
                                unsigned char* out);

} // namespace zeek::detail

using HashAlgorithm [[deprecated("Remove in v4.1. Use zeek::detail::HashAlgorithm.")]] =
	zeek::detail::HashAlgorithm;
constexpr auto Hash_MD5 [[deprecated("Remove in v4.1. Use zeek::detail::Hash_MD5.")]] =
	zeek::detail::Hash_MD5;
constexpr auto Hash_SHA1 [[deprecated("Remove in v4.1. Use zeek::detail::Hash_SHA1.")]] =
	zeek::detail::Hash_SHA1;
constexpr auto Hash_SHA224 [[deprecated("Remove in v4.1. Use zeek::detail::Hash_SHA224.")]] =
	zeek::detail::Hash_SHA224;
constexpr auto Hash_SHA256 [[deprecated("Remove in v4.1. Use zeek::detail::Hash_SHA256.")]] =
	zeek::detail::Hash_SHA256;
constexpr auto Hash_SHA384 [[deprecated("Remove in v4.1. Use zeek::detail::Hash_SHA384.")]] =
	zeek::detail::Hash_SHA384;
constexpr auto Hash_SHA512 [[deprecated("Remove in v4.1. Use zeek::detail::Hash_SHA512.")]] =
	zeek::detail::Hash_SHA512;

constexpr auto digest_print [[deprecated("Remove in v4.1. Use zeek::detail::digest_print.")]] =
	zeek::detail::digest_print;
constexpr auto md5_digest_print
	[[deprecated("Remove in v4.1. Use zeek::detail::md5_digest_print.")]] =
		zeek::detail::md5_digest_print;
constexpr auto sha1_digest_print
	[[deprecated("Remove in v4.1. Use zeek::detail::sha1_digest_print.")]] =
		zeek::detail::sha1_digest_print;
constexpr auto sha256_digest_print
	[[deprecated("Remove in v4.1. Use zeek::detail::sha256_digest_print.")]] =
		zeek::detail::sha256_digest_print;
constexpr auto hash_init [[deprecated("Remove in v4.1. Use zeek::detail::hash_init.")]] =
	zeek::detail::hash_init;
constexpr auto hash_update [[deprecated("Remove in v4.1. Use zeek::detail::hash_update.")]] =
	zeek::detail::hash_update;
constexpr auto hash_final [[deprecated("Remove in v4.1. Use zeek::detail::hash_final.")]] =
	zeek::detail::hash_final;
constexpr auto internal_md5 [[deprecated("Remove in v4.1. Use zeek::detail::internal_md5.")]] =
	zeek::detail::internal_md5;
constexpr auto calculate_digest
	[[deprecated("Remove in v4.1. Use zeek::detail::calculate_digest.")]] =
		zeek::detail::calculate_digest;
