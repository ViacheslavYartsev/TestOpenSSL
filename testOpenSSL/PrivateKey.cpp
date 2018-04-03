#include "stdafx.h"
#include "PrivateKey.h"

#include <openssl/err.h>

#include <sstream>
#include <iomanip>

struct PrivateKey::Impl {
	~Impl() {
		EC_KEY_free(key);
	}

	bool isValid() const {
		return priv_key && group;
	}

	EC_KEY *key = nullptr;
	const BIGNUM *priv_key = nullptr;
	const EC_GROUP *group = nullptr;
};


/**
 * @brief construct empty PrivateKey
 */
PrivateKey::PrivateKey()
	:	p(new Impl())
{
}

/**
 * @brief construct PrivateKey according the key
 * @param key
 */
PrivateKey::PrivateKey(EC_KEY *key) 
	: PrivateKey()
{
	p->key = key;
	EC_KEY_up_ref(p->key);
	p->priv_key = EC_KEY_get0_private_key(key);
	p->group = EC_KEY_get0_group(key);
}

/**
 * @brief get hex string for the PrivateKey
 */
std::string PrivateKey::toHex() const {
    if (p->isValid()) {
        unsigned char   *ep, *pp;

        const auto eplen = i2d_ECPrivateKey(p->key, NULL);
        if (!eplen)
        {
            ECerr(EC_F_ECKEY_PRIV_ENCODE, ERR_R_EC_LIB);
            return{};
        }
        ep = (unsigned char *)OPENSSL_malloc(eplen);
        if (!ep)
        {
            ECerr(EC_F_ECKEY_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
            return{};
        }
        pp = ep;

        if (!i2d_ECPrivateKey(p->key, &pp))
        {
            OPENSSL_free(ep);
            ECerr(EC_F_ECKEY_PRIV_ENCODE, ERR_R_EC_LIB);
            return{};
        }

       
        std::stringstream ss;
        for (int i = 0; i < eplen; ++i)
            ss << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)ep[i];
        std::string res = ss.str();
       
        OPENSSL_free(ep);
        return res;
	}
	return{};
}

PrivateKey::~PrivateKey()
{
}
