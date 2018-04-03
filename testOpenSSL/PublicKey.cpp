
#include "stdafx.h"
#include "PublicKey.h"

#include <openssl/err.h>
#include <openssl/pem.h>

#include <iostream>
#include <mutex>
#include <cassert>
#include <sstream>
#include <iomanip>
#include <vector>
#include <stdio.h>

struct PublicKey::Impl {
	~Impl() {
		EC_KEY_free(key);
	}

	bool isValid() const {
		return pub_key && group;
	}

    std::vector<uint8_t> publicKeyData() {
        unsigned char   *ep, *pp;

        const auto eplen = i2d_EC_PUBKEY(key, NULL);
        if (!eplen)
        {
            ECerr(EC_F_ECKEY_PUB_ENCODE, ERR_R_EC_LIB);
            return{};
        }
        ep = (unsigned char *)OPENSSL_malloc(eplen);
        if (!ep)
        {
            ECerr(EC_F_ECKEY_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
            return{};
        }
        pp = ep;

        if (!i2d_EC_PUBKEY(key, &pp))
        {
            OPENSSL_free(ep);
            ECerr(EC_F_ECKEY_PUB_ENCODE, ERR_R_EC_LIB);
            return{};
        }
        std::vector<uint8_t> res;
        std::stringstream ss;

        for (int i = 0; i<eplen; ++i)
            res.push_back(ep[i]);
        OPENSSL_free(ep);
        return res;
    }


	EC_KEY *key = nullptr;
	const EC_POINT *pub_key = nullptr;
	const EC_GROUP *group = nullptr;

	std::mutex mutex;

	mutable std::unique_ptr<KeyForAddr> keyForAddr;


};

PublicKey::PublicKey()
	:p(new Impl())
{
}

PublicKey::PublicKey(EC_KEY *key)
	:	PublicKey()
{
	p->key = key;
	EC_KEY_up_ref(p->key);
	p->pub_key = EC_KEY_get0_public_key(key);
	p->group = EC_KEY_get0_group(key);
}

PublicKey::~PublicKey()
{
}


std::string PublicKey::toHex() const {
	if (p->isValid()) {
        const auto data = p->publicKeyData();

        std::stringstream ss;
        for (int i = 0; i<data.size(); ++i)
            ss << std::setfill('0') << std::setw(2) << std::hex << (int)data[i];
        std::string res = ss.str();
        return res;
	}
	return{};
}

/**
 * @brief get public key part, that can be used for address generation
 */
PublicKey::KeyForAddr PublicKey::key() const{
	if (!p->isValid())
		return {};
	std::lock_guard<std::mutex> lock(p->mutex);
	if (p->keyForAddr)
		return *p->keyForAddr.get();

	p->keyForAddr.reset(new KeyForAddr());
    const auto data = p->publicKeyData();
    
    memcpy(p->keyForAddr->data, &data.data()[23], 65);

    assert(p->keyForAddr->data[0] == 4);

	return *p->keyForAddr.get();
}
