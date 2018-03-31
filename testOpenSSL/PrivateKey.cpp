#include "stdafx.h"
#include "PrivateKey.h"

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
		char * data = BN_bn2hex(p->priv_key);
		std::string res(data);
		OPENSSL_free(data);
		return res;
	}
	return{};
}

PrivateKey::~PrivateKey()
{
}
