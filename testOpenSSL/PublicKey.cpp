#include "stdafx.h"
#include "PublicKey.h"

#include <iostream>
#include <mutex>
#include <cassert>

struct PublicKey::Impl {
	~Impl() {
		EC_KEY_free(key);
	}

	bool isValid() const {
		return pub_key && group;
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
		char * data = EC_POINT_point2hex(p->group, p->pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL);
		std::string res(data);
		OPENSSL_free(data);
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

	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	
	if (1 != EC_POINT_get_affine_coordinates_GFp(p->group, p->pub_key, x, y, NULL)) {
		std::cerr << "couldn't get coordinates from the key\r\n";
		BN_free(x);
		BN_free(y);
		return {};
	}
	p->keyForAddr.reset(new KeyForAddr());

	p->keyForAddr->data[0] = 0x04;

	assert(x->dmax == 4);
	assert(y->dmax == 4);
	static_assert(sizeof(*x->d) == 8, "unexpected size of the public key data");

	auto pX = reinterpret_cast<uint8_t*>(x->d);
	auto pY = reinterpret_cast<uint8_t*>(y->d);

	for (int i = 0; i < 32; ++i) {
		p->keyForAddr->data[i + 1] = *pX;
		p->keyForAddr->data[i + 33] = *pY;
		++pX;
		++pY;
	}
	BN_free(x);
	BN_free(y);
	return *p->keyForAddr.get();
}
