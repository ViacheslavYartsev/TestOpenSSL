#include "stdafx.h"

#include "KeyManager.h"
#include "PrivateKey.h"
#include "PublicKey.h"

#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <iostream>

/**
 * @brief Private part of the KeyManager class
 */
struct KeyManager::Impl {
	~Impl() {
		EC_KEY_free(key);
	}
	EC_KEY *key = nullptr;
};

/**
 * @brief construct KeyManager
 */
KeyManager::KeyManager()
	:p(new Impl())
{
}


KeyManager::~KeyManager()
{
}

/**
 * @brief generate new EC_KEY
 */
void KeyManager::generateKey() {
	if (p->key) {
		EC_KEY_free(p->key);
		p->key = nullptr;
	}
	p->key = EC_KEY_new_by_curve_name(NID_secp256k1);

	if (!p->key) {
		std::cerr << "couldn't generate key\r\n";
		return;
	}
	if (1 != EC_KEY_generate_key(p->key)) {
		std::cerr << "couldn't generate keys\r\n";
	}
}

/**
 * @brief get privateKey
 */
std::unique_ptr<IKey> KeyManager::privateKey() const {
	std::unique_ptr<IKey> res(new PrivateKey(p->key));
	return res;
}

/**
 * @brief get publicKey
 */
std::unique_ptr<IKey> KeyManager::publicKey() const {
	std::unique_ptr<IKey> res(new PublicKey(p->key));
	return res;
}

/**
 * @brief create signature for the data
 * @param data
 */
std::unique_ptr<ECDSA_SIG, std::function<void(ECDSA_SIG*)>> KeyManager::signature(const std::vector<uint8_t> &data) const {
	if (p->key) {
		std::unique_ptr<ECDSA_SIG, std::function<void(ECDSA_SIG*)>> res(ECDSA_do_sign(data.data(), static_cast<int>(data.size()), p->key), [](ECDSA_SIG* val) {
			ECDSA_SIG_free(val);
		});
		return res;
	}
	return{};
}

/**
 * @brief verify if signature is valid for the data and the key
 * @param data
 * @param signature
 */
bool KeyManager::verify(const std::vector<uint8_t> &data, ECDSA_SIG *signature) const {
	if (!p->key) {
		std::cerr << "request verify without key generation\r\n";
		return false;
	}
	return  1 == ECDSA_do_verify(data.data(), static_cast<int>(data.size()), signature, p->key);
}

/**
 * @brief calculate address
 */
KeyManager::Address KeyManager::address() const {
	if (!p->key)
		return {false};
	PublicKey publicKey(p->key);
	unsigned char shaData[SHA256_DIGEST_LENGTH];
	unsigned char shaDataTmp[SHA256_DIGEST_LENGTH];
	


	if (!SHA256(publicKey.key().data, publicKey.publicKeySize, shaData)) {
		std::cerr << "Couldn't perform sha256 on public key\r\n";
		return {false};
	}

	Address address(true);

	RIPEMD160(shaData, SHA256_DIGEST_LENGTH, &address.data[1]);
	address.data[0] = 0;

	SHA256(address.data, RIPEMD160_DIGEST_LENGTH + 1, shaData);
	SHA256(shaData, SHA256_DIGEST_LENGTH, shaDataTmp);

	//combain values
	for (int i = 0; i < 4; i++)
		address.data[RIPEMD160_DIGEST_LENGTH + 1 + i] = shaDataTmp[i];
	return address;
}
