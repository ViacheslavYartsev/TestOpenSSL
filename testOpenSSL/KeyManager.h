#pragma once

#include "IKeyManager.h"

#include <memory>
#include <functional>

#include <openssl/ripemd.h>
#include <openssl/pem.h>

class KeyManager : public IKeyManager
{
public:
	static constexpr size_t ADDRESS_LENGTH = RIPEMD160_DIGEST_LENGTH + 5;//1 for the first 0x00 byte, 4  for the last four bytes in address
	struct Address{
		Address(bool v) :valid(v) {}
		uint8_t data[ADDRESS_LENGTH];
		const bool valid;
	};

public:
	KeyManager();
	~KeyManager();

	std::unique_ptr<ECDSA_SIG, std::function<void(ECDSA_SIG*)>> signature(const std::vector<uint8_t> &data) const;
	bool verify(const std::vector<uint8_t> &data, ECDSA_SIG *signature) const;

	Address address() const;

	//IKeyManager interface
	virtual void generateKey() override;

	virtual std::unique_ptr<IKey> privateKey() const override;
	virtual std::unique_ptr<IKey> publicKey() const override;

	

private:
	struct Impl;
	std::unique_ptr<Impl> p;
};

