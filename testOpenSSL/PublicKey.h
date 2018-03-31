#pragma once

#include "IKey.h"

#include <memory>

#include <openssl/ec.h>

class PublicKey : public IKey
{
public:
	static constexpr size_t publicKeySize = 65;
	struct KeyForAddr {
		uint8_t data[publicKeySize];
	};

public:
	PublicKey();
	PublicKey(EC_KEY *key);
	~PublicKey();

    KeyForAddr key() const;

	//IKey interface
    std::string toHex() const override;
	
private:
	struct Impl;
	std::unique_ptr<Impl> p;
};

