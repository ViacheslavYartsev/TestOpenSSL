#pragma once

#include "IKey.h"

#include <memory>

#include <openssl/ec.h>

class PrivateKey : public IKey
{
public:
	PrivateKey();
	PrivateKey(EC_KEY *key);
	~PrivateKey();

	//IKey interface
	std::string toHex() const override;

private:
	struct Impl;
	std::unique_ptr<Impl> p;
};

