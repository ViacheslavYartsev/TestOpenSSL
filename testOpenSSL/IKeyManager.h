#pragma once

#include "IKey.h"

#include <memory>
#include <string>
#include <vector>

/**
 * @brief The IKeyManager interface
 */
class IKeyManager
{
public:
	IKeyManager() = default;
	virtual ~IKeyManager() = default;

	virtual void generateKey() = 0;

	virtual std::unique_ptr<IKey> privateKey() const = 0;
	virtual std::unique_ptr<IKey> publicKey() const = 0;
};

