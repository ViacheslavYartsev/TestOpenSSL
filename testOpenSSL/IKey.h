#pragma once

#include <string>
#include <vector>

/**
 * @brief The IKey interface
 */
class IKey
{
public:
	IKey() = default;
	virtual ~IKey() = default;

	virtual std::string toHex() const = 0;
};

