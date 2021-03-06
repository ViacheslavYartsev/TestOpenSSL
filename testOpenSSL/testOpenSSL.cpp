// testOpenSSL.cpp: ���������� ����� ����� ��� ����������� ����������.
//

#include "stdafx.h"

#include "KeyManager.h"

#include <openssl/err.h>

#include <iostream>
#include <array>
#include <cassert>
#include <memory>
#include <iomanip>

//#include <openssl/evp.h>

int main(int argc, char **argv)
{
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    
	KeyManager manager;
	manager.generateKey();
	const auto &privateKeyStr = manager.privateKey()->toHex();
	const auto &publicKey = manager.publicKey();
	const auto &publicKeyStr = publicKey->toHex();
	std::cout << "Private key: 0x" << privateKeyStr << "\r\n\r\n";
	std::cout << "Public key: 0x" << publicKeyStr << "\r\n\r\n";

	const auto &address = manager.address();
	if (!address.valid) {
		std::cerr << "Couldn't get address \r\n";
	}
	std::cout << "Address: 0x";
	for (int i = 0; i < KeyManager::ADDRESS_LENGTH; i++) {
		std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)address.data[i];
	}
	std::cout << "\r\n\r\n";
	
	const char* text = "this is the example to test";
	std::vector<uint8_t> data;
	const char* p = text;
	while (*p != 0) {
		data.push_back(*p);
		++p;
	}
	auto signature = manager.signature(data);
	
	if (manager.verify(data, signature.get())) {
		std::cout << "Verified signature";
	}
	else {
		std::cout << "Failed to verify signature";
	}
    return 0;
}

