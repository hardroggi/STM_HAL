/*
 * RANDOM.h
 *
 *  Created on: 12.08.2016
 *  Author: tobias
 */
#include <stdint.h>

#ifndef SOURCES_APP_CRYPTOGRAPHY_RANDOM_H_
#define SOURCES_APP_CRYPTOGRAPHY_RANDOM_H_

class Random {
public:
	Random(uint8_t* entropy_data,uint8_t entropy_data_size, uint8_t* nonce, uint8_t nonce_size, uint8_t* personalization_String, uint8_t personalization_String_size);
	virtual ~Random();
	int32_t getNextRandomNumber(uint8_t* RandomString, uint8_t RandomString_size);
	int32_t initialize(uint8_t* entropy_data,uint8_t entropy_data_size, uint8_t* nonce, uint8_t nonce_size, uint8_t* personalization_String, uint8_t personalization_String_size);
	int32_t getStatus();
};

#endif /* SOURCES_APP_CRYPTOGRAPHY_RANDOM_H_ */
