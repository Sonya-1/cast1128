#pragma once
#include<iostream>
#include <vector>
#include"Cast128.h"

class CipherOFB {
	Cast128::Block state;
	Cast128::Key *key;


public: 
	CipherOFB(Cast128::Block iv, Cast128::Key *key) {
		this->state = iv;
		this->key = key;
	}

	void crypt(std::vector<uint8_t> *data, size_t offset) {
		state = Cast128::go(*key, state, true);

		std::vector<uint8_t> mask;
		mask.push_back((uint8_t)state.Msg[0]);
		mask.push_back(state.Msg[0] >> 8);
		mask.push_back(state.Msg[0] >> 16);
		mask.push_back(state.Msg[0] >> 24);
		mask.push_back(state.Msg[1]);
		mask.push_back(state.Msg[1] >> 8);
		mask.push_back(state.Msg[1] >> 16);
		mask.push_back(state.Msg[1] >> 24);

		auto d = *data;
		size_t end = std::min(offset + 8, d.size()) - offset;
		
		for (int i = 0; i < end; i++) {
			(*data)[i + offset] = d[i + offset] ^ mask[i];
		}
	}
};