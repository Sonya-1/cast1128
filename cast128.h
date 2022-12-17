#pragma once
#include<cstdint>
#include<string>
#include<vector>
static const int keyLength = 128;
static const int blockLength = 64;
static const int keysCount = 32;
static const int roundCount = 16;

static class Cast128 {
public:
	typedef uint32_t uint;
	typedef uint8_t  uint8;
	typedef uint Key[keyLength / 8];
	struct Block {
		uint Msg[blockLength / 8];
	};
	static void generateKey(std::string outFileName);
	static Block encrypt(const Key key, const Block msg);
	static Block decrypt(const Key key, const Block msg);
	static void readKey(const std::string path, Key* key);
	static uint sumMod2_32(uint a, uint b);
	static Block go(const Key key, const Block msg, bool isEncrypt);
	static uint subtractMod2_32(uint a, uint b);
	static uint cyclicShift(uint x, uint8 shift);
	static void splitI(uint I, uint8* Ia, uint8* Ib, uint8* Ic, uint8* Id);
	static void encryptFile(const char* inputFileName, const char* outFileName, Cast128::Key key);
	static void decryptFile(const char* inputFileName, const char* outFileName, Cast128::Key key);
	static void setByte(Cast128::Block& bl, uint8_t pos, uint8_t byte);
	static const Cast128::uint8 getByte(Cast128::Key key, Cast128::uint8 i);
	static Block invertSecond(Block b);
	static Cast128::Block invertThird(Block b);
	static std::vector<Cast128::Block> readFile(const char* inputFileName);

private:
	typedef uint sBlock[256];
	static const sBlock S1;
	static const sBlock S2;
	static const sBlock S3;
	static const sBlock S4;
	static const sBlock S5;
	static const sBlock S6;
	static const sBlock S7;
	static const sBlock S8;
	
	static Cast128::uint* generateKeys(const Cast128::Key key);
	static void writeLastBlock(std::vector<uint8_t>&, Cast128::Block);

};
