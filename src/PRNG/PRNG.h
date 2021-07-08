#pragma once
#include <random>
class PRNG
{
public:
	PRNG();
	std::mt19937 rng;
	void seed(uint32_t seed);
	void seed(std::seed_seq &seed);
	uint64_t nextUInt64();
	uint32_t nextUInt32();
	uint16_t nextUInt16();
	bool nextBit();
private:
	int unused_bits;
	uint32_t rand_value;
};

// A global RNG
static PRNG gRNG;