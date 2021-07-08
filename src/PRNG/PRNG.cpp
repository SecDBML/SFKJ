#include "PRNG.h"
#include <ctime>
using namespace std;

PRNG::PRNG()
{
#ifndef _DEBUG
	rng.seed(time(0));
#endif // In debug mode, we use fixed seed every time
}

void PRNG::seed(uint32_t seed)
{
	rng.seed(seed);
}

void PRNG::seed(seed_seq &seed)
{
	rng.seed(seed);
}

uint64_t PRNG::nextUInt64()
{
	return (((uint64_t)rng())<<32)|rng();
}

uint32_t PRNG::nextUInt32()
{
	return rng();
}

uint16_t PRNG:: nextUInt16()
{
	uint16_t ret;
	if (unused_bits < 16)
	{
		uint32_t r = rng();
		ret = r & 0xffff;
		rand_value = (rand_value << 16) | (r >> 16);
		unused_bits += 16;
	}
	else
	{
		ret = rand_value & 0xffff;
		rand_value >>= 16;
		unused_bits -= 16;
	}
	return ret;
}

bool PRNG::nextBit()
{
	if (unused_bits == 0)
	{
		rand_value = rng();
		unused_bits = 32;
	}
	bool ret = rand_value & 1;
	rand_value >>= 1;
	unused_bits--;
	return ret;
}