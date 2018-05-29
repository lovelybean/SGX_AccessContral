#pragma once
#include "Block.h"
#include <iostream>
class Bucket
{
private:
	int Z=4;
	Block block[4];
public:
	Bucket(void);
	void addblock(Block a, int index);
	Block getblock(int index);
	bool Haverealblock(int index);
	int getZ();

};
