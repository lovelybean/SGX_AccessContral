#pragma once
#include "Block.h"
#include <iostream>
#include <vector>
using namespace std;
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
	void ReplaceBucket(vector<Block> a);
	int getZ();

};
