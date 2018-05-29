#pragma once
#include "acBlock.h"
#include <vector>
using namespace std;
class acBucket
{
private:
	int Z = 4;
	acBlock acblock[4];
public:
	acBucket(void);
	void setblockindex(acBlock a,int i);
	void addblock(acBlock a, int index);
	acBlock *getacblock(int index);
	void ReplaceBucket(vector<acBlock*> a);
	bool Haverealacblock(int index);
	int getZ();
};
