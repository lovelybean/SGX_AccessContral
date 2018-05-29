#include "acBucket.h"

acBucket::acBucket(void)
{
	if (Z <= 0) {
		//printf("initialize Z false\n");
	}
	else {
		for (int i = 0; i<Z; i++) {
			acblock[i] = acBlock();
		}
	}
}

void acBucket::setblockindex(acBlock a,int i)
{
	a.setIndex(i);
}

void acBucket::addblock(acBlock a, int index)
{
	acblock[index] = a;
}

acBlock *acBucket::getacblock(int index)
{
	return &acblock[index];
}

void acBucket::ReplaceBucket(vector<acBlock*> a)
{
	for (int i = 0; i < Z; i++)
	{
		acblock[i] = *a.at(i);
	}
}

bool acBucket::Haverealacblock(int index)
{
	if (acblock[index].getIndex() == -1) {
		return false;
	}
	else return true;
}

int acBucket::getZ()
{
	return Z;
}
