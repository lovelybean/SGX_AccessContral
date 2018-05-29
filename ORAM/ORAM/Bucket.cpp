#include "Bucket.h"

Bucket::Bucket(void)
{
	if (Z <= 0) {
		//printf("initialize Z false\n");
	}
	else {
		for (int i = 0; i<Z; i++) {
			block[i] =Block();
		}
	}
}

void Bucket::addblock(Block a, int index)
{
	block[index].setData(a.getData());
	block[index].setIndex(a.getIndex());
}

Block Bucket::getblock(int index)
{
	return block[index];
}

bool Bucket::Haverealblock(int index)
{
	if (block[index].getIndex()==-1) {
		return false;
	}
	else return true;
}

int Bucket::getZ()
{
	return Z;
}
