#include "acBlock.h"


acBlock::acBlock(void)
{
	index = -1;
}

acBlock::acBlock(int index, int userid, accesstype userright)
{
	acBlock::index = index;
	acmap[userid] = userright;
}

int acBlock::getIndex()
{
	return index;
}

void acBlock::setIndex(int index)
{
	acBlock::index = index;
}

void acBlock::setMap(int id, accesstype type)
{
	acmap[id] = type;
}

int acBlock::getac(int id)
{
	return acmap[id];
}
