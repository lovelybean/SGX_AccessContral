#include "acBlock.h"
#include "sgx_trts.h"
//可以让所有的虚acblock中的map指向同一个map，节省内存。
acBlock::acBlock(void)
{
	index = -1;
	setMap(0,accesstype(2));
}
int getrand1(unsigned int num) {
	unsigned int r;
	unsigned int x = num;
	sgx_read_rand((unsigned char*)&r, sizeof(unsigned int));
	r = r%x;
	return int(r);
}
acBlock::acBlock(int len)
{
	index = -1;
	int k = -1;
	for (int i = 0; i < len; i++)
	{
		setMap(k--,accesstype(getrand1(3)));
	}
}

acBlock::acBlock(int index, int userid, accesstype userright)
{
	acBlock::index = index;
	setMap(userid, userright);
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
	map<int, accesstype>::iterator iter;
	if (!haveid(id)) {
		acmap->insert(pair<int, accesstype>(id, type));
	}
	else {
		iter = acmap->find(id);
		if (iter != acmap->end())
		{
			acmap->erase(iter);
			acmap->insert(pair<int, accesstype>(id, type));
		}
	}
}

bool acBlock::haveid(int id)
{
	if (acmap->count(id) > 0) { return true; }
	else return false;
}

int acBlock::getac(int id)
{
	return acmap->at(id);
}

int acBlock::getmaplen()
{
	return acmap->size();
}
map<int, accesstype> acBlock::returnmap()
{
	return *acmap;
}

void acBlock::givemap(map<int, accesstype> *tem)
{
	acmap = tem;
}
