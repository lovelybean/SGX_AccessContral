#pragma once
#include <map>
#include "AccessRight.h"
using namespace std;
//用户权限在oram中存储的格式
class acBlock
{
private:
	int index;
	map<int, accesstype> acmap;
public:
	acBlock(void);
	acBlock(int index, int userid,accesstype userright);
	int getIndex();
	void setIndex(int index);
	void setMap(int id,accesstype type);
	int getac(int id);
};