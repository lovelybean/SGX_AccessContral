#pragma once
#include <map>
#include "AccessRight.h"
using namespace std;
//用户权限在oram中存储的格式
class acBlock
{
private:
	int index;
	//泄露内存的风险
	map<int, accesstype> *acmap=new map<int, accesstype>();
public:
	acBlock(void);
	acBlock(int len);
	acBlock(int index, int userid, accesstype userright);
	int getIndex();
	void setIndex(int index);
	void setMap(int id,accesstype type);
	bool haveid(int id);
	int getac(int id);
	int getmaplen();
	map<int, accesstype> returnmap();
	void givemap(map<int, accesstype> *tem);
};