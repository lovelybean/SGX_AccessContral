#pragma once
#include <map>
#include "AccessRight.h"
using namespace std;
//�û�Ȩ����oram�д洢�ĸ�ʽ
class acBlock
{
private:
	int index;
	//й¶�ڴ�ķ���
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