#pragma once
#include "AccessRight.h"
#include <map>
using namespace std;
//��ʼ���û�id��Ȩ��
class userinfo{
private:
	int userid;
	map<int,accesstype> useracright;
public:
	userinfo(int userid, map<int, accesstype> useracright);
	void setuserid(int id);
	int getuserid();
	void setuserac(map<int, accesstype> useracright);
	int getuserac(int index);
};