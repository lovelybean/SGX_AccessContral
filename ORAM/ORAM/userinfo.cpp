#include "userinfo.h"


userinfo::userinfo(int userid, map<int, accesstype> useracright)
{
}

void userinfo::setuserid(int id)
{
	userid = id;
}

int userinfo::getuserid()
{
	return userid;
}

void userinfo::setuserac(map<int, accesstype> useracright)
{
	userinfo::useracright = useracright;
}


int userinfo::getuserac(int index)
{
	return useracright[index];
}
