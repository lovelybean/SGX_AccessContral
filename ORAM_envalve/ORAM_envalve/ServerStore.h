#pragma once
#include <Windows.h>
#include <string.h>
#include <iostream>
#include <math.h>
#include "Block.h"
#include "Bucket.h"
#include <vector>
#include <fstream>
#include <time.h>
#include <stdlib.h>
#include <conio.h>
using namespace std;
class server 
{
public:
	void Initbucket(int totalnum);
	void InitPosMap();
	int getPos(int leaf, int h);
	void Randomstoreblock(int leaf, Block block, vector<Bucket> *buckets);
	void storeuserblock();
	vector<Bucket> *getClienstash(int index);

};
