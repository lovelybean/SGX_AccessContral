#include <fstream>
#include <iostream>
#include <vector>
#include "Block.h"
const int LENGTH =1024;

using namespace std;

vector<Block> *getuserBlock()
{
	char buf[LENGTH];
	streamoff start;
	streamoff end;
	streamoff  length;
	vector<Block> *blocks=new vector<Block>();
	ifstream ifs("D:\\user\\xiuxian.txt", ios::binary);
	//ofstream destfile("C:\\Users\\Administrator\\Desktop\\oram\\test3.txt", ios::binary | ios::app);
	int i = 0;
	while (1)
	{
		start = ifs.tellg();
		ifs.seekg(0, ios::end);
		end = ifs.tellg();
		length = end - start;
		ifs.seekg(start);
		if (length >= LENGTH)
		{
			ifs.read(buf, LENGTH);
			blocks->push_back(Block(i,buf));
			printf("%s\n\n", buf);
			i++;
		}
		else
		{
			ifs.read(buf, length);
			blocks->push_back(Block(i,buf));
			break;
		}

	}
	return blocks;
}