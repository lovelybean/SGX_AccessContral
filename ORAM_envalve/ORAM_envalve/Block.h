#pragma once
#include <string.h>
#define MAX_char_len 1024
class Block
{
private:
	int index;
	char data[1024] = {'0'};
public:
	Block(void);
	Block(int index, char data[]);
	int getIndex();
	void setIndex(int index);
	char* getData();
	void setData(char data[]);
	int getcharlen();
};