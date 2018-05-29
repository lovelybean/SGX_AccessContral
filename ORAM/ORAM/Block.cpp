#include "Block.h"

Block::Block(void)
{
	index = -1;
	setData(new char[1024]);
}

Block::Block(int index, char data[])
{
	setIndex(index);
	setData(data);
}

int Block::getIndex()
{
	return Block::index;
}

void Block::setIndex(int index)
{
	Block::index = index;
}

char* Block::getData()
{
	return Block::data;
}

void Block::setData(char data[])
{
	memcpy(Block::data,data,1024);
}

int Block::getcharlen()
{
	return MAX_char_len;
}
