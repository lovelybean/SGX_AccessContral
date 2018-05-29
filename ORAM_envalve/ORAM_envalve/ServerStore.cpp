#include "ServerStore.h"
using namespace std;
vector<Bucket> *buckets=new vector<Bucket>();
int bucketsize=0;
boolean is_init = false;
vector<Block>* blocks;
vector<int> PosMap;
int TreeHeight=0;
Bucket a;
int Z = a.getZ();


void server::Initbucket(int totalnum)
{
	if (is_init == false)
	{
		is_init = true;
		for (int i = 0; i<totalnum; i++) {
			buckets->push_back(Bucket());
		}

	}
}

void server::InitPosMap()
{
	//ofstream destfile("C:\\Users\\Administrator\\Desktop\\oram\\test3.txt",ios::app);
	//PosMap = new vector<int>();
	int numleaf = pow(2,TreeHeight);
	srand((unsigned)time(NULL));
	for (int i = 0; i < bucketsize; i++)
	{
		int num = rand()%numleaf;
		//destfile << num << endl;
		PosMap.push_back(num);
	}
}
int server::getPos(int leaf,int h)
{
	int bnum = pow(2, TreeHeight)+leaf;
	if (h == TreeHeight)
	{
		return bnum - 1;
	}
	else 
	{
		for (int i = TreeHeight; i > h; i--)
		{
			bnum = bnum / 2;
		}
		return bnum - 1;
	}	
}
void server::Randomstoreblock(int leaf,Block block,vector<Bucket> *buckets)
{
	//ofstream destfile("C:\\Users\\Administrator\\Desktop\\oram\\test3.txt", ios::app|ios::binary);
	srand((unsigned)time(NULL));
	int h = rand()%(TreeHeight + 1);
	int binnum = rand()%(Z);
	int storeid = getPos(leaf, h);
	while (buckets->at(storeid).Haverealblock(binnum))
	{
		int h = rand()%(TreeHeight + 1);
		int binnum = rand()%(Z);
		int storeid = getPos(leaf, h);
	}
	buckets->at(storeid).addblock(block,binnum);
	//destfile.write(block.getData(),1024);
}
void server::storeuserblock()
{
	for (int i = 0; i < PosMap.size(); i++)
	{
		int leaf = PosMap.at(i);
		Randomstoreblock(leaf,blocks->at(i),buckets);
		//printf("%s\n\n\n", buckets.at(c).getblock(b).getData());
	}
	delete blocks;
}
vector<Bucket> *getClienstash(int index)
{
	vector<Bucket> *clientstash=new vector<Bucket>();
	int udataindex = PosMap.at(index)+pow(2,TreeHeight);
	for (int i = TreeHeight; i >= 0; i--)
	{
		clientstash->push_back(buckets->at(udataindex-1));
		udataindex = udataindex / 2;
	}
	return clientstash;
}
char *userdata;
void getuserdata(int index)
{
	vector<Bucket> *clientstash = getClienstash(index);
	for (int i = 0; i < clientstash->size(); i++)
	{
		for (int j = 0; j < 4; j++)
		{
			if (clientstash->at(i).getblock(j).getIndex() == index)
			{
				//printf("\n从ORAM中提取第1处为：\n%s\n", clientstash->at(i).getblock(j).getData());
				userdata=clientstash->at(i).getblock(j).getData();
			}
		}
	}
	delete clientstash;
}
char *Storeuserfile()
{
	server x;
	vector<Block> *getuserBlock();
	blocks = getuserBlock();
	bucketsize = blocks->size();
	TreeHeight = ceil(log(bucketsize)/log(2)) - 1;
	x.Initbucket(pow(2, (TreeHeight + 1)) - 1);
	x.InitPosMap();
	x.storeuserblock();
	getuserdata(0);
	delete buckets;
	return userdata;
}
