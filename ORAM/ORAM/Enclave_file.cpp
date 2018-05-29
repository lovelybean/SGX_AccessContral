#include <fstream>
#include <iostream>
#include <vector>
#include "Block.h"
#include <tchar.h>
#include <time.h>
#include <string>
#define ENCLAVE_FILE _T("ORAM_envalve.signed.dll")
#include "sgx_urts.h"
#include "ORAM_envalve_u.h"

using namespace std;
const int LENGTH = 1024;
const char *acmap_location = "E:\\test file\\acPosMap.txt";
const char *posmap_location = "E:\\test file\\PosMap.txt";
const char *acbucket_location = "E:\\test file\\acbucket.txt";
const char *bucket_location = "E:\\test file\\PathTable\\Path";
vector<Block> *clientstash = new vector<Block>;
void printblock(char *data)
{
	printf("%s\n",data);
}
int temindex = 0;
int temuserid = 0;
int temac = 0;
//保证用户权限的正确性
int acValidity(int index, int userid, accesstype userac)
{
	if (temindex==index&&temuserid==userid&&temac==userac)
	{
		return 1;
	}
	else return 0;
}
//get clientstash
void transferstash(char *data, int index, size_t len)
{
	if (len == LENGTH) {
		clientstash->push_back(Block(index, data));
	}
}
//ocall define
void printint(int i)
{
	printf("\n该用户在服务端中的count值：%d\n", i);
}
//ocall get random number(0-num)
int getrandnum(int num)
{
	srand((unsigned)time(NULL));
	return rand() % num;
}
//存储用户权限oram
void Transferacbucket(int len, int index,int tag)
{
	ofstream out;
	if (tag == 0) {
		out.open(acbucket_location, ios::trunc | ios::binary);
	}
	else
	{
		out.open(acbucket_location, ios::app | ios::binary);
	}
	out.write((char*)(&len),sizeof(int));
	out.write((char*)(&index), sizeof(int));
	out.close();
}
//存储PosMap
void StorePosMap(int pos,int tag,int type)
{
	ofstream out;
	if (tag == 0 && type==0) {
		out.open(posmap_location, ios::trunc);
	}
	else if(tag != 0 && type == 0)
	{
		out.open(posmap_location, ios::app);
	}
	if (tag == 0 && type == 1)
	{
		out.open(acmap_location, ios::trunc);
	}
	else if (tag != 0 && type == 1)
	{
		out.open(acmap_location, ios::app);
	}
	out << pos << endl;
}
//序列化数据到本地
void SerializeORAM(char *data, int i, int index, int tag, size_t len)
{
	ofstream out;
	string url = bucket_location + to_string(i) + ".txt";
	if (tag == 0) {
		out.open(url, ios::trunc | ios::binary);
	}
	else  out.open(url, ios::app | ios::binary);
	out.write((char*)(&index), sizeof(index));
	out.write(data, len);
	out.close();
}
vector<char *> sdata;
vector<int> dataindex;
//反序列化本地文件
void DeserializeORAM(int path)
{
	string url = bucket_location + to_string(path) + ".txt";
	ifstream in(url,ios::binary);
	while (1) {
		char *sbuf=new char[1024];
		char ti[4];
		streamoff start = in.tellg();
		in.seekg(0, ios::end);
		streamoff end = in.tellg();
		int length = end - start;
		in.seekg(start);
		if (length > 0) {
			in.read(ti, sizeof(ti));
			in.read(sbuf, LENGTH);
			sdata.push_back(sbuf);
			dataindex.push_back(*(int*)ti);
		}
		else
		{
			delete sbuf;
			break;
		}
	}
}
//将用户文件按字节形式分块传入oram
void getuserBlock(int sign,string fileurl)
{
	int index = 0;
	char buf[LENGTH];
	sgx_enclave_id_t   eid;
	sgx_status_t       ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;
	streamoff start;
	streamoff end;
	streamoff  length;
	ifstream ifs(fileurl, ios::binary);
	//ofstream destfile("C:\\Users\\Administrator\\Desktop\\oram\\test3.txt", ios::binary | ios::app);
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		printf("\nApp: error %#x, failed to create enclave.\n", ret);
	}
	if (sign == 0) {
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
				SaveasBlock(eid, buf, i, LENGTH);
				/*if (i == index) {
					printf("before store in the oram %d position content:\n %s\n\n",index,buf);
				}*/
				i++;
			}
			else
			{
				memset(buf, 0, sizeof(buf));
				ifs.read(buf, length);
				SaveasBlock(eid, buf, i, LENGTH);
				break;
			}
		}
		InitORAM(eid);
	}
	//初始化本地userac到enclave
	else
	{
		//getBlock(eid);
		ifstream in;
		int len;
		int index;
		int id;
		int ac;
		int tag = 0;
		in.open(acbucket_location, ios::in | ios::binary);
		//vector<int> ttt1;
		while (in.peek() != EOF)
		{
			in.read((char*)&len, sizeof(int));
			in.read((char*)&index, sizeof(int));	
			//ttt1.push_back(len);
			for (int i = 0; i < len; i++)
			{
				in.read((char*)&id, sizeof(int));
				in.read((char*)&ac, sizeof(int));
				getacORAM(eid, index, id, ac, i, len, tag);
				tag = 1;
			}
		}
		in.close();
		tag = 0;
		in.open(acmap_location,ios::in);
		while (in)
		{
			in >> index;
			if (in.fail())
			{
				break;
			}
			getacPosMap(eid, index, tag,0);
			tag = 1;
			
		}
		in.close();
	}
	while (1) {
		char updatedata[1024];
		int userid;
		int ac;
		int re = 0;
		int *x=&re;
		int pattern;
		cout << "ADD user or search data:1.add 2.search" << endl;
		cin >> pattern;
		cout << "Please input index which you want to access:" << endl;
		cin >> index;
		if (index == -2) break;
		cout << "Please input your id:" << endl;
		cin >> userid;
		cout << "Please input your access pattern: 1.read,2.write" << endl;
		cin >> ac;
		//验证修改的权限是否被服务端接收
		if (pattern == 1)
		{
			temindex = index;
			temuserid = userid;
			temac = ac;
		}
		getuserdata(eid,x,pattern, index, userid, accesstype(ac));
		if (re == 1) {
			if (sign != 0) {
				int tag = 0;
				int pindex=0;
				int tindex = 0;
				ifstream in(posmap_location, ios::in);
				//get index in posmap and init posmap to enclave
				while (in)
				{
					in >> pindex;
					if (tag == index)
					{
						tindex = pindex;
					}
					if (in.fail())
					{
						break;
					}
					getacPosMap(eid, pindex, tag, 1);
					tag++;

				}
				DeserializeORAM(tindex);
				for (int i = 0; i < dataindex.size(); i++)
				{
					Transferid(eid, sdata.at(i), dataindex.at(i), LENGTH);
				}
				sdata.clear();
				dataindex.clear();
				in.close();
			}
			returnuserdata(eid,index,sign);
			for (int i = 0; i < clientstash->size(); i++)
			{
				if (clientstash->at(i).getIndex() == index)
				{
					printf("\nget %d data from ORAM in win side：\n%s\n", index, clientstash->at(i).getData());
					//write
					if (ac==2)
					{
						/*cout << "Please input your new data:" << endl;
						cin.get(updatedata,1024);
						clientstash->at(i).setData(updatedata);*/
						//将数据传回oram
						for (int tem=0;tem<clientstash->size();tem++)
						{
							SaveasBlock(eid,clientstash->at(tem).getData(),clientstash->at(tem).getIndex(),LENGTH);
						}
						setbackdata(eid);
					}
					//read
					else if(ac == 1)
					{
						for (int tem = 0; tem<clientstash->size(); tem++)
						{
							SaveasBlock(eid, clientstash->at(tem).getData(), clientstash->at(tem).getIndex(), LENGTH);
						}
						setbackdata(eid);
					}
				}
			}
			clientstash->clear();
		}
	}
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		printf("\nApp: error, failed to destroy enclave.\n");
	//for (int i = 0; i < clientstash->size(); i++)
	//{
	//		if (clientstash->at(i).getIndex() == index)
	//		{
	//			printf("\nget %d data from ORAM in win side：\n%s\n",index, clientstash->at(i).getData());
	//			//userdata = clientstash->at(i).getData();
	//		}
	//	
	//}
	//delete clientstash;
}

void testecc()
{
	sgx_enclave_id_t   eid;
	sgx_status_t       ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		printf("\nApp: error %#x, failed to create enclave.\n", ret);
	}
	getBlock(eid);
	sgx_destroy_enclave(eid);
	system("pause");
}