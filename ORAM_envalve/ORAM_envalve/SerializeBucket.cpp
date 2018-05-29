#include "Bucket.h"
#include <fstream>
#include <vector>
#include <string>
using namespace std;
void storebucket(vector<Bucket> *x)
{
	for (int j = 0; j < x->size(); j++) {
		string url = "D://user//Bucket" + to_string(j) + ".txt";
		ofstream out(url, ios::trunc | ios::binary);
		for (int i = 0; i < 4; i++) {
			//printf("%d/n%s", sizeof(b), b);
			int temi = x->at(j).getblock(i).getIndex();
			out.write((char*)(&temi), sizeof(temi));
			out.write(x->at(j).getblock(i).getData(), x->at(j).getblock(i).getcharlen());
		}
		out.close();
	}
}
vector<Bucket> getbuc(vector<int> tem)
{
	vector<Bucket> re;

	for (int i = 0; i < tem.size(); i++)
	{
		int index = 0;
		Block a;
		Bucket b;
		char buf[1024];
		char ti[4];
		string url = "D://user//Bucket" + to_string(tem.at(i)) + ".txt";
		ifstream in(url, ios::binary);
		while (1) {
			streamoff start = in.tellg();
			in.seekg(0, ios::end);
			streamoff end = in.tellg();
			int length = end - start;
			in.seekg(start);
			if (length > 0) {
				in.read(ti, sizeof(ti));
				in.read(buf, sizeof(buf));
				a.setData(buf);
				a.setIndex(*(int*)ti);
				b.addblock(a, index);
				index++;
			}
			else break;
		}
		re.push_back(b);
	}
	return re;
}