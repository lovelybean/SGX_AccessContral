#include "ORAM_envalve_t.h"
#include "sgx_trts.h"
#include "sgx_dh.h"
#include "Bucket.h"
#include "acBucket.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include "sgx_thread.h"
#include "ipp/ippcp.h"
#include "sgx_tae_service.h"
#include <map>
#include <queue>
#define SharedKey 592
#define ORDSIZE 8

sgx_thread_mutex_t GK_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t GA_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t GC_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t Q_mutex = SGX_THREAD_MUTEX_INITIALIZER;

vector<Block> *blocks=new vector<Block>();
vector<Bucket> *buckets = new vector<Bucket>();
vector<acBucket> *acbuckets=new vector<acBucket>();
typedef struct skey {
	uint8_t sharekey[32];
};
map<int,skey> *GlobalKeyManagement = new map<int, skey>;//用于存放ID对应的秘钥
map<int, sgx_mc_uuid_t> *GlobalCountManagement = new map<int, sgx_mc_uuid_t>;//用于存放用户对应的计数器值
map<int, map<int,int>*> *GlobalacManagement = new map<int, map<int,int>*>;//用于存放用户的权限表
queue<int> *FIFOqueue = new queue<int>;//用于保存FIFO的顺序，目前设置缓存为20000个用户
int bucketsize = 0;
vector<int> PosMap;
vector<int> acPosMap;
int TreeHeight = 0;
int Initialleaf = 0;
Bucket a;
int Z = a.getZ();
int h = 0;
int binnum = 0;
int storeid = 0;
int *hw = &h;
int *binnumw = &binnum;
//用户与服务端间数据交换结构
typedef struct requestheader {
	int ID;
	int Scount;
	int dataid;
	int ac;
}rh;
//generate a random number
int getrand(unsigned int num) {
	unsigned int r;
	unsigned int x = num;
	sgx_read_rand((unsigned char*)&r, sizeof(unsigned int));
	r = r%x;
	return int(r);
}
//get user data and store in the Block
void SaveasBlock(char *buf, int index, size_t len)
{
	//memcpy(s,buf,strlen(buf)+1);
	if (index != -1) {
		blocks->push_back(Block(index, buf));
	}
}
//get oramdata from win
vector<Bucket> *wbucket=new vector<Bucket>();
Bucket temb;
int sign = 0;
void Transferid(char *data, int index,size_t len)
{
	if(sign<Z) {
		Block tem;
		tem.setData(data);
		tem.setIndex(index);
		temb.addblock(tem,sign);
		sign++;
		if (sign==Z) 
		{
			sign = 0;
			wbucket->push_back(temb);
		}
	}
}
//init user data block in a PosMap
void InitPosMap()
{
	int numleaf = pow(2, TreeHeight);
	for (int i = 0; i < bucketsize; i++)
	{
		int num = getrand(numleaf);
		//destfile << num << endl;
		PosMap.push_back(num);
	}
	for (int i = 0; i < PosMap.size(); i++) {
		StorePosMap(PosMap.at(i),i,0);
	}
	//初始化用户权限posmap
	for (int i = 0; i < bucketsize; i++)
	{
		int num = getrand(numleaf);
		acPosMap.push_back(num);
	}
	for (int i = 0; i < acPosMap.size(); i++) {
		StorePosMap(acPosMap.at(i), i, 1);
	}
}
//get acposmap from disk
void getacPosMap(int index,int tag,int type)
{
	if (type == 0) {
		if (tag == 0) {
			acPosMap.clear();
			acPosMap.push_back(index);
		}
		else
		{
			acPosMap.push_back(index);
		}
	}
	else if (type == 1)
	{
		if (tag == 0) {
			PosMap.clear();
			PosMap.push_back(index);
		}
		else
		{
			PosMap.push_back(index);
		}
	}
}
//get store pos in the vector<bucket>
int getPos(int leaf, int h)
{
	int bnum = pow(2, TreeHeight) + leaf;
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
//Init bucket with user data block
void Initbucket(int totalnum)
{
		for (int i = 0; i<totalnum; i++) {
			buckets->push_back(Bucket());
		}
}
//初始化useracbucket
int ach = 0;
int acbinnum = 0;
int acstoreid = 0;
int *achw = &ach;
int *acbinnumw = &acbinnum;
//transfer acbuckets to win and store in disk
void transferac(vector<acBucket> *tem)
{
	int tag = 0;
	for (int i = 0; i<tem->size(); i++)
	{
		for (int j = 0; j < Z; j++)
		{
			int maplen = tem->at(i).getacblock(j)->getmaplen();
			int acbindex = tem->at(i).getacblock(j)->getIndex();
			Transferacbucket(maplen,acbindex,tag);
			tag=1;
			map<int, accesstype> tac = tem->at(i).getacblock(j)->returnmap();
			auto iter = tac.begin();
			while(iter!=tac.end())
			{
				Transferacbucket(iter->first, iter->second,tag);
				iter++;
			}
		}
	}
}
//初始化用户权限oram
void InitacBucket(int initnum)
{
	for (int x = 0; x<initnum; x++) {
		acbuckets->push_back(acBucket());
	}
	for (int i = 0; i < acPosMap.size(); i++)
	{
		ach = getrand(TreeHeight + 1);
		acbinnum = getrand(Z);
		acstoreid = getPos(acPosMap.at(i), ach);
		while (acbuckets->at(acstoreid).Haverealacblock(acbinnum))
		{
			getrandnum(achw, TreeHeight + 1);
			getrandnum(acbinnumw, Z);
			acstoreid = getPos(acPosMap.at(i), ach);
		}
		acbuckets->at(acstoreid).getacblock(acbinnum)->setIndex(i);
	}
}
//store block in bucket
void Randomstoreblock(int leaf, Block block, vector<Bucket> *buckets)
{
	h = getrand(TreeHeight + 1);
	binnum = getrand(Z);
	storeid = getPos(leaf, h);
	while (buckets->at(storeid).Haverealblock(binnum))
	{
		getrandnum(hw,TreeHeight + 1);
		getrandnum(binnumw,Z);
		storeid=getPos(leaf, h);
	}
	buckets->at(storeid).addblock(block, binnum);
}
//store block in bucket
void storeuserblock()
{
	for (int i = 0; i < PosMap.size(); i++)
	{
		int leaf = PosMap.at(i);
		Randomstoreblock(leaf, blocks->at(i), buckets);
		//printf("%s\n\n\n", buckets.at(c).getblock(b).getData());
	}
	blocks->clear();
	//把ORAM存储到本地，此处存在一个问题（按叶节点链路存储会储存大量的冗余信息，但速度应该快，按每个bucket存储，会占用一定多于空间，因为一般每页为4kb，并且会走大量io，导致速度慢）
	for (int i = 0; i < pow(2, TreeHeight); i++)
	{
		int tag = 0;
		for (int j = 0; j <=TreeHeight; j++)
		{
			Bucket tem;
			tem = buckets->at(getPos(i, j));
			for (int k = 0; k < Z; k++) {
				SerializeORAM(tem.getblock(k).getData(), i,tem.getblock(k).getIndex(), tag,tem.getblock(k).getcharlen());
				tag++;
			}
		}
	}
}
//test get user clientstash
vector<Bucket> *getClienstash(int index)
{
	vector<Bucket> *clientstash = new vector<Bucket>();
	int udataindex = index + pow(2, TreeHeight);
	for (int i = TreeHeight; i >= 0; i--)
	{
		clientstash->push_back(buckets->at(udataindex - 1));
		udataindex = udataindex / 2;
	}
	return clientstash;
}
//初始化oram
void InitORAM() {
	 bucketsize = blocks->size();
	 TreeHeight = ceil(log(bucketsize) / log(2)) - 1;
	 InitPosMap();
	 Initbucket(pow(2, (TreeHeight + 1)) - 1);
	 storeuserblock();
	 InitacBucket(pow(2, (TreeHeight + 1)) - 1);
	 transferac(acbuckets);
}
//get acORAM from disk
acBucket temacbu;
acBlock temacbl;
int acbsign = 0;
map<int, accesstype> *tac;
//将用户权限表从disk调入enclave
void getacORAM(int index, int id, int ac,int lo, int len, int tag)
{
	//tttt1.push_back(index);
	if (tag == 0) {
		acbuckets->clear();
	}
	if(len==1)
	{
		tac = new map<int, accesstype>();
		tac->insert(make_pair(id, accesstype(ac)));	
		temacbl.givemap(tac);
		temacbl.setIndex(index);
		if (acbsign < (Z-1))
		{
			temacbu.addblock(temacbl, acbsign);
			acbsign++;
		}
		else
		{	
			temacbu.addblock(temacbl, acbsign);
			acbsign = 0;
			acbuckets->push_back(temacbu);
		}
	}else if (len > 1) {
		if (lo == 0)
		{
			tac = new map<int, accesstype>();
			tac->insert(make_pair(id, accesstype(ac)));
		}
		else if (lo>0&&lo < (len - 1))
		{
			tac->insert(make_pair(id, accesstype(ac)));
		}
		else if (lo == (len - 1))
		{
			tac->insert(make_pair(id, accesstype(ac)));
			temacbl.givemap(tac);
			temacbl.setIndex(index);
			if (acbsign < (Z-1))
			{
				temacbu.addblock(temacbl, acbsign);
				acbsign++;
			}
			else
			{
				temacbu.addblock(temacbl, acbsign);
				acbsign = 0;
				acbuckets->push_back(temacbu);
			}
		}
	}
}
//将用户权限加入到acbuckets
int k = -1;
void SetUserAccessRight(int userid, int dataindex, accesstype userac)
{
	//void signgetacORAM();
	for (int i = 0; i < acbuckets->size(); i++)
	{
		for (int j = 0; j < Z; j++)
		{
			if (acbuckets->at(i).getacblock(j)->getIndex() == dataindex)
			{
				acbuckets->at(i).getacblock(j)->setMap(userid, userac);
			}
			else 
			{
				int tem = getrand(3);
				acbuckets->at(i).getacblock(j)->setMap(k, accesstype(tem));
			}
		}
	}
	k--;
	transferac(acbuckets);
}
//add user info or search data for user
int getuserdata(int pattern,int index,int userid,accesstype userac)
{
	TreeHeight = ceil(log(acPosMap.size()) / log(2)) - 1;
	int re = 0;
	//接受用户端传来的确认参数
	int rac = 0;
	int *temrac = &rac;
	if (pattern == 1) {
		acValidity(temrac, index, userid, userac);
		if (rac==1) {
			SetUserAccessRight(userid, index, userac);
			return 2;
		}
		//数据有错误
		else return 3;
	}
	else if (pattern == 2) {
		vector<acBucket> userbucket;
		vector<acBlock*> userblock;
		vector<acBlock*> temblock;
		vector<acBlock*> temblock1;
		int useridindex = acPosMap.at(index) + pow(2, TreeHeight);
		//给useraccess重新分配叶节点
		int x = acPosMap.at(index);
		acPosMap[index] = getrand(pow(2, TreeHeight));
		for (int i = 0; i < acPosMap.size(); i++) {
			StorePosMap(acPosMap.at(i), i, 1);
		}
		for (int i = TreeHeight; i >= 0; i--)
		{
			userbucket.push_back(acbuckets->at(useridindex - 1));
			useridindex = useridindex / 2;
		}
		for (int i = 0; i < userbucket.size(); i++)
		{
			for (int j = 0; j < Z; j++)
			{
				userblock.push_back(userbucket.at(i).getacblock(j));
				if (userbucket.at(i).getacblock(j)->getIndex() == index) {
					if (userbucket.at(i).getacblock(j)->haveid(userid)) {
						//test ac
						//int tem = userbucket.at(i).getacblock(j)->getac(userid);
						if (userbucket.at(i).getacblock(j)->getac(userid) >= userac)
						{
							re = 1;
						}
						else
						{
							printblock("you don't have right to access data");
							break;
						}
					}
					else
					{
						printblock("don't have this id");
						break;
					}
				}
			}		
		}
		//将acblock按照新的页节点放回oram
		int maplen = 0;
		for (int i = TreeHeight; i >= 0;i--) {
			for (int j = 0; j < userblock.size(); j++)
			{
				if (userblock.at(j)->getIndex() != -1)
				{
					if (getPos(acPosMap.at(userblock.at(j)->getIndex()), i) == getPos(x, i))
					{
						maplen = userblock.at(j)->getmaplen();
						temblock.push_back(userblock.at(j));
					}
				}
			}
			if (temblock.size() >= Z)
			{
				temblock.assign(temblock.begin(),temblock.begin()+Z);
				acbuckets->at(getPos(x, i)).ReplaceBucket(temblock);
				set_symmetric_difference(userblock.cbegin(), userblock.cend(), temblock.cbegin(), temblock.cend(), inserter(temblock1, temblock1.begin()));
				userblock.assign(temblock1.begin(),temblock1.end());
				temblock1.clear();
				temblock.clear();
			}
			else
			{
				set_symmetric_difference(userblock.cbegin(),userblock.cend(),temblock.cbegin(),temblock.cend(),inserter(temblock1,temblock1.begin()));
				userblock = temblock1;
				for (int k = temblock.size(); k < Z; k++)
				{
					temblock.push_back(&acBlock(maplen));
				}
				acbuckets->at(getPos(x, i)).ReplaceBucket(temblock);
				temblock.clear();
				temblock1.clear();
			}
		}
		transferac(acbuckets);
	}
	return re;
}
//give a sign to win to show result
void returnuserdata(int index,int sign)
{
	//给data节点重新分配叶节点
	Initialleaf = PosMap.at(index);
	PosMap[index]= getrand(pow(2, TreeHeight));
	for (int i = 0; i < PosMap.size(); i++) {
		StorePosMap(PosMap.at(i), i, 0);
	}
	vector<Bucket> *clientstash;
	if (sign == 1) {
		clientstash = wbucket;
	}
	else if (sign == 0) {
		clientstash = getClienstash(Initialleaf);
	}
	for (int i = 0; i < clientstash->size(); i++)
	{
		for (int j = 0; j < 4; j++)
		{
			transferstash(clientstash->at(i).getblock(j).getData(), clientstash->at(i).getblock(j).getIndex(), clientstash->at(i).getblock(j).getcharlen());
		}
	}
	delete clientstash;
}
//set back the user data
void setbackdata()
{
	vector<Block> temblock;
	vector<Block> totalblock;
	for (int th = TreeHeight; th >= 0;th--) {
		for (int i = 0; i < blocks->size(); i++)
		{
			if (blocks->at(i).getIndex() != -1)
			{
				if (getPos(PosMap.at(blocks->at(i).getIndex()),th) == getPos(Initialleaf, th))
				{
					temblock.push_back(blocks->at(i));
				}
			}
		}
		if (temblock.size() >= Z)
		{
			temblock.assign(temblock.begin(),temblock.begin()+Z);
			totalblock.insert(totalblock.end(),temblock.begin(),temblock.end());
			//buckets->at(getPos(Initialleaf, th)).ReplaceBucket(temblock);
			for (int f = 0; f < temblock.size(); f++) {
				auto iter = blocks->begin();
				while (iter!=blocks->end())
				{
					if (iter->getIndex() == temblock.at(f).getIndex())
					{
						blocks->erase(iter);
						break;
					}
					else
					{
						iter++;
					}
				}
			}
			temblock.clear();
		}
		else if (temblock.size() < Z)
		{
			//从blocks中删除符合条件元素，此处有改进的地方，目前复杂度太高
			for (int f = 0; f < temblock.size(); f++) {
				auto iter = blocks->begin();
				while (iter != blocks->end())
				{
					if (iter->getIndex() == temblock.at(f).getIndex())
					{
						blocks->erase(iter);
						break;
					}
					else
					{
						iter++;
					}
				}
			}
			for (int j=temblock.size();j<Z;j++)
			{
				temblock.push_back(Block());
			}
			//文件过大可能导致内存放不下，所以采用按路径存取
			//buckets->at(getPos(Initialleaf, th)).ReplaceBucket(temblock);
			totalblock.insert(totalblock.end(), temblock.begin(), temblock.end());
			temblock.clear();
		}
	}
	int tag = 0;
	for (int i = TreeHeight; i >=0; i--) 
	{
		int temnum = i*Z;
		for (int j = 0; j < Z; j++)
		{
			SerializeORAM(totalblock.at(temnum+j).getData(), Initialleaf, totalblock.at(temnum + j).getIndex(),tag, totalblock.at(temnum + j).getcharlen());
			tag++;
		}
	}
	totalblock.clear();
	blocks->clear();
}
//test function
void getBlock()
{
	//InitORAM();
	//getuserdata(2, 5, 23, accesstype(1));
	//getacORAM(1,3,2,0,3,0);
	//getacORAM(1, 2, 2, 1, 3, 1);
	//getacORAM(1, 1, 2, 2, 3, 1);
	sgx_ecc_state_handle_t test;
	sgx_ecc256_open_context(&test);
	sgx_ec256_private_t prkey;
	sgx_ec256_public_t pubkey;
	sgx_ecc256_create_key_pair(&prkey,&pubkey,test);
}

//Local Attestation
sgx_key_128bit_t dh_aek;        // Session Key
sgx_enclave_id_t enclave2_id;
uint32_t Buildsecurepath(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id) {
	sgx_dh_session_t sgx_dh_session;
	uint32_t retstatus;
	sgx_dh_msg1_t dh_msg1;
	uint32_t session_id;
	sgx_status_t status = SGX_SUCCESS;
	sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &sgx_dh_session);
	status = session_request_lo(&retstatus, src_enclave_id, dest_enclave_id, &dh_msg1, &session_id);
	//Process the message 1 obtained from desination enclave and generate message 2
	sgx_dh_msg2_t dh_msg2;
	status = sgx_dh_initiator_proc_msg1(&dh_msg1, &dh_msg2, &sgx_dh_session);
	if (SGX_SUCCESS != status)
	{
		return status;
	}
	//Send Message 2 to Destination Enclave and get Message 3 in return
	sgx_dh_msg3_t dh_msg3;
	status = exchange_report_lo(&retstatus, src_enclave_id, dest_enclave_id, &dh_msg2, &dh_msg3, session_id);
	if (status == SGX_SUCCESS)
	{
		sgx_dh_session_enclave_identity_t responder_identity;
		status = sgx_dh_initiator_proc_msg3(&dh_msg3, &sgx_dh_session, &dh_aek, &responder_identity);
		disp(dh_aek,sizeof(sgx_aes_ctr_128bit_key_t));
		enclave2_id = dest_enclave_id;
	}
	else
	{
		return -1;
	}

}




//连接两个数据段
uint8_t* linkarray(void *a,size_t al,void *b,size_t bl)
{
	uint8_t *c;
	c = new uint8_t[al+bl];
	memcpy(c,a,al);
	memcpy(c + al, b, bl);
	return c;
}
//验证hash并存储权限表到本地
typedef struct send2server
{
	uint32_t version;
	uint32_t datasize;
	uint32_t ID;
	uint8_t hash[SGX_SHA256_HASH_SIZE];
	uint8_t data[];
}pd;//代理与服务端间数据结构
typedef struct replay_protected_pay_load
{
	sgx_mc_uuid_t mc;
	uint32_t mc_value;
	uint8_t secret[];
}sec;
typedef struct ProxyandServerCount {
	sgx_mc_uuid_t mc;
	uint32_t mc_value;
}PSC;
PSC temp_unseal;
uint32_t createcount(uint8_t *data, size_t len) {
	uint32_t ret = 0;
	int busy_retry_times = 2;
	PSC psc;
	memset(&psc, 0, sizeof(psc));
	uint32_t size = sgx_calc_sealed_data_size(0, sizeof(PSC));
	do {
		ret = sgx_create_pse_session();
	} while (ret == SGX_ERROR_BUSY && busy_retry_times--);
	if (ret != SGX_SUCCESS)
		return ret;
	do
	{
		ret = sgx_create_monotonic_counter(&psc.mc, &psc.mc_value);
		if (ret != SGX_SUCCESS)
		{
			switch (ret)
			{
			case SGX_ERROR_SERVICE_UNAVAILABLE:
				/* Architecture Enclave Service Manager is not installed or not
				working properly.*/
				break;
			case SGX_ERROR_SERVICE_TIMEOUT:
				/* retry the operation later*/
				break;
			case SGX_ERROR_BUSY:
				/* retry the operation later*/
				break;
			case SGX_ERROR_MC_OVER_QUOTA:
				/* SGX Platform Service enforces a quota scheme on the Monotonic
				Counters a SGX app can maintain. the enclave has reached the
				quota.*/
				break;
			case SGX_ERROR_MC_USED_UP:
				/* the Monotonic Counter has been used up and cannot create
				Monotonic Counter anymore.*/
				break;
			default:
				/*other errors*/
				break;
			}
			break;
		}
		ret = sgx_seal_data(0, NULL, sizeof(psc), (uint8_t*)&psc,
			len, (sgx_sealed_data_t*)data);
	} while (0);
	memset_s(&psc, sizeof(PSC), 0,sizeof(PSC));
	sgx_close_pse_session();
	return ret;
}
//Vcount值更新，自增1
uint32_t updatecount(uint8_t *data, size_t len) {
	uint32_t ret = 0;
	int busy_retry_times = 2;
	do {
		ret = sgx_create_pse_session();
	} while (ret == SGX_ERROR_BUSY && busy_retry_times--);
	sgx_increment_monotonic_counter(&temp_unseal.mc,&temp_unseal.mc_value);
	ret = sgx_seal_data(0, NULL, sizeof(PSC), (uint8_t*)&temp_unseal,len, (sgx_sealed_data_t*)data);
	sgx_close_pse_session();
	return ret;
}
int Decryptcount(uint8_t *data)
{
	uint32_t ret = 0;
	int busy_retry_times = 2;
	do {
		ret = sgx_create_pse_session();
	} while (ret == SGX_ERROR_BUSY && busy_retry_times--);
	if (ret != SGX_SUCCESS)
		return -1;
	uint32_t unseal_length = sizeof(PSC);
	ret = sgx_unseal_data((const sgx_sealed_data_t*)data, NULL, 0,
		(uint8_t*)&temp_unseal, &unseal_length);
	uint32_t mc_value;
	ret = sgx_read_monotonic_counter(&temp_unseal.mc, &mc_value);
	if (ret != SGX_SUCCESS) return -1;
	//if (mc_value != temp_unseal.mc_value) return -1;
	return mc_value;
	
}
uint32_t DetectacData(uint8_t *data, size_t len,uint8_t * Endata,size_t outlen)
{
	uint32_t ret = 0;
	pd *p2data;
	do {
		p2data = (pd*)malloc(len);
		if (p2data==NULL)
		{
			printblock("not have enough memory..........");
			break;
		}
		memcpy(p2data,data,len);
		uint8_t Vcount[580];
		GetVcount(Vcount,sizeof(Vcount));
		//对Vcount进行解密
		int vcount = Decryptcount(Vcount);
		if (vcount == -1) { return -1; }
		//int tvcount = vcount + 1;
		if (vcount == p2data->version) {
			uint8_t *hashdata;
			hashdata = linkarray(&p2data->version, sizeof(uint32_t), p2data->data, p2data->datasize);
			sgx_sha256_hash_t dhash;
			sgx_sha256_msg(hashdata, sizeof(uint32_t) + (p2data->datasize), &dhash);
			delete hashdata;
			printhash(dhash,32);
			//计算data、id、vcount的hash来传给客户端，保证代理端提交的信息正确接受,考虑要不要这步。
			/*uint8_t *s2phash;
			hashdata = linkarray(&p2data->ID,sizeof(uint32_t),p2data->data,p2data->datasize);
			s2phash = linkarray(hashdata,sizeof(uint32_t)+p2data->datasize,&tvcount,sizeof(int));
			sgx_sha256_msg(s2phash, sizeof(uint32_t) + (p2data->datasize)+sizeof(int),(sgx_sha256_hash_t*)nhash);
			delete hashdata;
			delete s2phash;*/


			//将代理端传来的数据加密并绑定一个计数器
			if (!memcmp(dhash, p2data->hash, SGX_SHA256_HASH_SIZE))
			{
				sec *usersecret;
				usersecret = (sec*)malloc(sizeof(sec) + p2data->datasize);
				int busy_retry_times = 2;
				uint32_t size = sgx_calc_sealed_data_size(0, sizeof(sec) + p2data->datasize);
				do {
					ret = sgx_create_pse_session();
				} while (ret == SGX_ERROR_BUSY && busy_retry_times--);
				if (ret != SGX_SUCCESS) {
					return -1;
				}
				ret = sgx_create_monotonic_counter(&usersecret->mc, &usersecret->mc_value);
				if (ret != SGX_SUCCESS)
				{
					return -1;
				}
				memcpy(&usersecret->secret, &p2data->data, p2data->datasize);
				uint32_t datalen = sizeof(sec) + p2data->datasize;
				uint8_t *tampdata=new uint8_t[datalen];
				memcpy(tampdata,usersecret,datalen);
				ret = sgx_seal_data(0, NULL, datalen, tampdata,outlen, (sgx_sealed_data_t*)Endata);
				//测试
				//uint8_t ppp[660];
				//memcpy(ppp,Endata,660);
				delete[]tampdata;
				if (ret == SGX_SUCCESS) {
					ret=p2data->ID;
				}
				delete usersecret;
				free(p2data);
			}
			else
			{
				return -1;
			}
		}
		else
		{
			return -1;
		}
	} while (0);
	sgx_close_pse_session();
	return ret;
}
//加密
uint32_t AES_Encryptcbc(uint8_t* key, size_t len, uint8_t *plaintext, size_t plen, uint8_t *Entext) {
	int size = 0;
	IppStatus re = ippStsNoErr;
	ippsAESGetSize(&size);
	IppsAESSpec *pCtx;
	pCtx = (IppsAESSpec *)malloc(size);
	memset(pCtx, 0, size);
	re = ippsAESInit(key, len, pCtx, size);
	Ipp8u piv[] = "\xff\xee\xdd\xcc\xbb\xaa\x99\x88"
		"\x77\x66\x55\x44\x33\x22\x11\x00";
	Ipp8u ctr[16];
	memcpy(ctr, piv, sizeof(ctr));
	re = ippsAESEncryptCBC(plaintext, Entext, plen, pCtx, ctr);
	ippsAESInit(0, len, pCtx, size);
	free(pCtx);
	return re;
}
//解密
uint32_t AES_Decryptcbc(uint8_t* key, size_t len, uint8_t *Entext, uint8_t *plaintext, size_t plen) {
	int size = 0;
	IppStatus re = ippStsNoErr;
	ippsAESGetSize(&size);
	IppsAESSpec *pCtx;
	pCtx = (IppsAESSpec *)malloc(size);
	memset(pCtx, 0, size);
	re = ippsAESInit(key, len, pCtx, size);
	Ipp8u piv[] = "\xff\xee\xdd\xcc\xbb\xaa\x99\x88"
		"\x77\x66\x55\x44\x33\x22\x11\x00";
	Ipp8u ctr[16];
	memcpy(ctr, piv, sizeof(ctr));
	re = ippsAESDecryptCBC(Entext, plaintext, plen, pCtx, ctr);
	ippsAESInit(0, len, pCtx, size);
	free(pCtx);
	return re;
}

//由于不知道SGX内部的曲线函数，故无法与外部进行交换,试过nist p-256曲线，但是不对
//int GetServerpublickey(uint8_t *px,uint8_t *py,size_t len)
//{
//	sgx_ecc_state_handle_t ec;
//	sgx_ecc256_open_context(&ec);	
//	sgx_ec256_public_t pt;
//	memset(&pt,0,sizeof(pt));
//	int re=sgx_ecc256_create_key_pair(&prt,&pt,ec);
//	memcpy(&testsp,&pt,sizeof(pt));
//	if (re==SGX_SUCCESS&&sizeof(pt.gx)==len) {
//		memcpy(px,pt.gx,SGX_ECP256_KEY_SIZE);
//		memcpy(py, pt.gy, SGX_ECP256_KEY_SIZE);
//	}
//	sgx_ecc256_close_context(ec);
//	return re;
//}
uint32_t Sealdata(uint8_t *data,int len,uint8_t *sealdata) {
	uint32_t ret = 0;
	uint32_t size = sgx_calc_sealed_data_size(0, len);
	ret = sgx_seal_data(0, NULL, len, data,
		size, (sgx_sealed_data_t*)sealdata);
	return ret;
}
//解密数据
uint32_t UnSealdata(uint8_t* data,void *unsealdata,uint32_t *unseallen) {
	uint32_t ret = 0;
	ret = sgx_unseal_data((const sgx_sealed_data_t*)data,NULL,0,(uint8_t*)unsealdata,unseallen);
	return ret;
}
//get encrypt size 为了使要加密的数据长度为16的倍数，所以需要进行数据填充
uint32_t getEncryptdatalen(int len) {
	uint32_t size=0;
	if (len % 16 == 0) {
		size= len;
	}
	else {
		size=len + (16-(len % 16));
	}
	return size;
}
//test sharekey
uint8_t* TestSharekey(sgx_ec256_dh_shared_t p_shared_key,size_t len) {
	int test = 1;
	int size = getEncryptdatalen(sizeof(int));
	Ipp8u *data = new Ipp8u[size];
	memset(data,0,size);
	memcpy(data, (uint8_t*)&test,sizeof(int));
	Ipp8u *endata=new Ipp8u[size];
	uint32_t re = AES_Encryptcbc(p_shared_key.s,len,data,size,endata);
	delete data;
	return endata;
}
uint8_t senddata[16];
int gettestdata(uint8_t *data, size_t len) {
	memcpy(data,senddata,len);
	memset(senddata, 0, len);
	return SGX_SUCCESS;
}



//使用IPP库与openssl进行密钥交换
static IppsECCPState* newStd_256_ECP(void)
{
	int ctxSize;
	ippsECCPGetSize(256, &ctxSize);
	IppsECCPState* pCtx = (IppsECCPState*)(new Ipp8u[ctxSize]);
	ippsECCPInit(256, pCtx);
	ippsECCPSetStd(IppECCPStd256r1, pCtx);
	return pCtx;
}

static IppsECCPPointState* newECP_256_Point(void)
{
	int ctxSize;
	ippsECCPPointGetSize(256, &ctxSize);
	IppsECCPPointState* pPoint = (IppsECCPPointState*)(new Ipp8u[ctxSize]);
	ippsECCPPointInit(256, pPoint);
	return pPoint;
}

static IppsBigNumState* newBN(int len, const Ipp32u* pData)
{
	int ctxSize;
	ippsBigNumGetSize(len, &ctxSize);
	IppsBigNumState* pBN = (IppsBigNumState*)(new Ipp8u[ctxSize]);
	ippsBigNumInit(len, pBN);
	if (pData)
		ippsSet_BN(IppsBigNumPOS, len, pData, pBN);
	return pBN;
}
IppsPRNGState* newPRNG(void)
{
	int ctxSize;
	ippsPRNGGetSize(&ctxSize);
	IppsPRNGState* pCtx = (IppsPRNGState*)(new Ipp8u[ctxSize]);
	ippsPRNGInit(160, pCtx);
	return pCtx;
}

IppsBigNumState* regPrivate = newBN(8, 0);
sgx_ec256_dh_shared_t shared_key;
//用ipp重写ECC算法实现与openssl进行秘钥协商,这里生成公钥与私钥
int GetServerpublickey(uint8_t *px, uint8_t *py, size_t len) {
	// define standard 256-bit EC 
	IppsECCPState* pECP = newStd_256_ECP();
	// define a message to be signed; let it be random, for example 
	IppsPRNGState* pRandGen = newPRNG(); // 'external' PRNG 
	IppsECCPPointState* regPublic = newECP_256_Point();
	IppStatus re;
	re = ippsECCPGenKeyPair(regPrivate, regPublic, pECP, ippsPRNGen, pRandGen);
	IppsBigNumState* pSPPublicX = newBN(ORDSIZE, 0);
	IppsBigNumState* pSPPublicY = newBN(ORDSIZE, 0);
	re=ippsECCPGetPoint(pSPPublicX, pSPPublicY, regPublic, pECP);
	re=ippsGetOctString_BN(px, 32, pSPPublicX);
	re=ippsGetOctString_BN(py, 32, pSPPublicY);
	delete[](Ipp8u*)pSPPublicX;
	delete[](Ipp8u*)pSPPublicY;
	delete[](Ipp8u*)regPublic;
	delete[](Ipp8u*)pRandGen;
	delete[](Ipp8u*)pECP;
	return re;
}
//计算共享秘钥
int ComputeSharekey(uint8_t *px, uint8_t *py, size_t len) {
	IppStatus re;
	IppsECCPState* pECP = newStd_256_ECP();
	IppsECCPPointState* regPublic = newECP_256_Point();
	IppsBigNumState* pSPPublicX = newBN(ORDSIZE, 0);
	IppsBigNumState* pSPPublicY = newBN(ORDSIZE, 0);
	ippsSetOctString_BN(px,32,pSPPublicX);
	ippsSetOctString_BN(py,32,pSPPublicY);
	re=ippsECCPSetPoint(pSPPublicX, pSPPublicY, regPublic, pECP);
	IppsBigNumState* pShare = newBN(ORDSIZE, 0);
	re = ippsECCPSharedSecretDH(regPrivate,regPublic,pShare,pECP);
	re = ippsGetOctString_BN(shared_key.s, 32, pShare);
	disp(shared_key.s, 32);
	if (re==ippStsNoErr) 
	{
		uint8_t *sd= TestSharekey(shared_key, SGX_ECP256_KEY_SIZE);
		memcpy(senddata, sd, 16);
		delete sd;	
	}
	delete[](Ipp8u*)pShare;
	delete[](Ipp8u*)pSPPublicX;
	delete[](Ipp8u*)pSPPublicY;
	delete[](Ipp8u*)regPublic;
	delete[](Ipp8u*)regPrivate;
	delete[](Ipp8u*)pECP;
	return re;
}
//int ComputeSharekey(uint8_t *px, uint8_t *py, uint8_t *prk,size_t len) {
//	sgx_ecc_state_handle_t ec;
//	/*sgx_ec256_dh_shared_t testcp;
//	memset(&testcp,0,sizeof(testcp));
//	sgx_ec256_private_t testprk;
//	memcpy(testprk.r,prk,32);*/
//
//	sgx_ecc256_open_context(&ec);
//	/*int pp = sgx_ecc256_compute_shared_dhkey(&testprk, &testsp, &testcp, ec);
//	disp(testcp.s, 32);*/
//	sgx_ec256_public_t cp;
//	memset(&cp,0,sizeof(sgx_ec256_public_t));
//	memcpy(cp.gx,px,len);
//	memcpy(cp.gy, py, len);
//
//	//检查该点是否在曲线上
//	int cr = -1;
//	sgx_ecc256_check_point(&cp,ec,&cr);
//	if (cr != 1) {
//		return -1;
//	}
//	int re = sgx_ecc256_compute_shared_dhkey(&prt, &cp, &shared_key, ec);
//	disp(shared_key.s, 32);
//	if (re==SGX_SUCCESS) 
//	{
//		uint8_t *sd= TestSharekey(shared_key, SGX_ECP256_KEY_SIZE);
//		memcpy(senddata, sd, 16);
//		delete sd;	
//	}
//	sgx_ecc256_close_context(ec);
//	return re;
//}
int Insertskey(uint8_t* sealkey,size_t len) {
	int re = 1;
	int size = sgx_calc_sealed_data_size(0,sizeof(sgx_ec256_dh_shared_t));
	if (len == size) {
		uint8_t sealdata[sizeof(sgx_ec256_dh_shared_t) + 560];
		re = Sealdata((uint8_t*)&shared_key, sizeof(sgx_ec256_dh_shared_t), sealdata);
		if (re == SGX_SUCCESS&&len == SharedKey) {
			memcpy(sealkey, sealdata, SharedKey);
			memset(shared_key.s, 0, SGX_ECP256_KEY_SIZE);
		}
		else
		{
			re = -1;
		}
	}
	return re;
}
//获取Uscount值
int GetUscount(sgx_mc_uuid_t *mc, uint32_t *mc_value) {
	uint32_t ret = 0;
	int busy_retry_times = 2;
	do {
		ret = sgx_create_pse_session();
	} while (ret == SGX_ERROR_BUSY && busy_retry_times--);
	ret=sgx_read_monotonic_counter(mc, mc_value);
	sgx_close_pse_session();
	return ret;
}
int UpdateUscount(sgx_mc_uuid_t *mc) {
	uint32_t ret = 0;
	int busy_retry_times = 2;
	do {
		ret = sgx_create_pse_session();
	} while (ret == SGX_ERROR_BUSY && busy_retry_times--);
	uint32_t temnum = 0;
	ret = sgx_increment_monotonic_counter(mc,&temnum);
	sgx_close_pse_session();
	return ret;
}
//序列化map
std::string* SerializeMap(std::map<int, int> *tem)
{
	std::string *Mchar = new std::string;
	std::map<int, int>::iterator it;
	it = tem->begin();
	while (it != tem->end()) {
		Mchar->push_back(it->first);
		Mchar->push_back(it->second);
		it++;
	}
	return Mchar;
}
//传送到enclave2的数据结构
typedef struct Tofileenclave {
	int dataid;
	sgx_ec256_dh_shared_t userkey;
	int ac;
};
typedef struct UserRequest {
	uint32_t ID;
	uint32_t len;
	uint8_t data[16];
};
int Requestislegal(int ID, uint8_t* data, size_t len, uint8_t *Response, size_t Reslen);
uint32_t AnalysisRequest(uint8_t *request, size_t len, uint8_t *Response, size_t Reslen) {
	uint32_t re = 0;
	uint8_t *Derequest = new uint8_t[len];
	UserRequest tampR;
	re = AES_Decryptcbc(dh_aek, sizeof(sgx_aes_ctr_128bit_key_t),request,Derequest,len);
	memcpy((uint8_t*)&tampR,Derequest,sizeof(tampR));
	delete[] Derequest;
	re=Requestislegal(tampR.ID,tampR.data,tampR.len,Response,Reslen);
	return re;
}
int Requestislegal(int ID,uint8_t* data, size_t len, uint8_t *Response, size_t Reslen) {
	rh temdata;
	int flag = 0;
	sec *earsedata;
	uint32_t re = -1;
	sec *userac;
	uint8_t* replaydata;
	int topid = -1;
	sgx_thread_mutex_lock(&GA_mutex);
	int isexist = GlobalacManagement->count(ID);
	sgx_thread_mutex_unlock(&GA_mutex);
	if ( isexist== 0) {
		//读数据from disk
		uint8_t *userdata;
		size_t datalen;
		Getdatalen(&datalen, ID);//获取用户数据长度
		userdata = (uint8_t*)malloc(datalen);
		Getuserdatafromdisk(ID, userdata, datalen);
		skey tem;
		uint32_t keylen = SGX_ECP256_KEY_SIZE;
		uint8_t keydata[SharedKey];
		memcpy(keydata,userdata,SharedKey);
		re = UnSealdata(keydata, tem.sharekey, &keylen);//获取该用户的协商秘钥
		//disp(tem.sharekey, keylen);
		if (re != SGX_SUCCESS) {
			return re;
		}
		sgx_thread_mutex_lock(&Q_mutex);
		int fisize = FIFOqueue->size();
		sgx_thread_mutex_unlock(&Q_mutex);
		if ( fisize< 20000) {
			sgx_thread_mutex_lock(&Q_mutex);
			FIFOqueue->push(ID);
			sgx_thread_mutex_unlock(&Q_mutex);
			sgx_thread_mutex_lock(&GK_mutex);
			GlobalKeyManagement->insert(pair<int, skey>(ID, tem));//将用户秘钥放入map
			sgx_thread_mutex_unlock(&GK_mutex);
		}
		else
		{
			flag = 1;
			sgx_thread_mutex_lock(&Q_mutex);
			topid = FIFOqueue->front();
			FIFOqueue->pop();
			sgx_thread_mutex_unlock(&Q_mutex);
			//将要移除的用户数据打包传到disk
			sgx_thread_mutex_lock(&GA_mutex);
			int acsize = GlobalacManagement->find(topid)->second->size() * 8;
			sgx_thread_mutex_unlock(&GA_mutex);
			earsedata = (sec*)malloc(sizeof(sec)+acsize);
			memset(earsedata,0, sizeof(sec) + acsize);
			sgx_thread_mutex_lock(&GC_mutex);
			earsedata->mc = GlobalCountManagement->find(topid)->second;
			sgx_mc_uuid_t tmpuuid = GlobalCountManagement->find(topid)->second;
			sgx_thread_mutex_unlock(&GC_mutex);
			GetUscount(&tmpuuid,&earsedata->mc_value);
			sgx_thread_mutex_lock(&GA_mutex);
			std::map<int, int> *tmpacmap = GlobalacManagement->find(topid)->second;
			sgx_thread_mutex_unlock(&GA_mutex);
			std::string *Smap = SerializeMap(tmpacmap);
			memcpy(earsedata->secret,(uint8_t*)Smap->c_str(), acsize);
			uint8_t *sealeardata = new uint8_t[560+sizeof(sec)+acsize];
			Sealdata((uint8_t*)earsedata,sizeof(sec)+acsize,sealeardata);
			free(earsedata);
			uint8_t sealearkey[SharedKey];
			sgx_thread_mutex_lock(&GK_mutex);
			uint8_t *tpkey = GlobalKeyManagement->find(topid)->second.sharekey;
			sgx_thread_mutex_unlock(&GK_mutex);
			Sealdata(tpkey,SGX_ECP256_KEY_SIZE,sealearkey);
			replaydata = (uint8_t*)malloc(SharedKey+580+acsize);
			memset(replaydata,0, SharedKey + 580 + acsize);
			memcpy(replaydata,sealearkey,SharedKey);
			memcpy(replaydata + SharedKey, sealeardata, 560 + sizeof(sec) + acsize);
			delete[] sealeardata;
			int srs = -1;
			UpdateshujutoServerdisk(&srs,ID, replaydata, SharedKey + 580 + acsize);
			if (srs != SGX_SUCCESS) {
				return -3;
			}
			sgx_thread_mutex_lock(&GK_mutex);
			GlobalKeyManagement->erase(topid);//从keymap中移除最先进来的用户key
			sgx_thread_mutex_unlock(&GK_mutex);
			sgx_thread_mutex_lock(&GC_mutex);
			GlobalCountManagement->erase(topid);//移除计数器
			sgx_thread_mutex_unlock(&GC_mutex);
			sgx_thread_mutex_lock(&GA_mutex);
			GlobalacManagement->erase(topid);//移除ac
			sgx_thread_mutex_unlock(&GA_mutex);
			sgx_thread_mutex_lock(&GK_mutex);
			GlobalKeyManagement->insert(pair<int, skey>(ID, tem));//将用户秘钥放入map
			sgx_thread_mutex_unlock(&GK_mutex);
			free(replaydata);
		}
		userac = (sec*)malloc(datalen - SharedKey - 560);
		memset(userac,0, datalen - SharedKey - 560);
		uint32_t acdatalen = datalen - SharedKey - 560;
		uint8_t *tampuserac=new uint8_t[datalen - SharedKey - 560];

		uint8_t *Enuseracdata = new uint8_t[datalen-SharedKey];
		memset(Enuseracdata,0, datalen - SharedKey);
		memcpy(Enuseracdata,userdata+592, datalen - SharedKey);
		re = UnSealdata(Enuseracdata, tampuserac, &acdatalen);//获取用户count与用户权限表
		memcpy(userac,tampuserac, acdatalen);
		delete[]tampuserac;
		delete[]Enuseracdata;

		if (re != SGX_SUCCESS) {
			return re;
		}
		uint8_t *pldata;
		pldata = (uint8_t*)malloc(len);
		
		AES_Decryptcbc(tem.sharekey, SGX_ECP256_KEY_SIZE, data, pldata, len);//解密用户端传来的请求
		memcpy(&temdata.ID, pldata, sizeof(int));
		memcpy(&temdata.Scount, pldata + sizeof(int), sizeof(int));
		memcpy(&temdata.dataid, pldata + 2 * sizeof(int), sizeof(int));
		memcpy(&temdata.ac, pldata + 3 * sizeof(int), sizeof(int));
		delete pldata;
		uint32_t mc_value = 0;
		re = GetUscount(&userac->mc, &mc_value);
		//printint(mc_value);
		sgx_thread_mutex_lock(&GC_mutex);
		GlobalCountManagement->insert(pair<int, sgx_mc_uuid_t>(ID, userac->mc));//将用户计数器ID放入map
		sgx_thread_mutex_unlock(&GC_mutex);
		if (re != SGX_SUCCESS || mc_value != temdata.Scount) {
			re = -2;
			return re;
		}
		//将用户权限反序列化到map中
		map<int, int> *useractable=new map<int,int>;
		int loca = 0;
		for (uint8_t *point = userac->secret; loca<((datalen - SharedKey - 580)/8); point += 8) {
			int a = 0, b = 0;
			memcpy(&a, point, sizeof(int));
			memcpy(&b, point + 4, sizeof(int));
			useractable->insert(pair<int, int>(a, b));
			loca++;
		}
		sgx_thread_mutex_lock(&GA_mutex);
		GlobalacManagement->insert(pair<int, map<int, int> *>(ID, useractable));//将用户权限表放入map
		sgx_thread_mutex_unlock(&GA_mutex);
		free(userac);
		free(userdata);
	}
	else
	{
		uint8_t *pldata;
		pldata = (uint8_t*)malloc(len);
		sgx_thread_mutex_lock(&GK_mutex);
		uint8_t *tamkey = GlobalKeyManagement->find(ID)->second.sharekey;
		sgx_thread_mutex_unlock(&GK_mutex);
		AES_Decryptcbc(tamkey, SGX_ECP256_KEY_SIZE, data, pldata, len);//解密用户端传来的请求
		memcpy(&temdata.ID, pldata, sizeof(int));
		memcpy(&temdata.Scount, pldata + sizeof(int), sizeof(int));
		memcpy(&temdata.dataid, pldata + 2 * sizeof(int), sizeof(int));
		memcpy(&temdata.ac, pldata + 3 * sizeof(int), sizeof(int));
		delete pldata;
	}
	//查询该用户是否对该数据拥有操作权限
	sgx_thread_mutex_lock(&GA_mutex);
	int tmac = GlobalacManagement->find(ID)->second->find(temdata.dataid)->second;
	sgx_thread_mutex_unlock(&GA_mutex);
	if (tmac >= temdata.ac) {
		
		sgx_thread_mutex_lock(&GC_mutex);
		UpdateUscount(&GlobalCountManagement->find(ID)->second);
		sgx_thread_mutex_unlock(&GC_mutex);
		Tofileenclave tamp;
		tamp.ac = temdata.ac;
		tamp.dataid = temdata.dataid;
		sgx_thread_mutex_lock(&GK_mutex);
		uint8_t *tmpkey = GlobalKeyManagement->find(ID)->second.sharekey;
		sgx_thread_mutex_unlock(&GK_mutex);
		memcpy(tamp.userkey.s,tmpkey ,SGX_ECP256_KEY_SIZE);
		size_t Tologicalendatalen = getEncryptdatalen(sizeof(Tofileenclave));
		uint8_t *Endata2enclave = new uint8_t[Tologicalendatalen];
		uint8_t *addlendata;
		addlendata = (uint8_t*)malloc(Tologicalendatalen);
		memset(addlendata,0,Tologicalendatalen);
		memcpy(addlendata,&tamp,sizeof(Tofileenclave));
		re=AES_Encryptcbc(dh_aek, sizeof(sgx_aes_ctr_128bit_key_t), addlendata, Tologicalendatalen, Endata2enclave);
		free(addlendata);
		/*uint8_t usershuju[1024];
		memset(usershuju,0,1024);
		Encryptusershuju((int*)&re,temdata.dataid, usershuju, 1024);*/
		memcpy(Response,Endata2enclave,Tologicalendatalen);
		//Getuserfilefromenclave2(&re,enclave2_id,Endata2enclave,Tologicalendatalen);
		delete[] Endata2enclave;
		//re=AES_Encryptcbc(GlobalKeyManagement->find(ID)->second.sharekey,SGX_ECP256_KEY_SIZE,usershuju,sizeof(usershuju),Enuserdata);
		
		return re;
	}
	else
	{
		return -1;
	}
}

