#include "Logical_enclave_t.h"
#include <string>
#include <map>
#include <queue>
#include "sgx_tae_service.h"
#include "sgx_tseal.h"
#include "ipp/ippcp.h"
#include "sgx_trts.h"
#include "sgx_thread.h"
#include <atomic>
#define ENFILELEN 1652
#define MSLEN 16
sgx_key_128bit_t dh_aek;   // Session key
sgx_dh_session_t sgx_dh_session;
//初始化BN
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
//初始化一个随机数生成器
IppsPRNGState* newPRNG(void)
{
	int ctxSize;
	ippsPRNGGetSize(&ctxSize);
	IppsPRNGState* pCtx = (IppsPRNGState*)(new Ipp8u[ctxSize]);
	ippsPRNGInit(160, pCtx);
	return pCtx;
}
//按位进行异或运算
void XORcompute(uint8_t *a, uint8_t *b, uint8_t *re, size_t len) {
	for (int i = 0; i < len; i++) {
		re[i] = a[i] ^ b[i];
	}
}
//使用AONT优化aes_cbc加密算法,计算出block
uint8_t* AES_EnIntegrateAONT_CBC(uint8_t *plaintext, size_t plaintextlen,uint8_t *randkey) {
	
	uint8_t *replaintext;//m
	uint8_t *tampreplaintext;//m'
	size_t repsize = plaintextlen;//按照16字节整数倍补全后的数据长度
	//补全数据为16的整数倍
	if (plaintextlen % 16 != 0)
	{
		repsize = plaintextlen + (16 - (plaintextlen % 16));
		replaintext = new uint8_t[repsize];
		tampreplaintext = new uint8_t[repsize];
		memset(tampreplaintext, 0, repsize);
		memset(replaintext, 0, repsize);
		memcpy(replaintext, plaintext, plaintextlen);
	}
	else
	{
		replaintext = new uint8_t[repsize];
		tampreplaintext = new uint8_t[repsize];
		memset(replaintext, 0, repsize);
		memset(tampreplaintext, 0, repsize);
		memcpy(replaintext, plaintext, plaintextlen);
	}
	int size = 0;
	IppStatus re = ippStsNoErr;
	ippsAESGetSize(&size);
	IppsAESSpec *pCtx;
	pCtx = (IppsAESSpec *)malloc(size);
	memset(pCtx, 0, size);
	re = ippsAESInit(randkey, 16, pCtx, size);
	//Ek'(i)
	for (int i = 0; i < (repsize / 16); i++) {
		uint8_t tamp[16];
		memset(tamp, 0, sizeof(tamp));
		memcpy(tamp, &i, sizeof(int));
		ippsAESEncryptECB(tamp,tampreplaintext+(16*i),16,pCtx);
	}
	//mi与Ek'(i)异或运算,计算m'
	for (int i = 0; i < (repsize / 16); i++) {
		XORcompute(replaintext + (16 * i), tampreplaintext + (16 * i), tampreplaintext + (16 * i), 16);
	}
	ippsAESInit(0, 16, pCtx, size);
	free(pCtx);
	delete[] replaintext;
	return tampreplaintext;
}
//AONT计算ms’
void CalculateMS(uint8_t *Blockfile,size_t blocklen,uint8_t *randkey, uint8_t *userkey,size_t keylen,uint8_t *ms) {
	int size = 0;
	IppStatus re = ippStsNoErr;
	ippsAESGetSize(&size);
	IppsAESSpec *pCtx;
	pCtx = (IppsAESSpec *)malloc(size);
	memset(pCtx, 0, size);
	re = ippsAESInit(userkey, keylen, pCtx, size);
	uint8_t *h = new uint8_t[blocklen];
	for (int i = 0; i < blocklen/16; i++) {
		uint8_t tamp[16];
		memset(tamp, 0, sizeof(tamp));
		memcpy(tamp, &i, sizeof(int));
		XORcompute(Blockfile + (16 * i), tamp, h + (16 * i), 16);
		ippsAESEncryptECB(h + (16 * i), h + (16 * i), 16, pCtx);
	}
	//计算ms'
	memcpy(ms, randkey, 16);
	for (int i = 0; i < blocklen/16; i++)
	{
		XORcompute(h + (16 * i), ms, ms, 16);
	}
	ippsAESInit(0, keylen, pCtx, size);
	free(pCtx);
	delete[] h;
}


//uerfile数据结构
typedef struct userfile {
	sgx_mc_uuid_t mc;
	uint32_t mc_value;
	uint8_t tampkey[16];
	uint8_t hash[32];
}uf;
typedef struct msfile {
	uint8_t file[1024];
}mf;

uint32_t session_request(sgx_enclave_id_t src_enclave_id, sgx_dh_msg1_t *dh_msg1, uint32_t *session_id)
{


	sgx_status_t status = SGX_SUCCESS;


	//Intialize the session as a session responder
	status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
	if (SGX_SUCCESS != status)
	{
		return status;
	}

	//get a new SessionID
	*session_id = 1;

	//Generate Message1 that will be returned to Source Enclave
	status = sgx_dh_responder_gen_msg1((sgx_dh_msg1_t*)dh_msg1, &sgx_dh_session);
	return status;
}
uint32_t exchange_report(sgx_enclave_id_t src_enclave_id, sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, uint32_t session_id)
{
	sgx_dh_session_enclave_identity_t initiator_identity;
	uint32_t rs = 0;
	memset(&dh_aek, 0, sizeof(sgx_key_128bit_t));
	do
	{
		dh_msg3->msg3_body.additional_prop_length = 0;
		//Process message 2 from source enclave and obtain message 3
		sgx_status_t se_ret = sgx_dh_responder_proc_msg2(dh_msg2, dh_msg3, &sgx_dh_session, &dh_aek, &initiator_identity);
		if (SGX_SUCCESS != se_ret)
		{
			rs = -1;
			break;
		}
		
	} while (0);
	disp(dh_aek, sizeof(sgx_aes_ctr_128bit_key_t));
	return rs;
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
std::map<int,uf> *userfile = new std::map<int,uf>;
std::queue<int> *FIFOqueue = new std::queue<int>;//用于保存FIFO的顺序，目前设置缓存为10000个文件
std::map<int, int> *wfilelock = new std::map<int, int>;//用于保存锁，如果是写请求就将对应文件加锁。
std::map<int, mf> *usermsfile = new std::map<int,mf>;
sgx_thread_mutex_t lock = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t wf_mutex = SGX_THREAD_MUTEX_INITIALIZER;//文件写锁
//sgx_thread_cond_t wc_cond = SGX_THREAD_COND_INITIALIZER;//条件锁
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
//给用户的文件解锁
uint32_t Deblocking(int tdataid) 
{
	sgx_thread_mutex_lock(&wf_mutex);
	wfilelock->erase(wfilelock->find(tdataid));
	sgx_thread_mutex_unlock(&wf_mutex);
	uint32_t re = 1;
	if (wfilelock->find(tdataid) == wfilelock->end()) re = 0;
	return re;
}
//get encrypt size 为了使要加密的数据长度为16的倍数，所以需要进行数据填充
uint32_t getEncryptdatalen(int len) {
	uint32_t size = 0;
	if (len % 16 == 0) {
		size = len;
	}
	else {
		size = len + (16 - (len % 16));
	}
	return size;
}
uint32_t FindfileTOuser(uint8_t* data, size_t len, uint8_t *Enuserdata, size_t len2);
uint32_t GetdatatoClient(int ID, uint8_t* data, size_t len, uint8_t* Enuserdata, size_t Enlen) {
	UserRequest tampR;
	Tofileenclave tampF;
	int Responsesize = getEncryptdatalen(sizeof(tampF));
	int Requestsize = getEncryptdatalen(sizeof(tampR));
	uint8_t *Entampf = new uint8_t[Responsesize];
	uint8_t *EnR=new uint8_t[Requestsize];
	uint32_t re = 0;
	tampR.ID = ID;
	tampR.len = len;
	memcpy(tampR.data,data,len);
	memset(EnR,0,Requestsize);
	memcpy(EnR,(uint8_t*)&tampR,sizeof(tampR));
	re = AES_Encryptcbc(dh_aek,sizeof(sgx_aes_ctr_128bit_key_t),EnR,Requestsize,EnR);
	TransferRequestToL(&re, EnR, Requestsize,Entampf,Responsesize);
	delete[] EnR;
	if (re == 0) {
		re=FindfileTOuser(Entampf,Responsesize,Enuserdata,Enlen);
	}
	delete[] Entampf;
	return re;
}
//增加计数器的值
uint32_t UpdateCount(sgx_mc_uuid_t *mc,uint32_t *tmc_value) {
	int busy_retry_times = 2;
	sgx_status_t ret = SGX_SUCCESS;
	do {
		ret = sgx_create_pse_session();
	} while (ret == SGX_ERROR_BUSY && busy_retry_times--);
	if (ret != SGX_SUCCESS) {
		return ret;
	}
	uint32_t mc_value = 0;
	ret = sgx_read_monotonic_counter(mc, &mc_value);
	if (mc_value != *tmc_value)
	{
		ret = SGX_ERROR_FILE_BAD_STATUS;
		return ret;
	}
	ret = sgx_increment_monotonic_counter(mc, tmc_value);
	if (ret != SGX_SUCCESS)
	{
		return ret;
	}
	ret = sgx_close_pse_session();
	return ret;
}
uint32_t FindfileTOuser(uint8_t* data, size_t len, uint8_t *Enuserdata, size_t len2) {
	int re = 0;
	uf useruf;
	Tofileenclave tamp;
	sgx_status_t ret = SGX_SUCCESS;
	
	uint8_t *getendatafromenclave1 = new uint8_t[len];
	re = AES_Decryptcbc(dh_aek, sizeof(sgx_aes_ctr_128bit_key_t),data,getendatafromenclave1,len);
	if (re != 0) return re;
	memcpy(&tamp, getendatafromenclave1, sizeof(Tofileenclave));
	delete[] getendatafromenclave1;
	//判断用户是否为写请求，若为写则加锁。
	sgx_thread_mutex_lock(&wf_mutex);
	int isW=wfilelock->count(tamp.dataid);
	if (isW == 0) {
		if (tamp.ac == 2) {
			wfilelock->insert(std::pair<int,int>(tamp.dataid,1));
		}
	}
	else
	{
		sgx_thread_mutex_unlock(&wf_mutex);
		return -3;
	}
	sgx_thread_mutex_unlock(&wf_mutex);
	if (userfile->find(tamp.dataid) == userfile->end()) {
		uint8_t *enfile = new uint8_t[ENFILELEN];
		Encryptusershuju(&re, tamp.dataid, enfile, ENFILELEN);
		uint8_t ufdats[628];
		memcpy(ufdats,enfile,628);
		if (re != 0) return re;
		uint32_t datalen = sizeof(uf);
		//计算hash以及ms'
		ret = sgx_unseal_data((sgx_sealed_data_t*)ufdats,NULL,0,(uint8_t*)&useruf,&datalen);
		
		if (ret != SGX_SUCCESS) {
			return -1;
		}
		sgx_sha256_hash_t dhash;
		sgx_sha256_msg(enfile+628, 1024, &dhash);
		if (memcmp(dhash,useruf.hash,SGX_SHA256_HASH_SIZE)!=0) {
			return -1;
		}
		//计数器++
		re=UpdateCount(&useruf.mc,&useruf.mc_value);
		if (re != 0) return re;
		//开线程异步写回disk
		//Updatefileindisk(&re, tamp.dataid,(uint8_t*)useruf,ENFILELEN);
		//int tmpsize = FIFOqueue->size();
		mf t;
		memcpy(t.file, enfile + 628, sizeof(mf));
		sgx_thread_mutex_lock(&lock);
		if (FIFOqueue->size() <= 10000) {		
			FIFOqueue->push(tamp.dataid);
			userfile->insert(std::pair<int, uf>(tamp.dataid, useruf));
			usermsfile->insert(std::pair<int,mf>(tamp.dataid,t));
		}
		else
		{	
			int topid = FIFOqueue->front();		
			uint8_t updatefile[ENFILELEN];		
			//memcpy(updatefile,&userfile->find(topid)->second,sizeof(uf));
			uint8_t Enuf[628];
			sgx_seal_data(0, NULL, sizeof(uf), (uint8_t*)&userfile->find(topid)->second, 628, (sgx_sealed_data_t*)Enuf);
			memcpy(updatefile,Enuf,sizeof(Enuf));
			memcpy(updatefile+628,usermsfile->find(topid)->second.file,sizeof(mf));
			int re = 0;
			Updatefileindisk(&re,topid,updatefile,ENFILELEN);
			if (re == 0) {
				FIFOqueue->pop();	
				userfile->erase(topid);
				userfile->insert(std::pair<int, uf>(tamp.dataid, useruf));
				usermsfile->insert(std::pair<int, mf>(tamp.dataid, t));
			}
			else
			{
				return -1;
			}
		}
		sgx_thread_mutex_unlock(&lock);
		uint8_t ms[16];
		CalculateMS(usermsfile->find(tamp.dataid)->second.file,1024,useruf.tampkey,tamp.userkey.s,sizeof(tamp.userkey.s),ms);
		memcpy(Enuserdata,t.file,sizeof(mf));
		memcpy(Enuserdata+sizeof(mf),ms,sizeof(ms));
		//re = AES_Encryptcbc(tamp.userkey.s, SGX_ECP256_KEY_SIZE, useruf->secret, 1024, Enuserdata);
	}
	else 
	{
		//什么时候往disk写是个问题，目前都在map中更新。
		UpdateCount(&userfile->find(tamp.dataid)->second.mc,&userfile->find(tamp.dataid)->second.mc_value);
		//开线程异步写回disk
		//Updatefileindisk(&re, tamp.dataid, (uint8_t*)userfile->find(tamp.dataid)->second, ENFILELEN);
		uint8_t ms[16];
		CalculateMS(usermsfile->find(tamp.dataid)->second.file, 1024, useruf.tampkey, tamp.userkey.s, sizeof(tamp.userkey.s), ms);
		memcpy(Enuserdata, usermsfile->find(tamp.dataid)->second.file, sizeof(mf));
		memcpy(Enuserdata + sizeof(mf), ms, sizeof(ms));
		//re = AES_Encryptcbc(tamp.userkey.s, SGX_ECP256_KEY_SIZE, userfile->find(tamp.dataid)->second->secret, 1024, Enuserdata);
	}
	return re;
}
//用户file加密并绑定计数器
uint32_t Encryptuserfile(uint8_t* file, size_t len,uint8_t *Entemfile,size_t outlen) {
	sgx_status_t ret = SGX_SUCCESS;
	uf temuf;
	memset(&temuf, 0, sizeof(uf) );
	int busy_retry_times = 2;
	uint32_t size = sgx_calc_sealed_data_size(0, sizeof(uf));
	do {
		ret = sgx_create_pse_session();
	} while (ret == SGX_ERROR_BUSY && busy_retry_times--);
	if (ret != SGX_SUCCESS) {
		return -1;
	}
	ret = sgx_create_monotonic_counter(&temuf.mc, &temuf.mc_value);
	if (ret != SGX_SUCCESS)
	{
		return -1;
	}
	uint8_t *tampdata;
	IppsBigNumState *randKey;
	IppsPRNGState *prng = newPRNG();
	randKey = newBN(4, 0);
	ippsPRNGenRDRAND_BN(randKey, 128, prng);//随机生成一个128位的key
	uint8_t publickey[16];
	ippsGetOctString_BN(publickey, 16, randKey);//将大数转化成unsigned char
	delete[](Ipp8u*)randKey;
	delete[](Ipp8u*)prng;//清内存
	memcpy(temuf.tampkey,publickey,sizeof(publickey));
	tampdata=AES_EnIntegrateAONT_CBC(file,len,publickey);
	//计算一层加密明文的hash
	sgx_sha256_hash_t dhash;
	sgx_sha256_msg(tampdata, len, &dhash);
	memcpy(temuf.hash,dhash,SGX_SHA256_HASH_SIZE);
	uint8_t *Enmsdata=new uint8_t[size];
	ret = sgx_seal_data(0, NULL, sizeof(temuf), (uint8_t*)&temuf, size, (sgx_sealed_data_t*)Enmsdata);
	memcpy(Entemfile,Enmsdata,size);
	memcpy(Entemfile+size,tampdata,len);
	memset(tampdata, 0, len );
	memset(Enmsdata,0,size);
	delete[] Enmsdata;
	delete[] tampdata;
	ret = sgx_close_pse_session();
	if (ret != SGX_SUCCESS) {
		return -1;
	}
	return ret;
}

//程序结束时将map内所有数据写回disk  改
uint32_t WritebackdatatoDisk() {
	sgx_thread_mutex_lock(&lock);
	uint32_t re = 0;
	std::map<int,uf>::iterator tamuf;
	uint8_t updata[ENFILELEN];
	for (tamuf = userfile->begin(); tamuf != userfile->end(); tamuf++) {
		sgx_seal_data(0,NULL,sizeof(uf),(uint8_t*)&tamuf->second,628,(sgx_sealed_data_t*)updata);
		memcpy(updata+628,usermsfile->find(tamuf->first)->second.file,sizeof(usermsfile->find(tamuf->first)->second.file));
		Updatefileindisk((int*)&re, tamuf->first, updata, ENFILELEN);
		memset(updata,0,ENFILELEN);
	}
	sgx_thread_mutex_unlock(&lock);
	return re;
}