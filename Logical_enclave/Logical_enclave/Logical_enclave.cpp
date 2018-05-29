#include "Logical_enclave_t.h"
#include <string>
#include <map>
#include <queue>
#include "ipp/ippcp.h"
#include "sgx_trts.h"
sgx_key_128bit_t dh_aek;   // Session key
sgx_dh_session_t sgx_dh_session;
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
std::map<int,uint8_t*> *userfile = new std::map<int,uint8_t*>;
std::queue<int> *FIFOqueue = new std::queue<int>;//用于保存FIFO的顺序，目前设置缓存为10000个文件
typedef struct Tofileenclave {
	int dataid;
	sgx_ec256_dh_shared_t userkey;
};
uint32_t FindfileTOuser(uint8_t* data, size_t len, uint8_t *Enuserdata, size_t len2) {
	int re = 0;
	Tofileenclave tamp;
	uint8_t *getendatafromenclave1 = new uint8_t[len];
	re = AES_Decryptcbc(dh_aek, sizeof(sgx_aes_ctr_128bit_key_t),data,getendatafromenclave1,len);
	if (re != 0) return re;
	memcpy(&tamp, getendatafromenclave1, sizeof(Tofileenclave));
	delete[] getendatafromenclave1;
	if (userfile->find(tamp.dataid) == userfile->end()) {
		uint8_t *usershuju = new uint8_t[1024];
		memset(usershuju, 0, 1024);
		Encryptusershuju(&re, tamp.dataid, usershuju, 1024);
		if (re != 0) return re;
		if (FIFOqueue->size() <= 10000) {
			FIFOqueue->push(tamp.dataid);
			userfile->insert(std::pair<int, uint8_t*>(tamp.dataid, usershuju));
		}
		else
		{
			int topid = FIFOqueue->front();
			FIFOqueue->pop();
			userfile->erase(topid);
			userfile->insert(std::pair<int, uint8_t*>(tamp.dataid, usershuju));
		}
		re = AES_Encryptcbc(tamp.userkey.s, SGX_ECP256_KEY_SIZE, usershuju, 1024, Enuserdata);
	}
	else 
	{
		re = AES_Encryptcbc(tamp.userkey.s, SGX_ECP256_KEY_SIZE, userfile->find(tamp.dataid)->second, 1024, Enuserdata);
	}
	return re;
}