#include "ORAM_envalve_u.h"
#include "Logical_enclave_u.h"
#include <Winsock2.h>
#include <tchar.h>
#include <cstdio>
#include <thread>
#include <fstream>
#include <string>
#include <atomic>
#include "ipp/ippcp.h"
#include <openssl\err.h>
#include <openssl\ssl.h>
#include <openssl\ec.h>
#include <openssl\aes.h>
#include "sgx_eid.h"
#include "sgx_urts.h"
#include "sgx_uae_service.h"


#define ENCLAVE_FILE _T("ORAM_envalve.signed.dll")
#define ENCLAVE_LOGICFILE _T("Logical_enclave.signed.dll")
#define ECDH_SIZE 33 
#define MSG_LEN 128
#define MAXBUF 1024
#define ENFILELEN 1604
#define P2SDATA 44
#define SaveDatasize 580
#define SharedKey 592
#define CA_FILE			"C:\\CA\\cacert.pem"
#define SERVER_CERT     "C:\\Server\\cert.pem"
#define SERVER_KEY      "C:\\Server\\key.pem"

#pragma comment(lib,"ws2_32.lib")
sgx_enclave_id_t   eid;
sgx_enclave_id_t   Leid;
//初始化文件
int Initfile() {
	std::fstream fs;
	fs.open("E:\\Server_file\\0.txt",std::ios::in);
	if (fs) {
		fs.close();
		return -1;
	}
	else
	{
		fs.close();
	}
	for (int i = 0; i < 3; i++) {
		uint32_t re = 0;
		std::string url = "E:\\Clientfile\\" + std::to_string(i) + ".txt";	
		fs.open(url, std::ios::in | std::ios::binary);
		uint8_t *file = new uint8_t[1024];
		memset(file,0,1024);
		fs.read((char*)file, MAXBUF);
		uint8_t Enfilelen[ENFILELEN];
		fs.close();
		Encryptuserfile(Leid, &re, file, MAXBUF, Enfilelen, ENFILELEN);
		delete[] file;
		std::string url2 = "E:\\Server_file\\" + std::to_string(i) + ".txt";
		fs.open(url2, std::ios::app | std::ios::out | std::ios::binary);
		fs.write((char*)Enfilelen, ENFILELEN);
		fs.flush();
		fs.close();
	}
}
//local attestation
void disp(uint8_t *pbuf, size_t len)

{
	putchar('\n');
	int i = 0;

	if (pbuf != NULL && len > 0) {

		for (i = 0; i<len; i++)

			printf("%02x ", *((unsigned char *)pbuf + i));

		putchar('\n');

	}

	putchar('\n');

}
//更新本地用户文件
int Updatefileindisk(int dataid, uint8_t *file, size_t len)
{
	std::fstream fs;
	std::string url = "E:\\Server_file\\" + std::to_string(dataid) + ".txt";
	fs.open(url,std::ios::trunc|std::ios::out|std::ios::binary);
	fs.write((char*)file,len);
	fs.flush();
	fs.close();
	return SGX_SUCCESS;
}
//show cert
void ShowCerts(SSL * ssl)
{
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl);
	if (cert != NULL) {
		long re = SSL_get_verify_result(ssl);
		if (re == 0) {
			printf("\n代理端证书正确\n");
			printf("数字证书信息:\n");
			line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
			printf("证书: %s\n", line);
			memset(line, 0, strlen(line));
			line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
			printf("颁发者: %s\n", line);
			memset(line, 0, strlen(line));

			X509_free(cert);
		}
	}
	else {
		printf("无证书信息！\n");
	}
}
void printhash(uint8_t* dhash, size_t len) {
	int i = 0;
	char buf[65] = { 0 };
	char tmp[3] = { 0 };
	for (i = 0; i < 32; i++)
	{
		sprintf(tmp, "%02X", dhash[i]);
		strcat(buf, tmp);
	}

	printf("\nHash is:%s\n", buf);
}

//Local Attestation
uint32_t session_request_lo (sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id)
{
	uint32_t status = 0;
	sgx_status_t ret = SGX_SUCCESS;

	ret = session_request(dest_enclave_id, &status, src_enclave_id, dh_msg1, session_id);
	if (ret != 0) {
		printf("session_report_ocall error!!!");
	}
	return ret;
}
uint32_t exchange_report_lo(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, uint32_t session_id)
{
	uint32_t status = 0;
	sgx_status_t ret = SGX_SUCCESS;

	ret = exchange_report(dest_enclave_id, &status, src_enclave_id, dh_msg2, dh_msg3, session_id);
	if (ret != 0) {
		printf("exchange_report_ocall error!!!");
	}
	return ret;
}
//传输数据到enclave2
uint32_t Getuserfilefromenclave2(sgx_enclave_id_t dest_enclave_id,uint8_t* data, size_t len, uint8_t *Enuserdata, size_t len2)
{
	uint32_t status = 0;
	sgx_status_t ret = SGX_SUCCESS;

	ret = FindfileTOuser(dest_enclave_id, &status, data,len,Enuserdata,len2);
	if (ret != 0) {
		printf("find file error!!!");
	}
	return ret;
}

int aes_encrypt(char* in, unsigned char* key, char* out)//, int olen)可能会设置buf长度
{
	if (!in || !key || !out) return 0;
	unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
	for (int i = 0; i<AES_BLOCK_SIZE; ++i)//iv一般设置为全0,可以设置其他，但是加密解密要一样就行
		iv[i] = 0;
	AES_KEY aes;
	if (AES_set_encrypt_key(key, AES_BLOCK_SIZE * 16, &aes) < 0)
	{
		return 0;
	}
	int len = strlen(in);//这里的长度是char*in的长度，但是如果in中间包含'\0'字符的话

						 //那么就只会加密前面'\0'前面的一段，所以，这个len可以作为参数传进来，记录in的长度				
	AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_ENCRYPT);
	return 1;
}
int aes_decrypt(char* in, unsigned char* key, char* out)
{
	if (!in || !key || !out) return 0;
	unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
	for (int i = 0; i<AES_BLOCK_SIZE; ++i)//iv一般设置为全0,可以设置其他，但是加密解密要一样就行
		iv[i] = 0;
	AES_KEY aes;
	if (AES_set_decrypt_key(key, AES_BLOCK_SIZE * 16, &aes) < 0)
	{
		return 0;
	}
	int len = strlen(in);
	AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_DECRYPT);
	return 1;
}
//OCALL getdatalen
size_t Getdatalen(int ID) {
	std::string url = "E:\\Server\\" + std::to_string(ID) + ".txt";
	std::fstream fs;
	fs.open(url,std::ios::in);
	std::streamoff end, start,len;
	start = fs.tellg();
	fs.seekg(0, std::ios::end);
	end = fs.tellg();
	len = end - start;
	fs.close();
	return len;
}
//OCALL 将用户数据传回enclave
void Getuserdatafromdisk(int ID, uint8_t *userdata, size_t len) {
	std::string url = "E:\\Server\\" + std::to_string(ID) + ".txt";
	std::fstream fs;
	fs.open(url, std::ios::in|std::ios::binary);
	fs.read((char*)userdata,len);
	fs.flush();
	fs.close();
}
//Ocall给enclave提供vcount
void GetVcount(uint8_t* data, size_t len)
{
	std::fstream fs;
	fs.open("E:\\Server\\Vcount.txt",std::ios::in|std::ios::binary);
	fs.read((char*)data,len);
	fs.flush();
	fs.close();
}
//Ocall 将用户请求的数据发送回enclave进行加密
int Encryptusershuju(int dataid, uint8_t* usershuju, size_t len) {
	int re = 1;
	std::fstream fs;
	std::string url = "E:\\Server_file\\" + std::to_string(dataid) + ".txt";
	fs.open(url, std::ios::in|std::ios::binary);
	if (fs) {
		fs.read((char*)usershuju, len);
		//printf("\nserver端数据：%s\n",(char*)usershuju);
		re = 0;
	}
	fs.flush();
	fs.close();
	return re;
}
//Ocall 将溢出的用户数据存到本地
int UpdateshujutoServerdisk(int ID, uint8_t* data, size_t len) {
	std::fstream fs;
	std::string url = "E:\\Server\\" + std::to_string(ID) + ".txt";
	fs.open(url,std::ios::trunc|std::ios::binary);
	fs.write((char*)data,len);
	fs.flush();
	fs.close();
	return SGX_SUCCESS;
}
int getcon(int port)
{	
	
	SOCKET sockServer;
	SOCKADDR_IN addrServer;
	
	sockServer = socket(AF_INET, SOCK_STREAM, 0);
	addrServer.sin_addr.S_un.S_addr = htonl(INADDR_ANY);//INADDR_ANY表示任何IP
	addrServer.sin_family = AF_INET;
	addrServer.sin_port = htons(port);//绑定端口
	bind(sockServer, (SOCKADDR*)&addrServer, sizeof(SOCKADDR));
	//Listen监听端
	listen(sockServer, SOMAXCONN);
	printf("服务器已启动:\n监听%d端口...\n",port);
	return sockServer;
}

int InsertsharekeybyID(int id,uint8_t* data, size_t len) {
	std::fstream fs;
	std::string url = "E:\\Server\\" + std::to_string(id) + ".txt";
	fs.open(url,std::ios::in|std::ios::binary);
	int re = -1;
	if (fs) {
		std::streamoff start;
		std::streamoff end;
		start = fs.tellg();
		end = fs.seekg(0, std::ios::end).tellg();
		fs.seekg(start);
		uint8_t *buf = new uint8_t[end-start+len];
		memcpy(buf,data,len);
		uint8_t *src = new uint8_t[end-start];
		fs.read((char*)src,end-start);
		memcpy(buf+len, src, end - start);
		fs.close();

		fs.open(url,std::ios::trunc|std::ios::out|std::ios::binary);
		fs.write((char*)buf, end - start + len);
		fs.flush();
		fs.close();
		delete src;
		delete buf;
		re = SGX_SUCCESS;
	}
	else printf("can not find user's actable");
	return re;
}

//处理来自客户端的请求
void DealClientRequest(SOCKET sockClient,sgx_enclave_id_t eid) {	
	SSL *ssl;
	SSL_CTX *ctx;
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(SSLv3_server_method());
	//加载服务端证书
	if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) != 1) {
		SSL_CTX_free(ctx);
		printf("Failed to load client certificate from %s", SERVER_CERT);
	}
	/*加载服务端私钥*/
	if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) != 1) {
		SSL_CTX_free(ctx);
		printf("Failed to load client private key from %s", SERVER_KEY);
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sockClient);
	
	sgx_status_t       ret = SGX_SUCCESS;
	sgx_ps_cap_t ps_cap;
	memset(&ps_cap, 0, sizeof(sgx_ps_cap_t));
	ret = sgx_get_ps_cap(&ps_cap);
	do {
		if (SSL_accept(ssl) == -1)
		{
			perror("accept");
			break;
		}
		int error = 0;
		int type = 0;
		//接收并打印客户端数据
		SSL_read(ssl,&type, sizeof(int));
		int ID = 0;
		SSL_read(ssl,&ID,sizeof(int));
		std::fstream fs;
		fs.open("E:\\Server\\"+std::to_string(ID)+".txt",std::ios::in);
		if (!fs) {
			fs.close();
			error = -1;
		}
		SSL_write(ssl, &error, sizeof(int));
		if (error == -1) break;
		if (type == 0)
		{
			printf("new Client connect");
			//send(sockClient,(char*)&curvenum,sizeof(int),0);
			if (ret == SGX_SUCCESS)
			{
				int re = 0;
				uint8_t px[32];
				uint8_t py[32];
				uint8_t Cpx[32];
				uint8_t Cpy[32];
				uint8_t prk[32];
				GetServerpublickey(eid,&re,px,py,sizeof(px));
				if (re == SGX_SUCCESS) {
					
					SSL_read(ssl, Cpx, sizeof(px));
					SSL_read(ssl, Cpy, sizeof(py));
					SSL_write(ssl, px, sizeof(px));
					SSL_write(ssl, py, sizeof(py));		
					ComputeSharekey(eid,&re,Cpx,Cpy,sizeof(px));
					uint8_t sendata[16];
					gettestdata(eid,&re,sendata,sizeof(sendata));
					if (re == SGX_SUCCESS) {
						SSL_write(ssl,sendata,sizeof(sendata));
						SSL_read(ssl, &re, sizeof(int));
						if (re == SGX_SUCCESS) {
							uint8_t sealkey[592];
							Insertskey(eid,&re, sealkey,592);
							if (re == SGX_SUCCESS) {
								re=InsertsharekeybyID(ID,sealkey,592);
								if (re != SGX_SUCCESS) {
									break;
								}
							}
						}
					}
				}
				else break;
			}
		}
		uint8_t DataFromClient[16];
		SSL_read(ssl,DataFromClient,sizeof(DataFromClient));
		int result = 1;
		uint8_t Enuserdata[1024];
		memset(Enuserdata,0,1024);
		GetdatatoClient(eid,&result,ID,DataFromClient,sizeof(DataFromClient),Enuserdata,sizeof(Enuserdata));
		int ttt = 0;
		if (result == SGX_SUCCESS) {
			
			ttt=SSL_write(ssl, &result, sizeof(int));
			ttt=SSL_write(ssl,Enuserdata,sizeof(Enuserdata));
		}
		else
		{
			SSL_write(ssl,&result,sizeof(int));
		}
		memset(Enuserdata, 0, sizeof(Enuserdata));
	} while (0);
	//关闭socket、SSL
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	closesocket(sockClient);
	printf("断开与客户端的连接！！！");
}
//在enclave内生成计数器
int Createcounter(sgx_enclave_id_t eid) {
	uint8_t count[580];
	//sgx_enclave_id_t   eid;
	sgx_status_t       ret = SGX_SUCCESS;
	//sgx_launch_token_t token = { 0 };
	int updated = 0;
	//ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret == SGX_SUCCESS)
	{
		sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;
		sgx_ps_cap_t ps_cap;
		memset(&ps_cap, 0, sizeof(sgx_ps_cap_t));
		sgx_ret = sgx_get_ps_cap(&ps_cap);
		uint32_t eret = 0;
		//ttt(enclave_id,&eret,datalog,620);
		createcount(eid, &eret, count, 580);
		if (eret ==SGX_SUCCESS) {
			std::fstream fs;
			fs.open("E:\\Server\\Vcount.txt",std::ios::app|std::ios::binary);
			fs.write((char*)count,sizeof(count));
			fs.flush();
			fs.close();
			printf("\n创建Vcount成功\n");
			return 1;
		}
	}
	return 0;
}
//更新全局计数器Vcount
int UpdateCount(sgx_enclave_id_t eid) {
	uint8_t count[580];
	uint32_t eret = 0;
	std::fstream fs;
	fs.open("E:\\Server\\Vcount.txt", std::ios::trunc|std::ios::out | std::ios::binary);
	updatecount(eid, &eret, count, 580);
	if (eret == SGX_SUCCESS) {	
		fs.write((char*)count, sizeof(count));
		fs.flush();
		fs.close();
		printf("\n更新Vcount成功\n");
		return 1;
	}
	return 0;
}
/*接受来自代理服务器的请求*/
void getProxycon(sgx_enclave_id_t eid)
{
	SOCKET sockServer;
	SOCKET sockClient;
	SOCKADDR_IN addrClient;
	sockServer=getcon(6001);

	SSL_CTX *ctx;
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(SSLv3_server_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, 0);
	//SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
	/*加载CA FILE*/
	if (SSL_CTX_load_verify_locations(ctx, CA_FILE, 0) != 1) {
		SSL_CTX_free(ctx);
		printf("Failed to load CA file %s", CA_FILE);	
	}
	//加载服务端证书
	if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) != 1) {
		SSL_CTX_free(ctx);
		printf("Failed to load client certificate from %s", SERVER_KEY);
	}
	/*加载服务端私钥*/
	if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) != 1) {
		SSL_CTX_free(ctx);
		printf("Failed to load client private key from %s", SERVER_KEY);
	}
	int re = 0;
	int p2sre = 0;
	while (true)
	{
		SSL *ssl;
		int len = sizeof(SOCKADDR);
		sockClient = accept(sockServer, (SOCKADDR*)&addrClient, &len);//会阻塞进程，直到有客户端连接上来为止
		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, sockClient);
		if (SSL_accept(ssl) == -1)
		{
			perror("accept");
			closesocket(sockClient);
			continue;
		}
		else {
			printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
			ShowCerts(ssl);
		}
		printf("\n收到代理端的连接。。。。。\n");
		do {
			int type = 0;
			SSL_read(ssl,&type,sizeof(int));
			if (type == 0) //若代理端第一次连接则创建Vcount
			{
				if (!Createcounter(eid))
				{
					break;
				}
			}
			int datasize = 0;
			SSL_read(ssl, &datasize, sizeof(int));
			uint8_t *p2s;
			p2s = (uint8_t*)malloc(datasize + P2SDATA);
			SSL_read(ssl, p2s, P2SDATA + datasize);//获取代理端传来的用户权限表

			uint8_t *outdata = new uint8_t[20+datasize + 560];
			memset(outdata,0, 20 + datasize + 560);
			sgx_status_t       ret = SGX_SUCCESS;
			uint32_t id = 0;
			if (ret == SGX_SUCCESS)
			{
				
				
				ret = SGX_ERROR_UNEXPECTED;
				sgx_ps_cap_t ps_cap;
				memset(&ps_cap, 0, sizeof(sgx_ps_cap_t));
				ret = sgx_get_ps_cap(&ps_cap);
				size_t p2slen = P2SDATA + datasize;
				size_t outdatalen = datasize + SaveDatasize;
				DetectacData(eid, &id, p2s,p2slen, outdata,outdatalen );
				
				if (id != -1)
				{
 					std::fstream fs;
					std::string url = "E:\\Server\\" + std::to_string(id) + ".txt";
					fs.open(url, std::ios::in);
					if (!fs) {
						fs.close();
						fs.open(url, std::ios::app | std::ios::out| std::ios::binary );
						fs.write((char*)outdata, datasize + SaveDatasize);

					}
					else {
						fs.close();
						fs.open(url, std::ios::trunc|std::ios::out | std::ios::binary);
						fs.write((char*)outdata, datasize + SaveDatasize);

					}
					re = -1;
					re=UpdateCount(eid);
					fs.flush();
					fs.close();
				}
				else {
					re = -1;
				}
			}
			else re = -1;
			
			
		} while (0);
		SSL_write(ssl,&re,sizeof(int));//返回结果给代理端
	}
}
//接受来自客户端的请求
void getClientcon(sgx_enclave_id_t eid)
{
	
	SOCKET sockServer;
	SOCKET sockClient;
	SOCKADDR_IN addrClient;
	
	sockServer = getcon(6000);

	while (true) {

		int len = sizeof(SOCKADDR);
		sockClient = accept(sockServer, (SOCKADDR*)&addrClient, &len);//会阻塞进程，直到有客户端连接上来为止
		std::thread t(DealClientRequest, sockClient,eid);
		t.detach();
		printf("\n收到来自客户端的连接\n");
	}
}

//绑定计数器并加密用户文件到disk，暂定文件大小为1024kb
uint32_t Enfileindisk(std::string fileurl,int dataid) {
	std::fstream fs;
	fs.open(fileurl,std::ios::in|std::ios::binary);
	uint8_t *ENfile = new uint8_t[MAXBUF+580];
	uint8_t file[MAXBUF];
	fs.read((char*)file,MAXBUF);
	sgx_enclave_id_t fid;
	sgx_launch_token_t token = { 0 };
	int updated = 0;
	sgx_create_enclave(ENCLAVE_LOGICFILE,SGX_DEBUG_FLAG,&token,&updated,&fid,NULL);
	uint32_t re = 0;
	Encryptuserfile(fid,&re,file,MAXBUF,ENfile,MAXBUF+580);
	sgx_destroy_enclave(fid);
	fs.close();
	std::string url = "E:\\Server_file\\" + std::to_string(dataid) + ".txt";
	fs.open(url,std::ios::app|std::ios::out|std::ios::binary);
	fs.write((char*)ENfile,MAXBUF+560);
	fs.flush();
	fs.close();
	return updated;
}
//开启多线程，线程1用来监听6000端口，线程2用来监听6001端口
void StartServer()
{	
	sgx_status_t       ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	ret = sgx_create_enclave(ENCLAVE_LOGICFILE, SGX_DEBUG_FLAG, &token, &updated, &Leid, NULL);
	//初始化文件
	Initfile();
	uint32_t rs = 0;
	Buildsecurepath(eid, &rs, eid, Leid);
	std::thread t1(getClientcon,eid);
	std::thread t2(getProxycon,eid);
	t1.join();
	t2.join();
	sgx_destroy_enclave(eid);
	sgx_destroy_enclave(Leid);
	WSACleanup();
}

//基于sgx自带的ra-sample做一次远端认证，仅在用户第一次连接时将报告发送给用户
//typedef int(*sample_enroll)(int sp_credentials, sample_spid_t* spid,
//	int* authentication_token);
//sample_spid_t g_spid;

