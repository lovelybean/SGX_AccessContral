#include <Winsock2.h>
#include <cstdio>
#include <stdlib.h>
#include <fstream>
#include <string>
#include<map>
#include<queue>
#include<iostream>
#include <openssl\err.h>
#include <openssl\ssl.h>
#include <openssl\bio.h>
#include <openssl\ec.h>
#include <openssl\aes.h>
#define Serverpubkeylen 32
#define MSG_LEN 16
#define CA_FILE                "C:/CA/cacert.pem"
#pragma comment(lib,"ws2_32.lib")
void handleErrors()

{

	printf("Error occurred.\n");

}



void disp(const char *str, const void *pbuf, const int size)

{

	int i = 0;

	if (str != NULL) {

		printf("%s:\n", str);

	}

	if (pbuf != NULL && size > 0) {

		for (i = 0; i<size; i++)

			printf("%02x ", *((unsigned char *)pbuf + i));

		putchar('\n');

	}

	putchar('\n');

}

//获取pubkey
EC_KEY * genECDHpubkey(unsigned char *px,unsigned char *py)

{
	EC_KEY *ecdh = EC_KEY_new();
	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);//NID_X9_62_prime256v1

	//Generate Public
	EC_KEY_generate_key(ecdh);
	const EC_GROUP *ec_group = EC_KEY_get0_group(ecdh);
	const EC_POINT *pub = EC_KEY_get0_public_key(ecdh);
	const BIGNUM *pr=BN_new();
	/*EC_POINT *pub2=NULL;
	pub2 = EC_POINT_new(ec_group);*/
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	if (EC_POINT_get_affine_coordinates_GFp(ec_group, pub, x, y, NULL)) {		
			BN_bn2bin(x, px);
			BN_bn2bin(y, py);
	}
	return ecdh;
}
//接受服务端传来的ecc公钥，将其转化成openssl内公钥形式
EC_POINT* genServerpubkey(EC_KEY *ecdh,unsigned char *px, unsigned char *py) {
	const EC_GROUP *ec_group = EC_KEY_get0_group(ecdh);
	EC_POINT *pub;
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	BN_bin2bn(px,32,x);
	BN_bin2bn(py,32,y);
	pub = EC_POINT_new(ec_group);
	if (EC_POINT_set_affine_coordinates_GFp(ec_group, pub, x, y, NULL)) {
		if (EC_POINT_is_on_curve(ec_group, pub, NULL))
		{
			return pub;
			printf("zai quxian\n");
		}
		
	}
	return NULL;
}
//加解密函数
int aes_encrypt(char* in,size_t len, unsigned char* key, char* out)
{
	if (!in || !key || !out) return 0;
	unsigned char iv[AES_BLOCK_SIZE] = {'\xff','\xee','\xdd','\xcc','\xbb','\xaa','\x99','\x88','\x77','\x66','\x55','\x44','\x33','\x22','\x11','\x00' };//加密的初始化向量
	AES_KEY aes;
	if (AES_set_encrypt_key(key, AES_BLOCK_SIZE * 16, &aes) < 0)
	{
		return 0;
	}

	AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_ENCRYPT);
	return 1;
}

int aes_decrypt(char* in,size_t len, unsigned char* key, char* out)
{
	if (!in || !key || !out) return 0;
	unsigned char iv[AES_BLOCK_SIZE] = { '\xff','\xee','\xdd','\xcc','\xbb','\xaa','\x99','\x88','\x77','\x66','\x55','\x44','\x33','\x22','\x11','\x00' };
	AES_KEY aes;
	if (AES_set_decrypt_key(key, AES_BLOCK_SIZE * 16, &aes) < 0)
	{
		return 0;
	}
	AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_DECRYPT);
	return 1;
}

uint8_t *genECDHsharedkey(EC_KEY *ecdh, EC_POINT *Serverkey, size_t secret_len)

{
	int len;
	uint8_t *shared = (uint8_t *)malloc(32);
	//ComputeKey
	if (0 == (len = ECDH_compute_key(shared, secret_len,Serverkey, ecdh, NULL))) handleErrors();


	disp("shared", shared, secret_len);

	return shared;

}
//show cert
void ShowCerts(SSL * ssl)
{
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl);
	if (cert != NULL) {
		long re = SSL_get_verify_result(ssl);
		printf("数字证书信息:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("证书: %s\n", line);
		memset(line, 0, strlen(line));
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("颁发者: %s\n", line);
		memset(line, 0, strlen(line));
		X509_free(cert);
	}
	else {
		printf("无证书信息！\n");
	}
}
void CheckServerpem(X509 *cert, X509 *cacert)
{
	int ret;
	X509_STORE *store;
	X509_STORE_CTX *ctx;

	store = X509_STORE_new();
	X509_STORE_add_cert(store, cacert);

	ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(ctx, store, cert, NULL);

	ret = X509_verify_cert(ctx);

}

uint8_t dh_key[32];
int initclient = 0;
int Scount = 0;
typedef struct requestheader {
	int ID;
	int Scount;
	int dataid;
	int ac;
}rh;
uint8_t *realdata = new uint8_t[1024];
//用户获取数据
uint8_t* GetDatafromServer(int ID,int dataid,int ac) {
	rh UsertoServer;
	//char *errormessage;
	SSL_CTX *ctx;
	SSL *ssl;
	WSADATA wsaData;
	SOCKET sockClient;//客户端Socket
	SOCKADDR_IN addrServer;//服务端地址
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	//新建客户端socket
	sockClient = socket(AF_INET, SOCK_STREAM, 0);

	/*SSL初始化*/
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(SSLv3_client_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL);
	//定义要连接的服务端地址
	addrServer.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	addrServer.sin_family = AF_INET;
	addrServer.sin_port = htons(6000);//连接端口6000
	connect(sockClient, (SOCKADDR*)&addrServer, sizeof(SOCKADDR));//连接到服务端													 
	
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sockClient);
	if (SSL_connect(ssl) == -1) {
		ERR_print_errors_fp(stderr);
	}
	else {
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);
	}
	//发送数据
	int type = -1;
	std::fstream fs;
	std::string url = "E:\\Client\\Key\\" + std::to_string(ID) + ".txt";
	fs.open(url,std::ios::in);
	//判断用户是否为第一次加入系统
	if (fs) {
		type = 1;
	}
	else type = 0;
	fs.close();
	int recvBuf = 0;
	int error=0;
	do {
		if (type == 0) {
			SSL_write(ssl, (uint8_t*)&type, sizeof(int));
			SSL_write(ssl, (uint8_t*)&ID, sizeof(int));
			SSL_read(ssl, &error, sizeof(int));
			if (error == -1) { 
				realdata = (uint8_t*)"\ndon't join in system!!!!\n";
				break; 
			}
			unsigned char* sx = new unsigned char[Serverpubkeylen];
			unsigned char* sy = new unsigned char[Serverpubkeylen];
			EC_KEY *ecdh = genECDHpubkey(sx, sy);
			SSL_write(ssl, sx, Serverpubkeylen);
			SSL_write(ssl, sy, Serverpubkeylen);
			SSL_read(ssl, sx, Serverpubkeylen);
			SSL_read(ssl, sy, Serverpubkeylen);
			EC_POINT* Serverpk = genServerpubkey(ecdh,sx, sy);
			uint8_t *sharedkey;
			sharedkey = genECDHsharedkey(ecdh, Serverpk, 32);
			memcpy(dh_key, sharedkey, sizeof(dh_key));
			initclient = 1;
			uint8_t testdata[16];
			SSL_read(ssl, testdata, sizeof(testdata));
			uint8_t plaintestdata[16];
			aes_decrypt((char*)testdata,sizeof(testdata), sharedkey, (char*)plaintestdata);
			int re = 1;
			int a = 0;
			memcpy(&a,plaintestdata,sizeof(int));
			if (a == 1) {
				re = 0;
			}
			else break;
			SSL_write(ssl, &re, sizeof(int));
			delete sx;
			delete sy;
			if (re == 0) {
				//将共享秘钥保存在本地
				fs.open(url, std::ios::app |std::ios::out| std::ios::binary);
				fs.write((char*)&Scount, sizeof(int));
				fs.write((char*)sharedkey, 32);
				free(sharedkey);
				fs.flush();
				fs.close();
			}
			else break;
		}
		else
		{	
			int error = 0;
			SSL_write(ssl, (uint8_t*)&type, sizeof(int));
			SSL_write(ssl, (uint8_t*)&ID, sizeof(int));
			SSL_read(ssl,(uint8_t*)&error,sizeof(int));
			if (error == -1) {
				realdata = (uint8_t*)"\ncan't find your key in server!!!!\n";
				break;
			}
		}
		//初始化全局变量
		if (initclient == 0) {
			fs.open(url, std::ios::in | std::ios::binary);
			fs.read((char*)&Scount, sizeof(int));
			fs.read((char*)dh_key, 32);
			fs.close();
		}
		//uint8_t Enkey[32];
		UsertoServer.ID = ID;
		UsertoServer.dataid = dataid;
		UsertoServer.ac = ac;
		UsertoServer.Scount = Scount;
		printf("\n客户端scount值：%d",Scount);
		uint8_t sendtoServer[sizeof(rh)];
		aes_encrypt((char*)&UsertoServer, sizeof(rh),dh_key, (char*)sendtoServer);//加密并发送请求到服务端
		SSL_write(ssl, sendtoServer, sizeof(rh));

		//接受服务端相应信息
		int rsflag = 1;
		SSL_read(ssl, &rsflag, sizeof(int));
		if (rsflag == 0) {
			uint8_t* datafromserver = new uint8_t[1024];
			memset(datafromserver, 0, 1024);
			SSL_read(ssl, datafromserver, 1024);
			if (strlen((char*)datafromserver) != 0) {
				Scount++;//将计数器值加1
				std::fstream fs;
				fs.open(url, std::ios::trunc| std::ios::out| std::ios::binary);
				fs.write((char*)&Scount, sizeof(int));//将计数器值写回文件
				fs.write((char*)dh_key, 32);//将秘钥写回文件
				fs.flush();
				fs.close();
				//解密服务端传来数据
				
				memset(realdata, 0, 1024);
				aes_decrypt((char*)datafromserver,1024, dh_key, (char*)realdata);
				delete datafromserver;
			}
		}
		else if(rsflag==-1)
		{
			realdata=(uint8_t*)"\ndon't have permission to access data\n";
		}
		else if(rsflag==-2)
		{

			realdata= (uint8_t*)"\nThe Count Value don't match!!!!\n";
		}
		else
		{
			realdata = (uint8_t*)"\nerror to get data!!!!\n";
		}
	} while (0);
	//关闭socket
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	closesocket(sockClient);
	WSACleanup();
	return realdata;
}
//用户上传文件,有时间再写
//uint32_t Uploadfile(int ID,std::string fileurl) {
//	return;
//}
//用户数据结构
typedef struct user_data
{
	int type;
	int Ucount=0;
	int ID=0;
	int dataId=0;
	int ac=0;	
}user_d;
int Pcount = 0;//维护一个与代理的全局变量
void GetScertfromProxy(int way) 
{
	/*SSL初始化*/
	SSL_library_init();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	BIO *bio;
	SSL_CTX *ctx;
	SSL *ssl;
	ctx = SSL_CTX_new(SSLv3_client_method());
	if (!SSL_CTX_load_verify_locations(ctx, "C:\\CA\\cacert.pem", NULL))
	{
		printf("not find CA cert");
	}
	bio = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(bio,&ssl);
	SSL_set_mode(ssl,SSL_MODE_AUTO_RETRY);
	BIO_set_conn_hostname(bio,"127.0.0.1:6666");
	if (BIO_do_connect(bio) <= 0)
	{
		printf("client fail to connect to proxy");
	}
	if (SSL_get_verify_result(ssl) != X509_V_OK)
	{
		printf("proxy cert not true!!!!!!");
	}
	else printf("cert success");
	//接收Server cert
	user_d tem;
	int type = 0;
	tem.type = way;
	BIO_write(bio,(char*)&tem,sizeof(int));
	BIO_read(bio, &type, sizeof(int));
	if (type == 1) {
		Pcount++;
		int id = 0;
		BIO_read(bio, &id, sizeof(int));
		char Scert[1224];
		BIO_read(bio, Scert, sizeof(Scert));
		std::ofstream out;
		std::string url = "E:\\Client\\" + std::to_string(id) + ".txt";
		out.open(url, std::ios::app | std::ios::binary);
		out.write((char*)&Pcount,sizeof(int));
		//out.write((char*)&id, sizeof(int));
		out.flush();
		out.close();
		out.open("E:\\Client\\cert.pem",std::ios::app| std::ios::trunc|std::ios::binary);
		out.write(Scert,sizeof(Scert));
		out.flush();
		out.close();
		printf("\n%d", id);
	}
	BIO_free_all(bio);
	SSL_CTX_free(ctx);
}
void ChangeAC(int id,int dataid,int ac)
{
	int ret = 0;
	user_d tem;
	tem.type = 2;
	tem.ID = id;
	tem.dataId = dataid;
	tem.ac = ac;
	std::ifstream in;
	std::string url = url = "E:\\Client\\" + std::to_string(id) + ".txt";
	in.open(url, std::ios::in | std::ios::binary);
	in.read((char*)&tem.Ucount,sizeof(int));
	in.close();
	/*SSL初始化*/
	SSL_library_init();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	BIO *bio;
	SSL_CTX *ctx;
	SSL *ssl;
	ctx = SSL_CTX_new(SSLv23_client_method());
	if (!SSL_CTX_load_verify_locations(ctx, "C:\\CA\\cacert.pem", NULL))
	{
		printf("not find CA cert");
	}
	bio = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(bio, &ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	BIO_set_conn_hostname(bio, "127.0.0.1:6666");
	if (BIO_do_connect(bio) <= 0)
	{
		printf("client fail to connect to proxy\n");
	}
	else {
		if (SSL_get_verify_result(ssl) != X509_V_OK)
		{
			printf("proxy cert not true!!!!!!");
		}
		else printf("cert success\n");
	}
	//接收Server cert
	BIO_write(bio, (char*)&tem, sizeof(user_d));
	BIO_read(bio,&ret,sizeof(int));
	if (ret == 1)
	{
		Pcount++;
		std::ofstream out;
		out.open(url,std::ios::trunc | std::ios::binary);
		out.write((char*)Pcount,sizeof(int));
		//out.write((char*)&id, sizeof(int));
		out.flush();
		out.close();
	}
	else
		printf("修改error！！！！！");
	BIO_free_all(bio);
	SSL_CTX_free(ctx);
}
void main()
{
	/*GetScertfromProxy(1);*/
	GetDatafromServer(0,2,1);
	printf("\n%s\n", (char*)realdata);
	system("pause");
} 