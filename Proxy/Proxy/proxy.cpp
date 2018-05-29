#include <Winsock2.h>
#include <cstdio>
#include <stdlib.h>
#include <fstream>
#include <string>
#include <map>
#include <atomic>
#include <mutex>
#include <thread>
#include <openssl\err.h>
#include <openssl\ssl.h>
#include <openssl\ec.h>
#include <openssl\aes.h>
#include <openssl\sha.h>
#define ECDH_SIZE 33
#define MSG_LEN 16
#pragma comment(lib,"ws2_32.lib")

#define CA_FILE                "C:/CA/cacert.pem"
#define Proxy_KEY            "C:/Proxy/key.pem"
#define Proxy_CERT         "C:/Proxy/cert.pem"



void printhash(unsigned char* hash) {
	int i = 0;
	char buf[65] = { 0 };
	char tmp[3] = { 0 };
	for (i = 0; i < 32; i++)
	{
		sprintf(tmp, "%02X", hash[i]);
		strcat(buf, tmp);
	}

	printf("\nHash is:%s",buf);
}

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



EC_KEY *genECDHpubkey(unsigned char *pubkey, int nid)

{

	int len;

	EC_KEY *ecdh = EC_KEY_new();



	//Generate Public

	ecdh = EC_KEY_new_by_curve_name(nid);//NID_secp521r1

	EC_KEY_generate_key(ecdh);

	const EC_POINT *point = EC_KEY_get0_public_key(ecdh);

	const EC_GROUP *group = EC_KEY_get0_group(ecdh);



	//unsigned char *pubkey = malloc(ECDH_SIZE);

	if (0 == (len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, pubkey, ECDH_SIZE, NULL))) handleErrors();

	//printf("len=%d\n", len);



	//return pubkey;

	return ecdh;

}

//加解密函数
int aes_encrypt(char* in, unsigned char* key, char* out)
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
	int len = strlen(in);

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

unsigned char *genECDHsharedsecret(EC_KEY *ecdh, unsigned char *peerkey, size_t secret_len)

{

	int len;

	unsigned char *shared = (unsigned char *)malloc(ECDH_SIZE);

	const EC_GROUP *group = EC_KEY_get0_group(ecdh);



	//ComputeKey

	EC_POINT *point_peer = EC_POINT_new(group);

	EC_POINT_oct2point(group, point_peer, peerkey, ECDH_SIZE, NULL);



	if (0 == (len = ECDH_compute_key(shared, secret_len, point_peer, ecdh, NULL))) handleErrors();


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
		if (re == 0) {
			printf("\n服务端证书正确\n");
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
//定义发送至服务端的数据结构
typedef struct send2server
{
	uint32_t version;
	uint32_t datasize;
	uint32_t ID;
	uint8_t hash[SHA256_DIGEST_LENGTH];
	uint8_t data[];
}p2s;



std::atomic<int> Version;//版本锁



//将更新后的权限表发回服务器
int Sendaccesstable(int id,int version, char *table, std::streamoff size)
{
	int re=0;
	SSL_CTX *ctx;
	SSL *ssl;
	SOCKET socketServer;
	SOCKADDR_IN addrServer;
	
	socketServer = socket(AF_INET, SOCK_STREAM, 0);
	addrServer.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	addrServer.sin_family = AF_INET;
	addrServer.sin_port = htons(6001);
	ctx = SSL_CTX_new(SSLv3_client_method());
	/*设置会话的握手方式*/
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
	/*处理握手多次*/
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
	//导入根证书
	if (0 == SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL))
	{
		printf("don't find cacert");
	}
	/*加载代理端证书*/
	if (SSL_CTX_use_certificate_file(ctx, Proxy_CERT, SSL_FILETYPE_PEM) != 1) {
		SSL_CTX_free(ctx);
		printf("Failed to load client certificate from %s", Proxy_KEY);
	}
	/*加载代理端私钥*/
	if (SSL_CTX_use_PrivateKey_file(ctx, Proxy_KEY, SSL_FILETYPE_PEM) != 1) {
		SSL_CTX_free(ctx);
		printf("Failed to load client private key from %s", Proxy_KEY);
	}
	/*验证私钥*/
	if (SSL_CTX_check_private_key(ctx) != 1) {
		SSL_CTX_free(ctx);
		printf("SSL_CTX_check_private_key failed");
	}
	connect(socketServer, (SOCKADDR*)&addrServer, sizeof(SOCKADDR));
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, socketServer);
	if (SSL_connect(ssl) == -1) {
		ERR_print_errors_fp(stderr);
	}
	else {
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);
	}
	do {
		int type = 0;
		p2s *tamp;
		tamp = (p2s*)malloc(size + sizeof(p2s));
		if (tamp == NULL)
		{
			printf("the memory not enough");
			break;
		}
		uint8_t *vdhash;
		vdhash = (uint8_t*)malloc(sizeof(int) + size);
		if (vdhash == NULL)
		{
			printf("the memory not enough");
			break;
		}
		memcpy_s(vdhash, sizeof(int), &version, sizeof(int));
		memcpy_s(vdhash + sizeof(int), size, table, size);
		unsigned char temhash[33];
		//计算version与data的hash值
		SHA256((const unsigned char*)vdhash, sizeof(int) + size, temhash);
		memcpy(tamp->hash,temhash,32);

		printhash(tamp->hash);

		free(vdhash);
		tamp->datasize = size;
		tamp->ID = id;
		tamp->version = version;
		memcpy_s(tamp->data, size, table, size);


		//发送数据到服务端
		SSL_write(ssl, &type,sizeof(int));
		SSL_write(ssl,&tamp->datasize,sizeof(int));
		SSL_write(ssl, (char*)tamp, size + sizeof(p2s));
		
		//接收服务端的响应消息
		SSL_read(ssl, &re, sizeof(int));

		if (re!=1)
		{
			printf("\n更新权限表失败\n");
			break;
		}
		else {
			printf("\n修改成功\n");
			re = 1;
		}	
	} while (0);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	closesocket(socketServer);
	SSL_CTX_free(ctx);
	printf("\n执行完sendac函数后version值：%d", version);
	return re;
}
//用户数据结构
typedef struct user_data
{
	int type;
	int Pcount;
	int ID;
	int dataId;
	int ac;
}user_d;
char* SerializeMap(std::map<int,int> *tem,int mapsize) 
{
	char *Mchar=new char[8*mapsize];
	memset(Mchar,0,8*mapsize);
	std::map<int, int>::iterator it;
	it = tem->begin();
	int a = 0;
	while (it != tem->end()) {
		uint8_t tem[4];
		memcpy(tem,&it->first,sizeof(tem));
		memcpy(Mchar+a,tem,sizeof(tem));
		a += 4;
		memcpy(tem,&it->second,sizeof(tem));
		memcpy(Mchar + a, tem, sizeof(tem));
		a += 4;
		it++;
	}
	return Mchar;
}

std::atomic<int> id ;//id锁

std::mutex m;//声明互斥锁
int txtlen = 10;
void useractive(SOCKET sockClient, SSL_CTX *ctx) {
	SSL *ssl;
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sockClient);
	if (SSL_accept(ssl) == -1)
	{
		perror("accept");
		closesocket(sockClient);
	}
	else printf("\naccept con from Client\n");
	user_d tamp_d;
	char *senddata;
	int Ucount = 0;//用户与代理间同步记号
	SSL_read(ssl, (char*)&tamp_d, sizeof(user_data));
	//此处可更改为只传送要修改的内容,让服务端去修改。我这里目前是在proxy端修改完然后全部传送。
	m.lock();//对下面代码段加锁
	if (tamp_d.type == 1)
	{
		std::ifstream in;
		char buf[1224];
		in.open("C://Server//cert.pem", std::ios::in | std::ios::binary);
		memset(buf, 0, 1224);
		in.read(buf, 1224);
		in.close();
		std::ofstream out;
		printf("\n来自用户：%d的连接\n", id);
		tamp_d.ID = id;
		std::string url = "E:\\Proxy\\" + std::to_string(id) + ".txt";
		out.open(url, std::ios::app | std::ios::binary);
		std::map<int, int> *useracmap = new std::map<int, int>;
		for (int i = 0; i < txtlen; i++)
		{
			useracmap->insert(std::pair<int, int>(i, rand() % 3));
			printf("\n%d用户权限：%d",id,useracmap->find(i)->second);
		}
		char *senddata = SerializeMap(useracmap, useracmap->size());
		
		int tem = Sendaccesstable(tamp_d.ID,Version, senddata, 8*(useracmap->size()));//发送数据到服务端
		if (tem == 1) {
			Ucount++;
			out.write((char*)&Ucount, sizeof(int));
			out.write(senddata, 8 * (useracmap->size()));
			SSL_write(ssl, &tem, sizeof(int));
			SSL_write(ssl, (char*)&id, sizeof(int));//返回客户端ID
			SSL_write(ssl, buf, sizeof(buf));//返回服务器证书
			out.flush();
			out.close();
			delete useracmap;
			id+=1;
			Version += 1;//计数器加1
			//写入ID
			std::fstream fs;
			fs.open("E:\\Proxy\\ID.txt", std::ios::trunc | std::ios::out);
			fs.write((char*)&id, sizeof(int));
			fs.flush();
			fs.close();
			//写入Version
			fs.open("E:\\Proxy\\Version.txt", std::ios::trunc | std::ios::out);
			fs.write((char*)&Version, sizeof(int));
			fs.flush();
			fs.close();
			
		}
		else
		{
			SSL_write(ssl, &tem, sizeof(int));
		}
	}
	else if (tamp_d.type == 2)
	{
		int tem = 0;
		std::map<int, int> *useracmap = new std::map<int, int>;
		std::ifstream in;
		std::string url = "E://Proxy//" + std::to_string(tamp_d.ID) + ".txt";
		in.open(url, std::ios::binary | std::ios::in);
		in.read((char*)&Ucount, sizeof(int));
		if (Ucount == tamp_d.Pcount) {
			std::streamoff start = in.tellg();
			std::streamoff end = in.seekg(0, std::ios::end).tellg();
			std::streamoff size = end - start;
			in.seekg(start);
			std::streamoff pos = in.tellg();
			/*写一个反序列化函数*/
			while (pos != end)
			{
				int a = 0;
				int b = 0;
				in.read((char*)&a, sizeof(int));
				in.read((char*)&b, sizeof(int));
				useracmap->insert(std::pair<int, int>(a, b));
				pos = in.tellg();
			}
			useracmap->at(tamp_d.dataId) = tamp_d.ac;
			char *senddata = SerializeMap(useracmap, useracmap->size());
			tem = Sendaccesstable(tamp_d.ID,Version, senddata, size);//发送修改完数据到服务端
			if (tem == 1) {
				std::ofstream out;
				out.open(url, std::ios::trunc | std::ios::binary);
				Ucount++;
				out.write((char*)&Ucount, sizeof(int));
				out.write(senddata, 8 * (useracmap->size()));
				out.flush();
				out.close();
				Version += 1;//计数器加1
				out.open("E:\\Proxy\\Version.txt", std::ios::trunc | std::ios::binary);
				out.write((char*)&Version, sizeof(int));
				out.flush();
				out.close();
				SSL_write(ssl, &tem, sizeof(int));
			}
			else SSL_write(ssl, &tem, sizeof(int));
			delete(useracmap);
		}
		else SSL_write(ssl, &tem, sizeof(int));	
	}
	m.unlock();
}
void StartProxy()
{
	SSL_CTX *ctx;
	//win下socket接口
	SOCKET sockproxy;
	SOCKET sockClient;//客户端Socket
	SOCKADDR_IN addrClient;//客户端地址
	SOCKADDR_IN addrProxy;//代理端地址
	
	//代理端绑定
	sockproxy = socket(AF_INET, SOCK_STREAM, 0);
	addrProxy.sin_addr.S_un.S_addr = htonl(INADDR_ANY);//INADDR_ANY表示任何IP
	addrProxy.sin_family = AF_INET;
	addrProxy.sin_port = htons(6666);//绑定端口6666
	bind(sockproxy, (SOCKADDR*)&addrProxy, sizeof(SOCKADDR));
	//Listen监听端
	listen(sockproxy, SOMAXCONN);//5为等待连接数目
	printf("Proxy已启动:\n监听中...\n");

	ctx = SSL_CTX_new(SSLv3_server_method());

	/*加载代理端证书*/
	if (SSL_CTX_use_certificate_file(ctx, Proxy_CERT, SSL_FILETYPE_PEM) != 1) {
		SSL_CTX_free(ctx);
		printf("Failed to load Proxy certificate from %s", Proxy_KEY);
	}
	/*加载代理端私钥*/
	if (SSL_CTX_use_PrivateKey_file(ctx, Proxy_KEY, SSL_FILETYPE_PEM) != 1) {
		SSL_CTX_free(ctx);
		printf("Failed to load Proxy private key from %s", Proxy_KEY);
	}
	/*验证私钥*/
	if (SSL_CTX_check_private_key(ctx) != 1) {
		SSL_CTX_free(ctx);
		printf("SSL_CTX_check_private_key failed");
	}
	int len = sizeof(SOCKADDR);
	while (true)
	{	
		sockClient = accept(sockproxy, (SOCKADDR*)&addrClient, &len);
		std::thread t(useractive,sockClient,ctx);
		t.detach();
	}

}
void InitIDandVersion() {
	std::fstream fs;
	fs.open("E:\\Proxy\\ID.txt", std::ios::in);
	if (fs) {
		fs.read((char*)&id, sizeof(int));
	}
	else {
		id = 0;
		fs.open("E:\\Proxy\\ID.txt", std::ios::app | std::ios::binary);
		fs.write((char*)&id, sizeof(int));
		fs.flush();
	}
	fs.close();
	fs.open("E:\\Proxy\\Version.txt",std::ios::in);
	if (fs) {
		fs.read((char*)&Version,sizeof(int));
	}
	else {
		Version = 0;
		fs.open("E:\\Proxy\\Version.txt", std::ios::app|std::ios::binary);
		fs.write((char*)&Version,sizeof(int));
		fs.flush();
		
	}
	fs.close();
	printf("初始化的Version值为：%d\n初始化的id值为：%d",Version,id);
}
void main()
{
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);//加载socket库
	/*SSL初始化*/
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	//初始化全局变量Version
	InitIDandVersion();
	StartProxy();
	WSACleanup();
	system("pause");
}
