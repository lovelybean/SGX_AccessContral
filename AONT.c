//��λ�����������
void XORcompute(uint8_t *a, uint8_t *b, uint8_t *re, size_t len) {
	for (int i = 0; i < len; i++) {
		re[i] = a[i] ^ b[i];
	}
}
//ʹ��AONT�Ż�aes_cbc�����㷨
void AES_EnIntegrateAONT_CBC(uint8_t *plaintext, size_t plaintextlen, uint8_t *key, size_t keylen, uint8_t *Entext) {
	BIGNUM *randKey;
	randKey = BN_new();//k'
	uint8_t *replaintext;//m
	uint8_t *tampreplaintext;//m'
	size_t repsize = plaintextlen;//����16�ֽ���������ȫ������ݳ���
	BN_rand(randKey, 128, -1, 0);//�������һ��128λ��key
	unsigned char Crandkey[16];
	BN_bn2bin(randKey, Crandkey);//������ת����unsigned char
	BN_clear_free(randKey);//���ڴ�
						   //��ȫ����Ϊ16��������
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
	AES_KEY tampkey;
	AES_set_encrypt_key(Crandkey, 128, &tampkey);
	//Ek'(i)
	for (int i = 0; i < (repsize / 16); i++) {
		uint8_t tamp[16];
		memset(tamp, 0, sizeof(tamp));
		memcpy(tamp, &i, sizeof(int));
		AES_encrypt((const unsigned char*)tamp, tampreplaintext + (16 * i), &tampkey);
	}
	//mi��Ek'(i)�������,����m'
	for (int i = 0; i < (repsize / 16); i++) {
		XORcompute(replaintext + (16 * i), tampreplaintext + (16 * i), tampreplaintext + (16 * i), 16);
	}
	//����hi
	AES_KEY publickey;
	AES_set_encrypt_key(key, keylen * 8, &publickey);
	uint8_t *h = new uint8_t[repsize];
	for (int i = 0; i < (repsize / 16); i++) {
		uint8_t tamp[16];
		memset(tamp, 0, sizeof(tamp));
		memcpy(tamp, &i, sizeof(int));
		XORcompute(tampreplaintext + (16 * i), tamp, h + (16 * i), 16);
		AES_encrypt(h + (16 * i), h + (16 * i), &publickey);
	}
	//����ms'
	uint8_t ms[16];
	memcpy(ms, Crandkey, sizeof(ms));
	for (int i = 0; i < (repsize / 16); i++)
	{
		XORcompute(h + (16 * i), ms, ms, 16);
	}
	memcpy(Entext, tampreplaintext, repsize);
	memcpy(Entext + repsize, ms, sizeof(ms));
	delete[] replaintext;
	delete[] tampreplaintext;
	delete[] h;
}
//AONT�����㷨
void AES_DeIntegrateAont_CBC(uint8_t *Entext, size_t Entextlen, uint8_t *key, size_t keylen, uint8_t *plaintext) {
	//����hi
	AES_KEY publickey;
	AES_set_encrypt_key(key, keylen * 8, &publickey);
	uint8_t *tampEndata = new uint8_t[Entextlen - 16];
	uint8_t *h = new uint8_t[Entextlen - 16];
	for (int i = 0; i < (Entextlen / 16) - 1; i++) {
		uint8_t count[16];
		memset(count, 0, 16);
		memcpy(count, &i, sizeof(int));
		XORcompute(Entext + (16 * i), count, tampEndata + (16 * i), 16);
		AES_encrypt(tampEndata + (16 * i), h + (16 * i), &publickey);
	}
	//����k'
	uint8_t tampkey[16];
	memset(tampkey, 0, sizeof(tampkey));
	for (int i = 0; i < (Entextlen / 16) - 1; i++) {
		XORcompute(tampkey, h + (16 * i), tampkey, 16);
	}
	XORcompute(tampkey, Entext + (Entextlen - 16), tampkey, 16);
	delete[] h;
	//��������
	AES_set_encrypt_key(tampkey, sizeof(tampkey) * 8, &publickey);
	for (int i = 0; i < Entextlen / 16 - 1; i++) {
		uint8_t tampi[16];
		memset(tampi, 0, 16);
		memcpy(tampi, &i, sizeof(int));
		AES_encrypt(tampi, tampEndata + (16 * i), &publickey);
	}
	//��������
	for (int i = 0; i < Entextlen / 16 - 1; i++) {
		XORcompute(Entext + (16 * i), tampEndata + (16 * i), plaintext + (16 * i), 16);
	}
	delete[] tampEndata;
}
