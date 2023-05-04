#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>

#pragma comment(lib, "crypt32")
#pragma comment(lib, "ws2_32.lib")

#include <iostream>
#include <string>
#include <vector>
#include <time.h>
#include <ctime>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/aes.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/asn1err.h>
#include <openssl/objects.h>
#include <openssl/ecdh.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/rsa.h>
#include <openssl/applink.c>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/types.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>

using namespace std;

typedef struct ASN1_email {
	ASN1_PRINTABLESTRING* s_from;
	ASN1_PRINTABLESTRING* s_to;
	ASN1_PRINTABLESTRING* s_title;
	ASN1_PRINTABLESTRING* s_body;
	ASN1_OCTET_STRING* s_signature;
	ASN1_TIME* s_time;
	ASN1_PRINTABLESTRING* s_encoded_key;
}ASN1_email;

ASN1_SEQUENCE(ASN1_email) = {
	ASN1_SIMPLE(ASN1_email, s_from, ASN1_PRINTABLESTRING),
	ASN1_SIMPLE(ASN1_email, s_to, ASN1_PRINTABLESTRING),
	ASN1_SIMPLE(ASN1_email, s_title, ASN1_PRINTABLESTRING),
	ASN1_SIMPLE(ASN1_email, s_body, ASN1_PRINTABLESTRING),
	ASN1_SIMPLE(ASN1_email, s_signature, ASN1_OCTET_STRING),
	ASN1_SIMPLE(ASN1_email, s_time, ASN1_TIME),
	ASN1_SIMPLE(ASN1_email, s_encoded_key, ASN1_PRINTABLESTRING)
}ASN1_SEQUENCE_END(ASN1_email);

DECLARE_ASN1_FUNCTIONS(ASN1_email);
IMPLEMENT_ASN1_FUNCTIONS(ASN1_email);

#define database_file "./ATM_MAIL_DB"
#define AES_GCM_KEY_SIZE 32
#define RSA_SIZE_BITS 4096
#define RSA_SIZE_BYTES 512
#define AES_GCM_IV_SIZE 12
#define AES_GCM_NONCE_SIZE 12
#define AES_GCM_BLOCK_SIZE 16
#define SHA256_OUTBLK_SIZE 32

unsigned char* get_SIM_KEY(int size) {
	unsigned char* key = new unsigned char[size];
	RAND_bytes(key, size);

	return key;
}

unsigned char* generate_key_pair(RSA** rsa, int key_size, const char* filename_key_PUB, const char* filename_key_PRV) {
	BIGNUM* bn = BN_new();

	BN_set_word(bn, RSA_F4);

	RSA_generate_key_ex(*rsa, key_size, bn, NULL);

	FILE* f_pub = fopen(filename_key_PUB, "wb");
	if (f_pub == NULL) {
		std::cout << "f pub file could not be opened\n";
		return NULL;
	}
	PEM_write_RSAPublicKey(f_pub, *rsa);
	fclose(f_pub);

	FILE* f_prv = fopen(filename_key_PRV, "wb");
	if (f_prv == NULL) {
		std::cout << "f prv file could not be opened\n";
		return NULL;
	}
	PEM_write_RSAPrivateKey(f_prv, *rsa, NULL, NULL, 0, NULL, NULL);
	fclose(f_prv);

	return (unsigned char*)"ok";
}

unsigned long long get_exponent() {
	//exponentul public egal cu cel mai mic număr liber de pătrate, impar, 
	//multiplu de 7 și mai mare decât momentul de timp din momentul înregistrării
	time_t time = std::time(NULL);
	int free_patr = 0;
	again:
	while (time % 2 == 0 && free_patr == 0) {
		time += 1;
		free_patr = 1;
		for (int i = 2; i <= std::sqrt(time); i++) {
			if (time % (i * i) == 0) {
				free_patr = 0;
				break;
			}
		}
	}
	/*if (time % 7 != 0) {
		goto again;
	}*/
	return static_cast<unsigned long long>(time);
}

void generate_RSA_pair(const char *filename_pub, const char *filename_prv) {
	RSA* pkey = RSA_new();

	unsigned long long exponent = get_exponent();
	BIGNUM* exp = BN_new();

	BN_set_word(exp, exponent);
	RSA_generate_key_ex(pkey, RSA_SIZE_BITS, exp, NULL);

	FILE* f_pub = fopen(filename_pub, "wb");
	PEM_write_RSAPublicKey(f_pub, pkey);
	fclose(f_pub);

	FILE* f_prv = fopen(filename_prv, "wb");
	PEM_write_RSAPrivateKey(f_prv, pkey, NULL, NULL, 0, NULL, NULL);
	fclose(f_prv);
}

void enrole_user(std::string email) {
	FILE* f_db = fopen(database_file, "a");
	std::string to_write_in_db = email + ": ";
	std::size_t pos = email.find('@');
	std::string name = email.substr(0, pos);
	std::string path = "./" + name + "-key.pub";
	std::string path_prv = "./" + name + "-key.prv";

	unsigned char* public_key = get_SIM_KEY(AES_GCM_KEY_SIZE);

	std::string line_db = to_write_in_db + path + "\n";

	fwrite((line_db).c_str(), strlen(line_db.c_str()), 1, f_db);
	fclose(f_db);

	//FILE* f = fopen(path.c_str(), "wb");
	//fwrite(public_key, AES_GCM_KEY_SIZE, 1, f);
	//fclose(f);

	std::string crypto_params_file = name + "-params.crypto";
	FILE* f_prms = fopen(crypto_params_file.c_str(), "wb");

	unsigned char* sim_key = get_SIM_KEY(AES_GCM_KEY_SIZE);
	fwrite(sim_key, AES_GCM_KEY_SIZE, 1, f_prms);
	unsigned char* nonce = get_SIM_KEY(AES_GCM_NONCE_SIZE);
	fwrite(nonce, AES_GCM_NONCE_SIZE, 1, f_prms);
	fwrite("\n", 1, 1, f_db);

	generate_RSA_pair(path.c_str(), path_prv.c_str());
	path += "\n";
	path_prv += "\n";
	fwrite(path.c_str(), strlen(path.c_str()), 1, f_prms);
	//fwrite("\n", 2, 1, f_db);
	fwrite(path_prv.c_str(), strlen(path_prv.c_str()), 1, f_prms);
	fclose(f_prms);
	std::cout << name + " was added successfully and crypto params are generated successfully\n";

	std::string a = name + ".account";

	FILE* aux = fopen(a.c_str(), "w");
	fclose(aux);
}

unsigned char* get_key_PBKDF2(unsigned char* passwd, int passwd_len) {
	unsigned char* salt = get_SIM_KEY(AES_GCM_IV_SIZE);
	unsigned char* key = new unsigned char[AES_GCM_KEY_SIZE];
	PKCS5_PBKDF2_HMAC((const char*)passwd, passwd_len, (const unsigned char*)salt, AES_GCM_IV_SIZE, 64000, EVP_sha256(), AES_GCM_KEY_SIZE, key);
	return key;
}

unsigned char* get_sim_key_from_crypto_params_FILE(std::string email) {
	std::size_t pos = email.find('@');
	std::string name = email.substr(0, pos);
	std::string crypto_params_file = name + "-params.crypto";
	FILE* f_prms = fopen(crypto_params_file.c_str(), "rb");

	unsigned char* key = new unsigned char[AES_GCM_KEY_SIZE];
	fread(key, AES_GCM_KEY_SIZE, 1, f_prms);
	fclose(f_prms);

	return key;
}

unsigned char* get_nonce_from_crypto_params_FILE(std::string email) {
	std::size_t pos = email.find('@');
	std::string name = email.substr(0, pos);
	std::string crypto_params_file = name + "-params.crypto";
	FILE* f_prms = fopen(crypto_params_file.c_str(), "rb");
	
	fseek(f_prms, AES_GCM_KEY_SIZE, SEEK_SET);

	unsigned char* nonce = new unsigned char[AES_GCM_IV_SIZE];
	fread(nonce, AES_GCM_IV_SIZE, 1, f_prms);
	fclose(f_prms);

	return nonce;
}

void AES_GCM_Encrypt(unsigned char* plain_text, int plain_len, unsigned char* key, int key_len, unsigned char* iv, unsigned char** cipher_text, int *cipher_len, unsigned char** tag) {
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL); // initializez operatia de criptare
	EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
	//aditional auth data
	int len_update;
	int len_final;
	*cipher_text = new unsigned char[plain_len + AES_GCM_BLOCK_SIZE - 1];
	EVP_EncryptUpdate(ctx, *cipher_text, &len_update, plain_text, plain_len);
	EVP_EncryptFinal_ex(ctx, *cipher_text + len_update, &len_final);
	*tag = new unsigned char[AES_GCM_BLOCK_SIZE];
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AES_GCM_BLOCK_SIZE, *tag);
	*cipher_len = len_update + len_final;
}

void AES_GCM_Decrypt(unsigned char* cipher_text, int cipher_len, unsigned char* key, int key_len, unsigned char* iv, unsigned char** plain_text, int* plain_len, unsigned char** tag) {
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL); // initializez operatia de criptare
	EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
	//aditional auth data
	int len_update;
	int len_final;
	*plain_text = new unsigned char[cipher_len + AES_GCM_BLOCK_SIZE - 1];
	EVP_DecryptUpdate(ctx, *plain_text, &len_update, cipher_text, cipher_len);
	EVP_DecryptFinal_ex(ctx, *plain_text + len_update, &len_final);
	*tag = new unsigned char[AES_GCM_BLOCK_SIZE];
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AES_GCM_BLOCK_SIZE, *tag);
	*plain_len = len_update + len_final;
}

unsigned char* get_iv(unsigned char* nonce, unsigned char* time_stamp) {
	unsigned char* iv = new unsigned char[AES_GCM_IV_SIZE];

	for (int i = 0; i < AES_GCM_IV_SIZE; i++) {
		iv[i] = nonce[i] ^ time_stamp[i % strlen((char*)time_stamp)];
	}

	return iv;
}

unsigned char* get_timestamp() {
	time_t t = time(NULL);
	unsigned char timestamp[sizeof(time_t)];
	unsigned char* ptr = (unsigned char*)&t;

	for (size_t i = 0; i < sizeof(time_t); i++) {
		timestamp[i] = *(ptr + i);
	}
	return timestamp;
}

unsigned char* encode_base64(unsigned char* str, int* len) {
	BIO* memory;
	BIO* b64event;
	BUF_MEM* my_buf;

	b64event = BIO_new(BIO_f_base64());
	memory = BIO_new(BIO_s_mem());
	b64event = BIO_push(b64event, memory);

	BIO_set_flags(b64event, BIO_FLAGS_BASE64_NO_NL);

	BIO_write(b64event, str, *len);

	BIO_flush(b64event);

	BIO_get_mem_ptr(b64event, &my_buf);


	*len = (4 * (*len)) / 3 + 2;
	size_t output_len = my_buf->length;

	unsigned char* res = new unsigned char[(int)output_len + 1];
	memcpy(res, (unsigned char*)my_buf->data, (int)output_len);
	res[output_len] = '\0';

	BIO_free_all(b64event);
	return res;
}

unsigned char* decode_base64(unsigned char* str, int* len) {
	int nr_eq = 0;

	if (str[strlen((char*)str) - 1] == '=' && str[strlen((char*)str) - 2] == '=') {
		nr_eq = 2;
	}

	BIO* b64 = BIO_new(BIO_f_base64());
	BIO* buffy = BIO_new_mem_buf(str, *len); //-1 null terminated si size e strlen
	buffy = BIO_push(b64, buffy);

	BIO_set_flags(buffy, BIO_FLAGS_BASE64_NO_NL);

	

	unsigned char* plain_text = (unsigned char*)malloc((*len) * sizeof(unsigned char));
	if (plain_text == NULL) {
		exit(EXIT_FAILURE);
	}

	int k = BIO_read(buffy, plain_text, *len);
	(*len) = (3 * ((*len))) / 4 - nr_eq + 1;
	plain_text[(*len) + 1] = '\0';

	return plain_text;
}

RSA* get_public_key(std::string email) {
	std::size_t pos = email.find('@');
	std::string name = email.substr(0, pos);
	std::string path = "./" + name + "-key.pub";

	FILE* f = fopen(path.c_str(), "rb");
	
	RSA* pkey = RSA_new();
	PEM_read_RSAPublicKey(f, &pkey, NULL, NULL);

	fclose(f);

	return pkey;
}

RSA* get_private_key(std::string email) {
	std::size_t pos = email.find('@');
	std::string name = email.substr(0, pos);
	std::string path = "./" + name + "-key.prv";

	FILE* f = fopen(path.c_str(), "rb");

	RSA* pkey = RSA_new();
	PEM_read_RSAPrivateKey(f, &pkey, NULL, NULL);

	fclose(f);

	return pkey;
}

unsigned char* get_AES_key(std::string email) {
	unsigned char* to_ret = new unsigned char[AES_GCM_KEY_SIZE];

	std::size_t pos = email.find('@');
	std::string name = email.substr(0, pos);
	std::string crypto_params_file = name + "-params.crypto";

	FILE* f = fopen(crypto_params_file.c_str(), "rb");

	fread(to_ret, AES_GCM_KEY_SIZE, 1, f);
	fclose(f);

	return to_ret;
}

unsigned char* hash_body(unsigned char* body, int body_len, int* after_len) {
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();

	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

	int len_update;
	int len_final;

	EVP_DigestUpdate(ctx, body, body_len);

	unsigned char* hashed = new unsigned char[SHA256_OUTBLK_SIZE];

	EVP_DigestFinal(ctx, hashed, (unsigned int *)after_len);

	return hashed; /////PROST!!!!! INTREABA LAB!!!!!??????????????????
}

//unsigned char* sign_body(unsigned char* body, int body_len, std::string to, size_t *out_len) {
//	//RSA* prv_key = get_private_key(to);
//	////EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(prv_key, NULL);
//
//	//int output = 0;
//
//	//unsigned char* hbody = hash_body(body, body_len, &output);
//	//unsigned char* signature = new unsigned char[RSA_SIZE_BITS];
//
//	//size_t slen = 0;
//	//EVP_PKEY_sign_init_ex(ctx, NULL);
//	//int k = EVP_PKEY_sign(ctx, signature, &slen, hbody, output);
//	//if (k <= 0) {
//	//	std::cout << ERR_error_string(ERR_get_error(), NULL);
//	//}
//	//*out_len = slen;
//
//	//return signature;//PROST!!!!! INTREABA LAB !!!!??????
//}

//unsigned char* sign_body2(unsigned char* body, int body_len, std::string to, size_t* out_len) {
//	RSA* prv_key = get_private_key(to);
//	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
//
//	EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, prv_key);
//	EVP_DigestSignUpdate(md_ctx, body, body_len);
//	size_t signature_len;
//	EVP_DigestSignFinal(md_ctx, NULL, &signature_len);
//	unsigned char* signature = (unsigned char*)OPENSSL_malloc(signature_len);
//	
//	if (EVP_DigestSignFinal(md_ctx, signature, &signature_len) != 1) {
//		std::cout << ERR_error_string(ERR_get_error(), NULL);
//	}
//
//	*out_len = signature_len;
//	return signature;
//}

//unsigned char* sign_body2(unsigned char* body, int body_len, std::string to, int* out_len) {
//	RSA* prv_key = get_private_key(to);
//	unsigned char* signature = (unsigned char*)OPENSSL_malloc(RSA_size(prv_key));
//
//	unsigned char* hash = new unsigned char[SHA256_DIGEST_LENGTH];
//	SHA256(body, body_len, hash);
//
//	int bytes_enc = RSA_sign(NID_sha256, body, body_len, signature, (unsigned int *)out_len, prv_key);
//	
//	if (bytes_enc <= 0) {
//		// Error occurred while signing the message
//		printf("Error signing message: %s\n", ERR_error_string(ERR_get_error(), NULL));
//		exit(EXIT_FAILURE);
//	}
//	return signature;
//}
//
//void verify_signed_body_2(unsigned char* body, int body_len, std::string from, int* out_len) {
//	RSA* prv_key = get_public_key(from);
//	unsigned char* signature = (unsigned char*)OPENSSL_malloc(RSA_size(prv_key));
//
//	int bytes_enc = RSA_verify(NID_sha256, body, body_len, signature, (unsigned int)out_len, prv_key);
//
//	if (bytes_enc != 1) {
//		// Error occurred while signing the message
//		printf("Error verifying signature: %s\n", ERR_error_string(ERR_get_error(), NULL));
//		exit(EXIT_FAILURE);
//	}
//	else {
//		printf("SIGNATURE MATCHES! \n");
//	}
//}

unsigned char* sign_body2(unsigned char* body, int body_len, std::string from, int* out_len) {
	RSA* prv_key = get_private_key(from);

	EVP_PKEY* prv_key_evp = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(prv_key_evp, prv_key);

	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();

	int k = EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, prv_key_evp);
	if (k <= 0) {
		printf("Error signing message-init: %s\n", ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}
	k = EVP_DigestSignUpdate(md_ctx, body, body_len);
	if (k <= 0) {
		printf("Error signing message-update: %s\n", ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}
	size_t sign_len;

	k = EVP_DigestSignFinal(md_ctx, NULL, &sign_len);
	if (k <= 0) {
		printf("Error signing message-final_size: %s\n", ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}
	unsigned char* signature = new unsigned char[sign_len];
	k = EVP_DigestSignFinal(md_ctx, signature, &sign_len);
	if (k <= 0) {
		printf("Error signing message-final: %s\n", ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}
	*out_len = sign_len;
	return signature;
}

void verify_signed_body_2(unsigned char* body, int body_len, unsigned char *signature, int signature_len, std::string from, int* out_len) {
	RSA* prv_key = get_public_key(from);

	EVP_PKEY* prv_key_evp = EVP_PKEY_new();
	int k = EVP_PKEY_assign_RSA(prv_key_evp, prv_key);

	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();

	k = EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, prv_key_evp);
	k = EVP_DigestVerifyUpdate(md_ctx, body, body_len);

	int result = EVP_DigestVerifyFinal(md_ctx, signature, signature_len);
	if (result == 1) {
		std::cout << "Signature matches!" << std::endl;
	}
	else std::cout << "Signature does not match" << std::endl << ERR_error_string(ERR_get_error(), NULL) << std::endl;
}

unsigned char* encode_key(unsigned char* key, std::string to) {
	RSA* pub_key = get_public_key(to);

	int size = RSA_size(pub_key);

	unsigned char* encrypted = new unsigned char[size];

	size_t outlen;
	int bytes_enc = RSA_public_encrypt(AES_GCM_KEY_SIZE, key, encrypted, pub_key, RSA_PKCS1_PADDING);
	if (bytes_enc <= 0) {
		std::cout << ERR_error_string(ERR_get_error(), NULL);
	}

	return encrypted;
}

unsigned char* decode_key(unsigned char* key, std::string to) {
	RSA* pub_key = get_private_key(to);

	int size = RSA_size(pub_key);

	unsigned char* encrypted = new unsigned char[size];

	size_t outlen;
	int bytes_enc = RSA_private_decrypt(RSA_SIZE_BYTES, key, encrypted, pub_key, RSA_PKCS1_PADDING);
	if (bytes_enc <= 0) {
		std::cout << ERR_error_string(ERR_get_error(), NULL);
	}

	return encrypted;
}

char* convert_to_hex_string(unsigned char* text, int *len) {
	char* hex = new char[2 * (*len) + 1];

	for (int i = 0; i < (*len); i++) {
		sprintf(hex + 2 * i, "%.02x", text[i]);
	}
	*len = (2 * (*len)) + 1;
	text[*len] = '\0';
	return hex;
}

unsigned char* convert_from_hex_string(const unsigned char* hex_text, int hex_len) {
	int bin_len = (hex_len) / 2;
	unsigned char* bin_text = (unsigned char*)malloc(bin_len * sizeof(char));
	if (bin_len == NULL) {
		return NULL;
	}
	char bin_byte[3];
	for (int i = 0; i < bin_len; i++) {
		bin_byte[0] = hex_text[i * 2];
		bin_byte[1] = hex_text[i * 2 + 1];
		bin_byte[2] = '\0';
		bin_text[i] = strtol(bin_byte, NULL, 16);
	}

	return bin_text;
}

void write_mail_in_conversation(std::string to, ASN1_email* data) {
	std::size_t pos = to.find('@');
	std::string name = to.substr(0, pos);
	std::string a = name + ".account";

	FILE* f = fopen(a.c_str(), "ab");
	unsigned char* ber_info, * myber;
	int len = i2d_ASN1_email(data, NULL);
	ber_info = (unsigned char*)OPENSSL_malloc(len);
	if (ber_info == nullptr)
		fprintf(stderr, "OpenSSL malloc Error Occur:(\n");
	myber = ber_info;

	i2d_ASN1_email(data, &myber);

	char* text = convert_to_hex_string(ber_info, &len);
	strcat(text, "\n");
	fwrite(text, len, 1, f);
	fclose(f);
}

void send_mail(std::string from, std::string to, std::string title, std::string body) {
	unsigned char* sim_key_file = get_sim_key_from_crypto_params_FILE(from);
	unsigned char* sim_enc_key = get_key_PBKDF2(sim_key_file, AES_GCM_KEY_SIZE);
	unsigned char* cipher_text;
	int cipher_len;
	unsigned char* tag;
	unsigned char* iv = get_iv(get_nonce_from_crypto_params_FILE(from), get_timestamp());

	///////////body

	AES_GCM_Encrypt((unsigned char*)body.c_str(), strlen(body.c_str()), sim_enc_key, AES_GCM_KEY_SIZE, iv, &cipher_text, &cipher_len, &tag);

	int final_size = AES_GCM_IV_SIZE + cipher_len + AES_GCM_BLOCK_SIZE;
	unsigned char* body_block = new unsigned char[final_size];

	memcpy(body_block, iv, AES_GCM_IV_SIZE);
	memcpy(body_block + AES_GCM_IV_SIZE, cipher_text, cipher_len);
	memcpy(body_block + AES_GCM_IV_SIZE + cipher_len, tag, AES_GCM_BLOCK_SIZE);
	
	unsigned char* encoded_body = encode_base64(body_block, &final_size);
	int asn1_finalsize = final_size;

	int out_sgn_len = 0;

	/////////body

	unsigned char* signature = sign_body2(encoded_body, final_size, from, &out_sgn_len);

	time_t current_time;
	time(&current_time);

	struct tm* tm_val = gmtime(&current_time);

	unsigned char* encoded_key = encode_key(sim_enc_key, to);

	ASN1_email* email = ASN1_email_new();

	email->s_from = ASN1_PRINTABLESTRING_new();
	email->s_to = ASN1_PRINTABLESTRING_new();
	email->s_title = ASN1_PRINTABLESTRING_new();
	email->s_body = ASN1_PRINTABLESTRING_new();
	email->s_signature = ASN1_OCTET_STRING_new();
	email->s_time = ASN1_UTCTIME_new();
	email->s_encoded_key = ASN1_PRINTABLESTRING_new();

	ASN1_STRING_set(email->s_from, (const char *)from.c_str(), from.length());
	ASN1_STRING_set(email->s_to, (const char*)to.c_str(), to.length());
	ASN1_STRING_set(email->s_title, (const char*)title.c_str(), title.length());
	ASN1_STRING_set(email->s_body, encoded_body, asn1_finalsize);
	ASN1_OCTET_STRING_set(email->s_signature, signature, out_sgn_len);
	ASN1_UTCTIME_set(email->s_time, current_time);

	int sizeB = RSA_SIZE_BYTES;

	unsigned char* base64_enc_key = encode_base64(encoded_key, &sizeB);

	ASN1_STRING_set0(email->s_encoded_key, base64_enc_key, sizeB);

	write_mail_in_conversation(to, email);
}

unsigned char* decrypt_body(unsigned char* body, int length, unsigned char *key, unsigned char* timestamp, int len_stamp, int *plain_lenRET) {
	unsigned char* decodif = decode_base64(body, &length);

	int cipher_len = length - AES_GCM_IV_SIZE - AES_GCM_BLOCK_SIZE - 1;

	unsigned char* iv = new unsigned char[AES_GCM_IV_SIZE];
	unsigned char* cipher_text = new unsigned char[cipher_len];
	unsigned char* tag = new unsigned char[AES_GCM_BLOCK_SIZE];

	memcpy(iv, decodif, AES_GCM_IV_SIZE);
	iv[AES_GCM_IV_SIZE] = '\0';
	unsigned char* good_iv = new unsigned char[AES_GCM_IV_SIZE];

	for (int i = 0; i < AES_GCM_IV_SIZE; i++) {
		good_iv[i] = iv[i] ^ timestamp[i % len_stamp];
	}

	memcpy(cipher_text, decodif + AES_GCM_IV_SIZE, cipher_len);
	memcpy(tag, decodif + AES_GCM_IV_SIZE + cipher_len, AES_GCM_BLOCK_SIZE);

	int plain_len;

	unsigned char* plain_text;
	cipher_text[cipher_len] = '\0';
	AES_GCM_Decrypt(cipher_text, cipher_len, key, AES_GCM_KEY_SIZE, iv, &plain_text, &plain_len, &tag);
	*plain_lenRET = plain_len;

	return plain_text;
}

unsigned char* decrypt_sim_key(unsigned char* encoded_key, std::string email) {
	int orig_size = (4 * RSA_SIZE_BYTES) / 3 + 2;

	unsigned char* haha_key = decode_base64(encoded_key, &orig_size);

	return decode_key(haha_key, email);
}

void read_mail(std::string who, int index) {
	std::size_t pos = who.find('@');
	std::string name = who.substr(0, pos);
	std::string a = name + ".account";

	FILE* f = fopen(a.c_str(), "rb");

	fseek(f, 0, SEEK_END);
	int file_size = ftell(f);
	rewind(f);

	int i = 1;

	unsigned char* buffer = new unsigned char[file_size];
	size_t how_much = fread(buffer, file_size, 1, f);

	char* p = strtok((char*)buffer, "\n");

	while (p != NULL) {

		if (i == index) {
			unsigned char* work = convert_from_hex_string((unsigned char*)p, strlen(p));
			ASN1_email* new_email = ASN1_email_new();
			new_email = d2i_ASN1_email(NULL, (const unsigned char**)&work, strlen(p));
			if (!new_email) {
				std::cout << "Could not parse email!" << std::endl;
				std::cout << ERR_error_string(ERR_get_error(), NULL);
				exit(EXIT_FAILURE);
			}
			std::cout << "FROM: " << ASN1_STRING_get0_data(new_email->s_from) << std::endl;
			std::cout << "TO: " << ASN1_STRING_get0_data(new_email->s_to) << std::endl;
			std::cout << "TITLE: " << ASN1_STRING_get0_data(new_email->s_title) << std::endl;
			std::cout << "TIME_STAMP: " << ASN1_STRING_get0_data(new_email->s_time) << std::endl;

			int len_body = strlen((const char*)ASN1_STRING_get0_data(new_email->s_body));
			unsigned char* body = new unsigned char[len_body];
			memcpy(body, (const char*)ASN1_STRING_get0_data(new_email->s_body), len_body);

			unsigned char* encoded_key = new unsigned char[(4 * RSA_SIZE_BYTES) / 3 + 2];
			memcpy(encoded_key, ASN1_STRING_get0_data(new_email->s_encoded_key), (4 * RSA_SIZE_BYTES) / 3 + 3);

			unsigned char* key = decrypt_sim_key(encoded_key, who);
			int len_mesg;
			unsigned char* mesg = decrypt_body(body, len_body, key, (unsigned char*)ASN1_STRING_get0_data(new_email->s_time), 13, &len_mesg);
			mesg[len_mesg - 1] = '\0';
			std::cout << "MESSAGE: " << mesg << std::endl;

			unsigned char* signature = new unsigned char[RSA_SIZE_BYTES];
			memcpy(signature, (unsigned char*)ASN1_STRING_get0_data(new_email->s_signature), RSA_SIZE_BYTES);

			std::string from(reinterpret_cast <const char*> (ASN1_STRING_get0_data(new_email->s_from)));

			int outt_len;

			verify_signed_body_2(body, len_body, signature, RSA_SIZE_BYTES, from, &outt_len);

			break;

		}
		i++;
		p = strtok(NULL, "\n");
	}
}

int main() {
	std::string decision;

	while (1) {
		std::cout << "DECISION: ";
		std::cin >> decision;
		std::cout << std::endl;
		if (decision == "enrole") {
			std::string email;
			std::cout << "EMAIL: ";
			std::cin >> email;
			enrole_user(email);
		}
		else if (decision == "send" || decision == "Send" || decision == "SEND") {
			std::string from;
			std::string aux;
			std::string to;
			char title[100];
			char message[100];

			size_t title_len;
			size_t messg_len;

			std::cout << "FROM: ";
			std::cin >> from;
			std::cout << std::endl;
			std::cout << "TO: ";
			std::cin >> to;
			std::cout << std::endl;
			std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
			std::cout << "TITLE: ";
			fgets(title, sizeof(title), stdin);
			title[strcspn(title, "\n")] = '\0';
			std::cout << std::endl;
			std::cout << "MESSAGE: ";
			fgets(message, sizeof(message), stdin);
			message[strcspn(message, "\n")] = '\0';
			std::cout << std::endl;
			send_mail(from, to, title, message);
			std::cout << std::endl << "Message successfully sent from: " << from << " to: " << to << std::endl;
		}
		else if (decision == "read") {
			std::string whoami;
			std::cout << "WHO: ";
			std::cin >> whoami;

			int index;
			std::cout << "INDEX: ";
			std::cin >> index;

			read_mail(whoami, index);
		}
		
	}

	

	return 0;
}