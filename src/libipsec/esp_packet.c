/*
 * Copyright (C) 2012-2013 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "esp_packet.h"
#include "sha256hmac.h"
#include <library.h>
#include <utils/debug.h>
#include <crypto/crypters/crypter.h>
#include <crypto/signers/signer.h>
#include <bio/bio_reader.h>
#include <bio/bio_writer.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h> // For malloc, free
#include <pthread.h>

#define EVP_MAX_MD_SIZE 64
#define socket_path "/tmp/my_socket" // 定义本地套接字路径

typedef struct private_esp_packet_t private_esp_packet_t;

/**
 * Private additions to esp_packet_t.
 */
struct private_esp_packet_t
{

	/**
	 * Public members
	 */
	esp_packet_t public;

	/**
	 * Raw ESP packet
	 */
	packet_t *packet;

	/**
	 * Payload of this packet
	 */
	ip_packet_t *payload;

	/**
	 * Next Header info (e.g. IPPROTO_IPIP)
	 */
	uint8_t next_header;
};

#define MAX_DYNAMIC_SPI_COUNT 100 // 设定最大的套接字数量

typedef struct Queue Queue;

typedef struct keyparameter
{
	int range;
	char qkey[64 + 1];
} keyparameter;

typedef struct KeyqueueNode
{
	keyparameter keypara;
	struct KeyqueueNode *next;
} KeyqueueNode;

struct Queue
{
	KeyqueueNode *front;
	KeyqueueNode *rear;
	pthread_mutex_t lock; // 添加锁以保证线程安全
	int count;
};

void init_queue(Queue *queue);

void enqueue(Queue *queue, keyparameter data);

keyparameter dequeue(Queue *queue);

int is_empty(const Queue *queue);

// 初始化队列
void init_queue(Queue *queue)
{
	queue->front = NULL;
	queue->rear = NULL;
	pthread_mutex_init(&queue->lock, NULL); // 初始化锁
	queue->count = 0;
}

// 入队
void enqueue(Queue *queue, keyparameter data)
{
	pthread_mutex_lock(&queue->lock); // 加锁
	KeyqueueNode *new_node = (KeyqueueNode *)malloc(sizeof(KeyqueueNode));
	if (!new_node)
	{
		pthread_mutex_unlock(&queue->lock); // 解锁
		perror("Memory allocation error");
	}
	new_node->keypara = data;
	new_node->next = NULL;
	if (queue->rear)
	{
		queue->rear->next = new_node;
	}
	else
	{
		queue->front = new_node;
	}
	queue->rear = new_node;
	queue->count += 1;
	pthread_mutex_unlock(&queue->lock); // 解锁
}

// 出队
keyparameter dequeue(Queue *queue)
{
	pthread_mutex_lock(&queue->lock); // 加锁
	if (is_empty(queue))
	{
		pthread_mutex_unlock(&queue->lock); // 解锁
		perror("Queue underflow");
	}
	KeyqueueNode *temp = queue->front;
	keyparameter data = temp->keypara;
	queue->front = temp->next;
	if (!queue->front)
	{
		queue->rear = NULL;
	}
	free(temp);
	queue->count -= 1;
	pthread_mutex_unlock(&queue->lock); // 解锁
	return data;
}

// 检查队列是否为空
int is_empty(const Queue *queue)
{
	return queue->front == NULL;
}

// 销毁队列
void destroy_queue(Queue *queue)
{
	free(queue);
	pthread_mutex_destroy(&queue->lock); // 销毁锁
}

typedef struct
{
	int socket_fd;
	uint32_t spi;
	bool key_type;
	int key_lenth;
	char raw_ekey[64 + 1], raw_dkey[64 + 1], old_dkey[64 + 1]; // 记录原始量子密钥
	Queue *encQueue, *decQueue;								   // 加密密钥队列和解密密钥队列
	int ekey_rw, dkey_lw, dkey_rw;							   // 加密右窗口，解密左窗口，解密右窗口
	pthread_mutex_t mutex;									   // 互斥锁变量
} SpiSocketPair;

SpiSocketPair *socket_pairs[MAX_DYNAMIC_SPI_COUNT];
int total_sockets = 0;

// hkdf
void compute_hmac_ex(unsigned char *dest, const uint8_t *key, uint32_t klen, const uint8_t *msg, uint32_t mlen)
{
	uint8_t md[SHA256_DIGESTLEN] = {0};
	HMAC_SHA256_CTX hmac;
	hmac_sha256_init(&hmac, key, klen);
	hmac_sha256_update(&hmac, msg, mlen);
	hmac_sha256_final(&hmac, md);
	memcpy(dest, md, SHA256_DIGESTLEN);
}

void HKDF(const unsigned char *salt, int salt_len,
		  const unsigned char *ikm, int ikm_len,
		  const unsigned char *info, int info_len,
		  unsigned char *okm, int okm_len)
{
	unsigned char prk[EVP_MAX_MD_SIZE];
	compute_hmac_ex(prk, (const uint8_t *)salt, salt_len, (const uint8_t *)ikm, ikm_len);
	unsigned char prev[EVP_MAX_MD_SIZE];
	memset(prev, 0x00, EVP_MAX_MD_SIZE);

	int iter = (okm_len + 31) / 32;

	for (int i = 0; i < iter; i++)
	{
		unsigned char hmac_input[EVP_MAX_MD_SIZE];
		if (i == 0)
		{
			memcpy(hmac_input, info, info_len);
			hmac_input[info_len] = 0x01;
		}
		else
		{
			memcpy(hmac_input, prev, 32);
			memcpy(hmac_input + 32, info, info_len);
			hmac_input[32 + info_len] = i + 1;
		}

		unsigned char hmac_out[EVP_MAX_MD_SIZE];
		compute_hmac_ex(hmac_out, (const uint8_t *)prk, 32, (const uint8_t *)hmac_input, info_len + 32 * (i == 0 ? 0 : 1) + 1);

		memcpy(prev, hmac_out, 32);
		memcpy(okm + i * 32, hmac_out,
			   (i == iter - 1) ? okm_len - i * 32 : 32);
	}
}

void *thread_enckey_preaccess(void *args)
{
	SpiSocketPair *spipair = (SpiSocketPair *)args;
	spipair->encQueue = (Queue *)malloc(sizeof(Queue));
	init_queue(spipair->encQueue); // 初始化加密密钥缓存队列
	int next_seqno = 1;
	while (spipair->encQueue->count < 10) // 大概10ms获取一次密钥，每次更换用时1ms
	{
		char buf[128], rbuf[128];
		sprintf(buf, "getsk %u %d %u 0\n", spipair->spi, spipair->key_lenth, next_seqno);
		int ret = send(spipair->socket_fd, buf, strlen(buf), 0);
		if (ret < 0)
		{
			perror("getsk send error!\n");
			return false;
		}
		ret = read(spipair->socket_fd, rbuf, sizeof(rbuf));
		if (ret < 0)
		{
			perror("getsk read error!\n");
			return false;
		}
		keyparameter keypara;
		int range = 0;
		memcpy(&range, rbuf, sizeof(int));
		next_seqno += range;
		keypara.range = range;
		memcpy(keypara.qkey, rbuf + sizeof(int), spipair->key_lenth);
		enqueue(spipair->encQueue, keypara);
	}
	destroy_queue(spipair->encQueue);
}

void *thread_deckey_preaccess(void *args)
{
	SpiSocketPair *spipair = (SpiSocketPair *)args;
	spipair->decQueue = (Queue *)malloc(sizeof(Queue));
	init_queue(spipair->decQueue); // 初始化加密密钥缓存队列
	int next_seqno = 1;
	while (spipair->decQueue->count < 10)
	{
		char buf[128], rbuf[128];
		sprintf(buf, "getsk %u %d %u 1\n", spipair->spi, spipair->key_lenth, next_seqno);
		int ret = send(spipair->socket_fd, buf, strlen(buf), 0);
		if (ret < 0)
		{
			perror("getsk send error!\n");
			return false;
		}
		ret = read(spipair->socket_fd, rbuf, sizeof(rbuf));
		if (ret < 0)
		{
			perror("getsk read error!\n");
			return false;
		}
		keyparameter keypara;
		int range = 0;
		memcpy(&range, rbuf, sizeof(int));
		next_seqno += range;
		keypara.range = range;
		memcpy(keypara.qkey, rbuf + sizeof(int), spipair->key_lenth);
		enqueue(spipair->decQueue, keypara);
	}
	destroy_queue(spipair->decQueue);
}

/**
 * @description: 派生量子密钥,通过spi和原始密钥派生
 * @param {unsigned char*} key 原始密钥
 * @param {int} next_seqno 序列号
 * @param {int} keysize 密钥长度
 * @return {*} TRUE if 获取成功
 */
static void derive_key(unsigned char *key, int rawkeysize, int next_seqno, int keysize)
{
	unsigned char salt[32] = {0};
	unsigned char info[32];
	unsigned char okm[keysize];
	sprintf(info, "%d", next_seqno);
	HKDF(salt, sizeof(salt) - 1, key, rawkeysize, info, strlen(info), okm, sizeof(okm));
	memcpy(key, okm, keysize);
}

// 为每个SPI,key_type对返回不同的SOCKET
SpiSocketPair *findspipair(uint32_t spi, bool key_type)
{

	// 检查是否已经存在特定SPI
	for (int i = 0; i < total_sockets; ++i)
	{
		if (socket_pairs[i]->spi == spi && socket_pairs[i]->key_type == key_type)
		{
			return socket_pairs[i];
		}
	}

	// 动态分配内存，并存储新的SPI参数
	socket_pairs[total_sockets] = (SpiSocketPair *)malloc(sizeof(SpiSocketPair));
	if (socket_pairs[total_sockets] == NULL)
	{
		perror("Failed to allocate memory");
		return NULL;
	}

	// 创建新的套接字
	int new_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (new_socket_fd == -1)
	{
		perror("Failed to create socket");
		return NULL;
	}
	struct sockaddr_un serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sun_family = AF_UNIX;
	strncpy(serv_addr.sun_path, socket_path, sizeof(serv_addr.sun_path) - 1);

	int connect_result = connect(new_socket_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	if (connect_result == -1)
	{
		perror("getqotpk connect error!\n");
		return NULL;
	}

	// 存储新创建的套接字
	socket_pairs[total_sockets]->socket_fd = new_socket_fd;
	socket_pairs[total_sockets]->spi = spi;
	socket_pairs[total_sockets]->key_type = key_type;
	socket_pairs[total_sockets]->dkey_lw = 0;
	socket_pairs[total_sockets]->dkey_rw = 0;
	socket_pairs[total_sockets]->ekey_rw = 0;
	pthread_mutex_init(&(socket_pairs[total_sockets]->mutex), NULL); // 初始化互斥锁
	++total_sockets;

	return socket_pairs[total_sockets - 1];
}

// TODO
/**
 * @description: 获取量子密钥,通过spi和序列号获取对应的密钥
 * @param {uint32_t} spi spi
 * @param {uint32_t} next_seqno 序列号
 * @param {bool} key_type TRUE表示解密，FALSE表示加密
 * @param {chunk_t} *qk 量子密钥存储
 * @param {size_t} keysize 密钥长度
 * @return {*} TRUE if 获取成功
 */
static bool getqsk(uint32_t spi, uint32_t next_seqno, bool key_type, chunk_t *qk, size_t keysize)
{
	int ret = 0;
	SpiSocketPair *spipair;
	spipair = findspipair(spi, key_type);
	pthread_mutex_lock(&spipair->mutex);
	if (key_type == 0)
	{
		if (next_seqno > spipair->ekey_rw)
		{ // 向km请求密钥和密钥派生参数
			if (spipair->socket_fd == -1)
			{
				// 处理建立连接失败的情况
				perror("establish_connection error!\n");
				return false;
			}
			// 如果是第一个数据包，启动密钥预取线程
			if (next_seqno == 1)
			{
				spipair->key_lenth = keysize;
				pthread_t thread_enckey;
				// 创建子线程
				if (pthread_create(&thread_enckey, NULL, thread_enckey_preaccess, (void *)spipair) != 0)
				{
					perror("pthread_create");
					return false;
				}
				// 线程分离
				if (pthread_detach(thread_enckey) != 0)
				{
					perror("pthread_detach");
					return false;
				}
			}
			while (is_empty(spipair->encQueue))
			{ // 先判断队列是否为空，如果是空，说明参数还未到达队列，进行一定时间的等待
				usleep(1000);
			}
			keyparameter keypara = dequeue(spipair->encQueue); // 正确的密钥参数由一个队列管理
			memcpy(spipair->raw_ekey, keypara.qkey, keysize);
			spipair->ekey_rw += keypara.range;
		}
		pthread_mutex_unlock(&spipair->mutex);
		memcpy(qk->ptr, spipair->raw_ekey, keysize);
		return true;
	}
	else
	{
	loop1:
		if (next_seqno > spipair->dkey_rw)
		{ // 向km请求密钥和密钥派生参数
			if (spipair->socket_fd == -1)
			{
				// 处理建立连接失败的情况
				perror("establish_connection error!\n");
				return false;
			}
			// 如果是第一个数据包，启动密钥预取线程
			if (next_seqno == 1)
			{
				spipair->key_lenth = keysize;
				pthread_t thread_deckey;
				// 创建子线程
				if (pthread_create(&thread_deckey, NULL, thread_deckey_preaccess, (void *)spipair) != 0)
				{
					perror("pthread_create");
					return false;
				}
				// 线程分离
				if (pthread_detach(thread_deckey) != 0)
				{
					perror("pthread_detach");
					return false;
				}
			}
			while (is_empty(spipair->decQueue))
			{ // 先判断队列是否为空，如果是空，说明参数还未到达队列，进行一定时间的等待
				usleep(1000);
			}
			keyparameter keypara = dequeue(spipair->decQueue); // 正确的密钥参数由一个队列管理
			memcpy(spipair->old_dkey, spipair->raw_dkey, keysize);
			memcpy(spipair->raw_dkey, keypara.qkey, keysize);
			spipair->dkey_lw = spipair->dkey_rw;
			spipair->dkey_rw += keypara.range;
			goto loop1;
		}
		pthread_mutex_unlock(&spipair->mutex);
		if (next_seqno > spipair->dkey_lw)
		{
			memcpy(qk->ptr, spipair->raw_dkey, keysize);
			return true;
		}
		else
		{
			memcpy(qk->ptr, spipair->old_dkey, keysize);
			return true;
		}
	}
}

/**
 *获取量子OTP密钥
 *
 * 通过spi和序列号获取对应的密钥
 *
 *
 *
 * @param spi			spi
 * @param next_seqno	序列号
 * @param key_type		TRUE表示解密，FALSE表示加密
 * @param qk			量子密钥存储
 * @param keysize		密钥长度
 * @return				TRUE if 获取成功
 */
static bool getqotpk(uint32_t spi, uint32_t next_seqno, bool key_type, chunk_t *qk, size_t keysize)
{
	u_char rawkey[keysize + 1];
	int ret = 0;
	char buf[128], rbuf[128];
	SpiSocketPair *spipair;
	spipair = findspipair(spi, key_type);
	if (spipair->socket_fd == -1)
	{
		// 处理建立连接失败的情况
		perror("establish_connection error!\n");
		return false;
	}
	sprintf(buf, "getotpk %u %u %d\n", spi, next_seqno, key_type);

	ret = send(spipair->socket_fd, buf, strlen(buf), 0);
	if (ret < 0)
	{
		perror("getotpk send error!\n");
		return false;
	}
	ret = read(spipair->socket_fd, rbuf, sizeof(rbuf));
	if (ret < 0)
	{
		perror("getqotpk read error!\n");
		return false;
	}
	memcpy(rawkey, rbuf, ret);
	derive_key(rawkey, ret, next_seqno, keysize);
	memcpy(qk->ptr, rawkey, keysize);

	return true;
}

/**
 * Forward declaration for clone()
 */
static private_esp_packet_t *esp_packet_create_internal(packet_t *packet);

METHOD(packet_t, set_source, void,
	   private_esp_packet_t *this, host_t *src)
{
	return this->packet->set_source(this->packet, src);
}

METHOD2(esp_packet_t, packet_t, get_source, host_t *,
		private_esp_packet_t *this)
{
	return this->packet->get_source(this->packet);
}

METHOD(packet_t, set_destination, void,
	   private_esp_packet_t *this, host_t *dst)
{
	return this->packet->set_destination(this->packet, dst);
}

METHOD2(esp_packet_t, packet_t, get_destination, host_t *,
		private_esp_packet_t *this)
{
	return this->packet->get_destination(this->packet);
}

METHOD(packet_t, get_data, chunk_t,
	   private_esp_packet_t *this)
{
	return this->packet->get_data(this->packet);
}

METHOD(packet_t, set_data, void,
	   private_esp_packet_t *this, chunk_t data)
{
	return this->packet->set_data(this->packet, data);
}

METHOD(packet_t, get_dscp, uint8_t,
	   private_esp_packet_t *this)
{
	return this->packet->get_dscp(this->packet);
}

METHOD(packet_t, set_dscp, void,
	   private_esp_packet_t *this, uint8_t value)
{
	this->packet->set_dscp(this->packet, value);
}

METHOD(packet_t, get_metadata, metadata_t *,
	   private_esp_packet_t *this, const char *key)
{
	return this->packet->get_metadata(this->packet, key);
}

METHOD(packet_t, set_metadata, void,
	   private_esp_packet_t *this, const char *key, metadata_t *data)
{
	this->packet->set_metadata(this->packet, key, data);
}

METHOD(packet_t, skip_bytes, void,
	   private_esp_packet_t *this, size_t bytes)
{
	return this->packet->skip_bytes(this->packet, bytes);
}

METHOD(packet_t, clone_, packet_t *,
	   private_esp_packet_t *this)
{
	private_esp_packet_t *pkt;

	pkt = esp_packet_create_internal(this->packet->clone(this->packet));
	pkt->payload = this->payload ? this->payload->clone(this->payload) : NULL;
	pkt->next_header = this->next_header;
	return &pkt->public.packet;
}

METHOD(esp_packet_t, parse_header, bool,
	   private_esp_packet_t *this, uint32_t *spi)
{
	bio_reader_t *reader;
	uint32_t seq;

	reader = bio_reader_create(this->packet->get_data(this->packet));
	if (!reader->read_uint32(reader, spi) ||
		!reader->read_uint32(reader, &seq))
	{
		DBG1(DBG_ESP, "failed to parse ESP header: invalid length");
		reader->destroy(reader);
		return FALSE;
	}
	reader->destroy(reader);

	DBG2(DBG_ESP, "parsed ESP header with SPI %.8x [seq %u]", *spi, seq);
	*spi = htonl(*spi);
	return TRUE;
}

/**
 * Check padding as specified in RFC 4303
 */
static bool check_padding(chunk_t padding)
{
	size_t i;

	for (i = 0; i < padding.len; ++i)
	{
		if (padding.ptr[i] != (uint8_t)(i + 1))
		{
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * Remove the padding from the payload and set the next header info
 */
static bool remove_padding(private_esp_packet_t *this, chunk_t plaintext)
{
	uint8_t next_header, pad_length;
	chunk_t padding, payload;
	bio_reader_t *reader;

	reader = bio_reader_create(plaintext);
	if (!reader->read_uint8_end(reader, &next_header) ||
		!reader->read_uint8_end(reader, &pad_length))
	{
		DBG1(DBG_ESP, "parsing ESP payload failed: invalid length");
		goto failed;
	}
	if (!reader->read_data_end(reader, pad_length, &padding) ||
		!check_padding(padding))
	{
		DBG1(DBG_ESP, "parsing ESP payload failed: invalid padding");
		goto failed;
	}
	this->payload = ip_packet_create(reader->peek(reader));
	reader->destroy(reader);
	if (!this->payload)
	{
		DBG1(DBG_ESP, "parsing ESP payload failed: unsupported payload");
		return FALSE;
	}
	this->next_header = next_header;
	payload = this->payload->get_encoding(this->payload);

	DBG3(DBG_ESP, "ESP payload:\n  payload %B\n  padding %B\n  "
				  "padding length = %hhu, next header = %hhu",
		 &payload, &padding,
		 pad_length, this->next_header);
	return TRUE;

failed:
	reader->destroy(reader);
	chunk_free(&plaintext);
	return FALSE;
}

METHOD(esp_packet_t, decrypt, status_t,
	   private_esp_packet_t *this, esp_context_t *esp_context)
{
	bio_reader_t *reader;
	uint32_t spi, seq;
	chunk_t data, iv, icv, aad, ciphertext, plaintext, qk;
	aead_t *aead;

	DESTROY_IF(this->payload);
	this->payload = NULL;

	data = this->packet->get_data(this->packet);
	aead = esp_context->get_aead(esp_context);

	reader = bio_reader_create(data);
	if (!reader->read_uint32(reader, &spi) ||
		!reader->read_uint32(reader, &seq) ||
		!reader->read_data(reader, aead->get_iv_size(aead), &iv) ||
		!reader->read_data_end(reader, aead->get_icv_size(aead), &icv) ||
		reader->remaining(reader) % aead->get_block_size(aead))
	{
		DBG1(DBG_ESP, "ESP decryption failed: invalid length");
		return PARSE_ERROR;
	}
	ciphertext = reader->peek(reader);
	reader->destroy(reader);
	size_t keysize = aead->get_key_size(aead);
	qk = chunk_alloc(keysize);
	if (keysize > 128)
	{
		// 如果密钥长度大于128字节，显然是用的otp加密
		if (!getqotpk(spi, seq, TRUE, &qk, keysize))
		{
			DBG0(DBG_ESP, "get qsk failed!");
			return FAILED;
		}
		else
		{
			if (!aead->set_key(aead, qk))
			{
				DBG0(DBG_ESP, "set quantum key failed!");
				return FAILED;
			}
		}
	}
	else
	{
		if (!getqsk(spi, seq, TRUE, &qk, keysize))
		{
			DBG0(DBG_ESP, "get qsk failed!");
			return FAILED;
		}
		else
		{
			if (!aead->set_key(aead, qk))
			{
				DBG0(DBG_ESP, "set quantum key failed!");
				return FAILED;
			}
		}
	}
	if (!esp_context->verify_seqno(esp_context, seq))
	{
		DBG1(DBG_ESP, "ESP sequence number verification failed:\n  "
					  "src %H, dst %H, SPI %.8x [seq %u]",
			 get_source(this), get_destination(this), spi, seq);
		return VERIFY_ERROR;
	}
	DBG3(DBG_ESP, "ESP decryption:\n  SPI %.8x [seq %u]\n  IV %B\n  "
				  "encrypted %B\n  ICV %B",
		 spi, seq, &iv, &ciphertext, &icv);

	/* include ICV in ciphertext for decryption/verification */
	ciphertext.len += icv.len;
	/* aad = spi + seq */
	aad = chunk_create(data.ptr, 8);

	if (!aead->decrypt(aead, ciphertext, aad, iv, &plaintext))
	{
		DBG1(DBG_ESP, "ESP decryption or ICV verification failed");
		return FAILED;
	}
	esp_context->set_authenticated_seqno(esp_context, seq);

	if (!remove_padding(this, plaintext))
	{
		return PARSE_ERROR;
	}
	chunk_clear(&qk);
	return SUCCESS;
}

/**
 * Generate the padding as specified in RFC4303
 */
static void generate_padding(chunk_t padding)
{
	size_t i;

	for (i = 0; i < padding.len; ++i)
	{
		padding.ptr[i] = (uint8_t)(i + 1);
	}
}

METHOD(esp_packet_t, encrypt, status_t,
	   private_esp_packet_t *this, esp_context_t *esp_context, uint32_t spi)
{
	chunk_t iv, icv, aad, padding, payload, ciphertext, qk;
	bio_writer_t *writer;
	uint32_t next_seqno;
	size_t blocksize, plainlen;
	aead_t *aead;
	iv_gen_t *iv_gen;

	this->packet->set_data(this->packet, chunk_empty);

	if (!esp_context->next_seqno(esp_context, &next_seqno))
	{
		DBG1(DBG_ESP, "ESP encapsulation failed: sequence numbers cycled");
		return FAILED;
	}

	aead = esp_context->get_aead(esp_context);
	size_t keysize = aead->get_key_size(aead);
	qk = chunk_alloc(keysize);
	if (keysize > 128)
	{
		// 如果密钥长度大于128字节，显然是用的otp加密
		if (!getqotpk(spi, next_seqno, FALSE, &qk, keysize))
		{
			DBG0(DBG_ESP, "get qsk failed!");
			return FAILED;
		}
		else
		{
			if (!aead->set_key(aead, qk))
			{
				DBG0(DBG_ESP, "set quantum key failed!");
				return FAILED;
			}
		}
	}
	else
	{
		if (!getqsk(spi, next_seqno, FALSE, &qk, keysize))
		{
			DBG0(DBG_ESP, "get qsk failed!");
			return FAILED;
		}
		else
		{
			if (!aead->set_key(aead, qk))
			{
				DBG0(DBG_ESP, "set quantum key failed!");
				return FAILED;
			}
		}
	}
	iv_gen = aead->get_iv_gen(aead);
	if (!iv_gen)
	{
		DBG1(DBG_ESP, "ESP encryption failed: no IV generator");
		return NOT_FOUND;
	}

	blocksize = aead->get_block_size(aead);
	iv.len = aead->get_iv_size(aead);
	icv.len = aead->get_icv_size(aead);

	/* plaintext = payload, padding, pad_length, next_header */
	payload = this->payload ? this->payload->get_encoding(this->payload)
							: chunk_empty;
	plainlen = payload.len + 2;
	padding.len = pad_len(plainlen, blocksize);
	/* ICV must be on a 4-byte boundary */
	padding.len += pad_len(iv.len + plainlen + padding.len, 4);
	plainlen += padding.len;

	/* len = spi, seq, IV, plaintext, ICV */
	writer = bio_writer_create(2 * sizeof(uint32_t) + iv.len + plainlen +
							   icv.len);
	writer->write_uint32(writer, ntohl(spi));
	writer->write_uint32(writer, next_seqno);

	iv = writer->skip(writer, iv.len);
	if (!iv_gen->get_iv(iv_gen, next_seqno, iv.len, iv.ptr))
	{
		DBG1(DBG_ESP, "ESP encryption failed: could not generate IV");
		writer->destroy(writer);
		return FAILED;
	}

	/* plain-/ciphertext will start here */
	ciphertext = writer->get_buf(writer);
	ciphertext.ptr += ciphertext.len;
	ciphertext.len = plainlen;

	writer->write_data(writer, payload);

	padding = writer->skip(writer, padding.len);
	generate_padding(padding);

	writer->write_uint8(writer, padding.len);
	writer->write_uint8(writer, this->next_header);

	/* aad = spi + seq */
	aad = writer->get_buf(writer);
	aad.len = 8;
	icv = writer->skip(writer, icv.len);

	DBG3(DBG_ESP, "ESP before encryption:\n  payload = %B\n  padding = %B\n  "
				  "padding length = %hhu, next header = %hhu",
		 &payload, &padding,
		 (uint8_t)padding.len, this->next_header);

	/* encrypt/authenticate the content inline */
	if (!aead->encrypt(aead, ciphertext, aad, iv, NULL))
	{
		DBG1(DBG_ESP, "ESP encryption or ICV generation failed");
		writer->destroy(writer);
		return FAILED;
	}

	DBG3(DBG_ESP, "ESP packet:\n  SPI %.8x [seq %u]\n  IV %B\n  "
				  "encrypted %B\n  ICV %B",
		 ntohl(spi), next_seqno, &iv,
		 &ciphertext, &icv);

	this->packet->set_data(this->packet, writer->extract_buf(writer));
	writer->destroy(writer);
	chunk_clear(&qk);
	return SUCCESS;
}

METHOD(esp_packet_t, get_next_header, uint8_t,
	   private_esp_packet_t *this)
{
	return this->next_header;
}

METHOD(esp_packet_t, get_payload, ip_packet_t *,
	   private_esp_packet_t *this)
{
	return this->payload;
}

METHOD(esp_packet_t, extract_payload, ip_packet_t *,
	   private_esp_packet_t *this)
{
	ip_packet_t *payload;

	payload = this->payload;
	this->payload = NULL;
	return payload;
}

METHOD2(esp_packet_t, packet_t, destroy, void,
		private_esp_packet_t *this)
{
	DESTROY_IF(this->payload);
	this->packet->destroy(this->packet);
	free(this);
}

static private_esp_packet_t *esp_packet_create_internal(packet_t *packet)
{
	private_esp_packet_t *this;

	INIT(this,
		 .public = {
			 .packet = {
				 .set_source = _set_source,
				 .get_source = _get_source,
				 .set_destination = _set_destination,
				 .get_destination = _get_destination,
				 .get_data = _get_data,
				 .set_data = _set_data,
				 .get_dscp = _get_dscp,
				 .set_dscp = _set_dscp,
				 .get_metadata = _get_metadata,
				 .set_metadata = _set_metadata,
				 .skip_bytes = _skip_bytes,
				 .clone = _clone_,
				 .destroy = _destroy,
			 },
			 .get_source = _get_source,
			 .get_destination = _get_destination,
			 .get_next_header = _get_next_header,
			 .parse_header = _parse_header,
			 .decrypt = _decrypt,
			 .encrypt = _encrypt,
			 .get_payload = _get_payload,
			 .extract_payload = _extract_payload,
			 .destroy = _destroy,
		 },
		 .packet = packet, .next_header = IPPROTO_NONE, );
	return this;
}

/**
 * Described in header.
 */
esp_packet_t *esp_packet_create_from_packet(packet_t *packet)
{
	private_esp_packet_t *this;

	this = esp_packet_create_internal(packet);

	return &this->public;
}

/**
 * Described in header.
 */
esp_packet_t *esp_packet_create_from_payload(host_t *src, host_t *dst,
											 ip_packet_t *payload)
{
	private_esp_packet_t *this;
	packet_t *packet;

	packet = packet_create_from_data(src, dst, chunk_empty);
	this = esp_packet_create_internal(packet);
	this->payload = payload;
	if (payload)
	{
		this->next_header = payload->get_version(payload) == 4 ? IPPROTO_IPIP
															   : IPPROTO_IPV6;
	}
	else
	{
		this->next_header = IPPROTO_NONE;
	}
	return &this->public;
}
