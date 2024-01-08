
/* OTP as implemented from 'OTP: Springer-Verlag paper'
 * (From LECTURE NOTES IN COMPUTER SCIENCE 809, FAST SOFTWARE ENCRYPTION,
 * CAMBRIDGE SECURITY WORKSHOP, CAMBRIDGE, U.K., DECEMBER 9-11, 1993)
 */

#include "otpalg_crypter.h"

typedef struct private_otpalg_crypter_t private_otpalg_crypter_t;

/**
 * Class implementing the OTP symmetric encryption algorithm.
 */
struct private_otpalg_crypter_t
{

	/**
	 * Public part of this class.
	 */
	otpalg_crypter_t public;

	/*
	 * the key
	 */
	chunk_t key;
};

/**
 * Encrypt  data.
 * in: date to encrypt or decrypt
 * out: date to output
 * len: date lenth
 * key: otpalg key
 * key_len:otpalg key lenth
 * enc_flag:    1,encrypt;0,decrypt
 */
static void OTP_encrypt(const unsigned char *in, unsigned char *out, unsigned int len, unsigned char *key, unsigned int key_len)
{
	for (int i = 0; i < len && i < key_len; i++)
	{
		out[i] = in[i] ^ key[i];
	}
}

METHOD(crypter_t, decrypt, bool,
	   private_otpalg_crypter_t *this, chunk_t data, chunk_t iv,
	   chunk_t *decrypted)
{
	uint8_t *in, *out;

	if (decrypted)
	{
		*decrypted = chunk_alloc(data.len);
		out = decrypted->ptr;
	}
	else
	{
		out = data.ptr;
	}
	in = data.ptr;

	OTP_encrypt(in, out, data.len, this->key.ptr, this->key.len);

	return TRUE;
}

METHOD(crypter_t, encrypt, bool,
	   private_otpalg_crypter_t *this, chunk_t data, chunk_t iv,
	   chunk_t *encrypted)
{
	uint8_t *in, *out;

	if (encrypted)
	{
		*encrypted = chunk_alloc(data.len);
		out = encrypted->ptr;
	}
	else
	{
		out = data.ptr;
	}
	in = data.ptr;

	OTP_encrypt(in, out, data.len, this->key.ptr, this->key.len);

	return TRUE;
}

METHOD(crypter_t, get_block_size, size_t,
	   private_otpalg_crypter_t *this)
{
	return OTP_BLOCK_SIZE;
}

METHOD(crypter_t, get_iv_size, size_t,
	   private_otpalg_crypter_t *this)
{
	return OTP_BLOCK_SIZE;
}

METHOD(crypter_t, get_key_size, size_t,
	   private_otpalg_crypter_t *this)
{
	return 1480;
}

METHOD(crypter_t, set_key, bool,
	   private_otpalg_crypter_t *this, chunk_t key)
{
	chunk_clear(&this->key);
	this->key = chunk_alloc(key.len);
	memcpy(this->key.ptr, key.ptr, key.len);
	// this->key=chunk_create(key.ptr,key.len);
	return TRUE;
}

METHOD(crypter_t, destroy, void,
	   private_otpalg_crypter_t *this)
{
	chunk_clear(&this->key);
	free(this);
}

/*
 * Described in header
 */
otpalg_crypter_t *otpalg_crypter_create(encryption_algorithm_t algo,
										size_t key_size)
{
	private_otpalg_crypter_t *this;

	// if (algo != ENCR_OTP_CBC)
	// {
	// 	return NULL;
	// }

	INIT(this,
		 .public = {
			 .crypter = {
				 .encrypt = _encrypt,
				 .decrypt = _decrypt,
				 .get_block_size = _get_block_size,
				 .get_iv_size = _get_iv_size,
				 .get_key_size = _get_key_size,
				 .set_key = _set_key,
				 .destroy = _destroy,
			 },
		 }, );
	this->key = chunk_alloc(key_size);
	return &this->public;
}
