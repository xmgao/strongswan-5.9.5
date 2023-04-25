
/* Otp as implemented from 'Otp: Springer-Verlag paper'
 * (From LECTURE NOTES IN COMPUTER SCIENCE 809, FAST SOFTWARE ENCRYPTION,
 * CAMBRIDGE SECURITY WORKSHOP, CAMBRIDGE, U.K., DECEMBER 9-11, 1993)
 */

#include "otp_crypter.h"

typedef struct private_otp_crypter_t private_otp_crypter_t;

/**
 * Class implementing the Otp symmetric encryption algorithm.
 */
struct private_otp_crypter_t {

	/**
	 * Public part of this class.
	 */
	otp_crypter_t public;

	/*
	 * the key
	 */
	chunk_t	key;

};

/**
 * Encrypt  data.
 * in: date to encrypt or decrypt
 * out: date to output
 * len: date lenth
 * key: otp key
 * key_len:otp key lenth
 * enc_flag:    1,encrypt;0,decrypt
 */
static void OTP_encrypt( const unsigned char* in, unsigned char* out,unsigned int len,unsigned char *key,unsigned int key_len,bool enc_flag)
{
    if(enc_flag){
        for (int i = 0; i < len; i++) {
            out[i] = (in[i] + key[i%key_len]) % 256;
        }
    }

    else{
        for (int i = 0; i < len; i++) {
            out[i] = (in[i]-key[i%key_len] + 256) % 256;
        }
    }
}


METHOD(crypter_t, decrypt, bool,
	private_otp_crypter_t *this, chunk_t data, chunk_t iv,
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

	OTP_encrypt(in, out, data.len, this->key.ptr,this->key.len,0);


	return TRUE;
}

METHOD(crypter_t, encrypt, bool,
	private_otp_crypter_t *this, chunk_t data, chunk_t iv,
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

	OTP_encrypt(in, out, data.len, this->key.ptr,this->key.len,1);


	return TRUE;
}

METHOD(crypter_t, get_block_size, size_t,
	private_otp_crypter_t *this)
{
	return OTP_BLOCK_SIZE;
}

METHOD(crypter_t, get_iv_size, size_t,
	private_otp_crypter_t *this)
{
	return OTP_BLOCK_SIZE;
}

METHOD(crypter_t, get_key_size, size_t,
	private_otp_crypter_t *this)
{
	return 1024;
}

METHOD(crypter_t, set_key, bool,
	private_otp_crypter_t *this, chunk_t key)
{   
    chunk_clear(&this->key);
    this->key = chunk_alloc(key.len);
	memcpy(this->key.ptr, key.ptr, key.len);
    //this->key=chunk_create(key.ptr,key.len);
	return TRUE;
}

METHOD(crypter_t, destroy, void,
	private_otp_crypter_t *this)
{   
    chunk_clear(&this->key);
	free(this);
}

/*
 * Described in header
 */
otp_crypter_t *otpalg_crypter_create(encryption_algorithm_t algo,
											size_t key_size)
{
	private_otp_crypter_t *this;

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
		},
	);
    this->key = chunk_alloc(key_size);
	return &this->public;
}
