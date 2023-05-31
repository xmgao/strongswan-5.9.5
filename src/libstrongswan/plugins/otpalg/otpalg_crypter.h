/*
 * Copyright (C) 2005-2008 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

/**
 * @defgroup otpalg_crypter otpalg_crypter
 * @{ @ingroup otpalg_p
 */

#ifndef OTP_CRYPTER_H_
#define OTP_CRYPTER_H_

typedef struct otpalg_crypter_t otpalg_crypter_t;

#include <crypto/crypters/crypter.h>

/**
 * Class implementing the OTP encryption algorithm.
 */
struct otpalg_crypter_t {

	/**
	 * Implements crypter_t interface.
	 */
	crypter_t crypter;
};

/**
 * Constructor to create otpalg_crypter_t objects.
 *
 * @param key_size		key size in bytes
 * @param algo			algorithm to implement
 * @return				otpalg_crypter_t object, NULL if not supported
 */
otpalg_crypter_t *otpalg_crypter_create(encryption_algorithm_t algo,
								  size_t key_size);

#endif /** OTP_CRYPTER_H_ @}*/
