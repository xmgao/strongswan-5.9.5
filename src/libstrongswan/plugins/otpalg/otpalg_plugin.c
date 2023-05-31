
/*
 * Copyright (C) 2008 Martin Willi
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



#include <library.h>
#include "otpalg_crypter.h"
#include "otpalg_plugin.h"

typedef struct private_otpalg_plugin_t private_otpalg_plugin_t;

/**
 * private data of otpalg_plugin
 */
struct private_otpalg_plugin_t {

	/**
	 * public functions
	 */
	otpalg_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_otpalg_plugin_t *this)
{
	return "otpalg";
}

METHOD(plugin_t, get_features, int,
	private_otpalg_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(CRYPTER, otpalg_crypter_create),
			PLUGIN_PROVIDE(CRYPTER, ENCR_OTP_CBC, 128),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_otpalg_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *otpalg_plugin_create()
{
	private_otpalg_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = destroy,
			},
		},
	);

	return &this->public.plugin;
}

