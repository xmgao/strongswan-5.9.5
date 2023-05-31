/**
 * @defgroup otpalg_p otpalg
 * @ingroup plugins
 *
 * @defgroup otpalg_plugin otpalg_plugin
 * @{ @ingroup otpalg_p
 */

#ifndef OTPALG_PLUGIN_H_
#define OTPALG_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct otpalg_plugin_t otpalg_plugin_t;

/**
 * Plugin implementing crypto functions via the otpalg library
 */
struct otpalg_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** OTPALG_PLUGIN_H_ @}*/
