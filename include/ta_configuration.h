/*****************************************************************************
** Copyright (C) 2013 Intel Corporation.                                    **
**                                                                          **
** Licensed under the Apache License, Version 2.0 (the "License");          **
** you may not use this file except in compliance with the License.         **
** You may obtain a copy of the License at                                  **
**                                                                          **
**      http://www.apache.org/licenses/LICENSE-2.0                          **
**                                                                          **
** Unless required by applicable law or agreed to in writing, software      **
** distributed under the License is distributed on an "AS IS" BASIS,        **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and      **
** limitations under the License.                                           **
*****************************************************************************/

#ifndef __TEE_TA_CONFIGURATION_H__
#define __TEE_TA_CONFIGURATION_H__

#include "tee_internal_api.h"
#include <stdbool.h>

/*!
 * \brief The gpd_ta_config struct
 * This structure defines the Standard Configuration Properties of an applet as outlined in
 * table 4-11 of the Internal API spec
 */
struct gpd_ta_config {
	TEE_UUID appID;
	size_t dataSize;
	size_t stackSize;
	bool singletonInstance;
	bool multiSession;
	bool instanceKeepAlive;
};

#endif
