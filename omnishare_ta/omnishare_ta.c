/*****************************************************************************
** Copyright (C) 2015 Tanel Dettenborn                                      **
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

#include "tee_internal_api.h"

#ifdef TA_PLUGIN
#include "tee_ta_properties.h" /* Setting TA properties */

/* UUID must be unique */
SET_TA_PROPERTIES(
	{ 0x12345678, 0x8765, 0x4321, { 'O', 'M', 'N', 'I', 'S', 'H', 'A', 'R'} }, /* UUID */
		512, /* dataSize */
		255, /* stackSize */
		0, /* singletonInstance */
		1, /* multiSession */
		0) /* instanceKeepAlive */
#endif

TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{

}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
					      TEE_Param params[4],
					      void **sessionContext)
{
	paramTypes = paramTypes;
	params = params;
	sessionContext = sessionContext;

	return TEE_SUCCESS;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
	sessionContext = sessionContext;
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext,
						uint32_t commandID,
						uint32_t paramTypes,
						TEE_Param params[4])
{
	sessionContext = sessionContext;
	commandID = commandID;
	paramTypes = paramTypes;
	params = params;

	return TEE_SUCCESS;
}
