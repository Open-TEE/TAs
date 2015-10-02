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

#include "conn_test_ctl.h"
#include "tee_internal_api.h"
#include "tee_logging.h"

#ifdef TA_PLUGIN
#include "tee_ta_properties.h"

/* UUID must be unique */
SET_TA_PROPERTIES(
	{ 0x12345678, 0x8765, 0x4321, { 'T', 'A', 'C', 'O', 'N', 'N', 'T', 'E'} }, /* UUID */
		512, /* dataSize */
		255, /* stackSize */
		1, /* singletonInstance */
		1, /* multiSession */
		0) /* instanceKeepAlive */
#endif





static TEE_Result check_full_treat_params(struct full_fn_params *fn_params,
					  uint32_t paramTypes,
					  TEE_Param *params)
{
	uint32_t i;

	/* Check parameter type */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INOUT) {
		OT_LOG(LOG_ERR, "Expected value inout type as index 0 parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_MEMREF_INOUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_MEMREF_INOUT ||
	    TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_MEMREF_INOUT) {
		OT_LOG(LOG_ERR, "Expected buffer inout type as index 1,2,3 parameter");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Param 0 */
	if (params[0].value.a != IN_VALUE_A) {
		OT_LOG(LOG_ERR, "Not expected parameter at 0 (value a)");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].value.b != IN_VALUE_B) {
		OT_LOG(LOG_ERR, "Not expected parameter at 0 (value b)");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Param 1 & 2 */
	for (i = 1; i < 3; i++) {

		if (SIZE_OF_VEC(fn_params->in_vector) != params[i].memref.size) {
			OT_LOG(LOG_ERR, "Not expected parameter at %u (wrong buffer length)", i);
			return TEE_ERROR_BAD_PARAMETERS;
		}

		if (TEE_MemCompare(fn_params->in_vector, params[1].memref.buffer,
				   params[1].memref.size)) {
			OT_LOG(LOG_ERR, "Not expected parameter at %u (wrong data)", i);
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	/* Param 3, just length */
	if (RAND_BUFFER_SIZE != params[3].memref.size) {
		OT_LOG(LOG_ERR, "Not expected parameter at 3 (wrong buffer length)");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static void fill_full_treat_response(struct full_fn_params *fn_params,
				     TEE_Param *params)
{
	uint32_t i;

	/* Param 0 */
	params[0].value.a = OUT_VALUE_A;
	params[0].value.b = OUT_VALUE_B;

	/* Param 1 & 2 */
	for (i = 1; i < 3; i++) {
		TEE_MemMove(params[i].memref.buffer,
				fn_params->out_vector, SIZE_OF_VEC(fn_params->out_vector));
		params[i].memref.size = SIZE_OF_VEC(fn_params->out_vector);
	}

	/* Param 3 */
	reverse_buffer(params[3].memref.buffer, params[3].memref.size, &params[3].memref.size);
}

static TEE_Result handle_full_treat_params(uint32_t paramTypes,
					   TEE_Param *params)
{
	struct full_fn_params fn_params = {{IN_KNOWN_VECTOR}, {OUT_KNOWN_VECTOR}, {0}, 0};
	TEE_Result tee_rv = TEE_SUCCESS;

	tee_rv = check_full_treat_params(&fn_params, paramTypes, params);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	fill_full_treat_response(&fn_params, params);

	return tee_rv;
}






TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	OT_LOG(LOG_INFO, "Calling the create entry point");

	/* Run storage tests and crypto stuff */

	return TEE_SUCCESS;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{
	OT_LOG(LOG_INFO, "Calling the Destroy entry point");
	/* Run storage tests and crypto stuff */
}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
					      TEE_Param params[4],
					      void **sessionContext)
{
	TEE_Result tee_rv = TEE_SUCCESS;
	sessionContext = sessionContext;

	OT_LOG(LOG_INFO, "Calling the Open session entry point");

	tee_rv = handle_full_treat_params(paramTypes, params);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	/* Run storage tests and crypto stuff */

	return tee_rv;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
	sessionContext = sessionContext;

	OT_LOG(LOG_INFO, "Calling the Close session entry point");
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext,
						uint32_t commandID,
						uint32_t paramTypes,
						TEE_Param params[4])
{
	TEE_Result tee_rv = TEE_SUCCESS;
	sessionContext = sessionContext;
	commandID = commandID;

	tee_rv = handle_full_treat_params(paramTypes, params);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	/* Parser*/

	return TEE_SUCCESS;
}
