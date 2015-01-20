/*****************************************************************************
** Copyright (C) 2015 Intel Corporation.                                    **
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

/* NOTE!!
 *
 * This is implemented for user study. It is serving the purpose of user study!
 * Therefore it might not have the most perfect design choices and implementation.
 *
 * NOTE!!
 */

#include "tee_internal_api.h" /* TA envrionment */
#include "tee_logging.h" /* OpenTEE logging functions */
#include "usr_study_ta_ctrl.h" /* Control structures */

#ifdef TA_PLUGIN
#include "tee_ta_properties.h" /* Setting TA properties */

/* UUID must be unique */
SET_TA_PROPERTIES(
	{ 0x12345678, 0x8765, 0x4321, { 'U', 'S', 'R', 'S', 'T', 'U', 'D', 'Y'} }, /* UUID */
		512, /* dataSize */
		255, /* stackSize */
		1, /* singletonInstance */
		0, /* multiSession */
		1) /* instanceKeepAlive */
#endif

struct account_event {
	struct account_event *next;
	int32_t amount;
	void *message;
};

static struct account_event *account_events;
static uint32_t account_balance;
static uint32_t currency_type;

/*
 * Release event
 */
static void free_event(struct account_event *event)
{
	if (!event)
		return;

	free(event->message);
	free(event);
}

/*
 * Function removes all events
 */
static void rm_all_events()
{
	struct account_event *rm_event = account_events, *next_event;

	while (rm_event) {
		next_event = rm_event->next;
		free_event(rm_event);
		rm_event = next_event;
	}
}

/*
 * Functions add new event
 */
static void add_event(struct account_event *event)
{
	event->next = account_events;
	account_events = event;
}

static TEE_Result exec_transaction(uint32_t transaction_type,
				   uint32_t paramTypes, TEE_Param *params)
{
	struct account_event *new_event = NULL;

	/* Check parameter types */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) {
		OT_LOG(LOG_ERR, "Expected currency type as a index 0 parameter")
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT) {
		OT_LOG(LOG_ERR, "Expected deposit message as a index 1 parameter")
		return TEE_ERROR_BAD_PARAMETERS;
	}

	new_event = TEE_Malloc(sizeof(struct account_event), 0);
	if (!new_event) {
		OT_LOG(LOG_ERR, "Out of memory")
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	new_event->message = TEE_Malloc(params[1].memref.size, 0);
	if (!new_event->message) {
		OT_LOG(LOG_ERR, "Out of memory")
		TEE_Free(new_event);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
}

TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	OT_LOG(LOG_ERR, "Calling the create entry point");

	/* No actions */

	return TEE_SUCCESS;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{
	OT_LOG(LOG_ERR, "Calling the Destroy entry point");

	/* No actions */
}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
					      TEE_Param params[4], void **sessionContext)
{
	OT_LOG(LOG_ERR, "Calling the Open session entry point");

	sessionContext = sessionContext; /* Not used */

	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) {
		OT_LOG(LOG_ERR, "Expected currency type as a index 0 parameter")
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch (params[0].value.a) {
	case USR_STUDY_CUR_X:
	case USR_STUDY_CUR_Y:
	case USR_STUDY_CUR_Z:
		break;
	default:
		OT_LOG(LOG_ERR, "Not supported currency")
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Initialize account */
	currency_type = params[0].value.a;
	account_balance = 0;
	account_events = NULL;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
	OT_LOG(LOG_ERR, "Calling the Close session entry point");

	sessionContext = sessionContext; /* Not used */

	rm_all_events();
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
						uint32_t paramTypes, TEE_Param params[4])
{
	TEE_Result ret;

	OT_LOG(LOG_ERR, "Calling the Invoke command entry point");

	sessionContext = sessionContext; /* Not used */

	switch (commandID) {
	case USR_STUDY_CMD_DEPOSIT:
		ret = exec_transaction(USR_STUDY_CMD_DEPOSIT, paramTypes, params);
		break;

	case USR_STUDY_CMD_WITHDRAW:
		ret = exec_transaction(USR_STUDY_CMD_WITHDRAW, paramTypes, params);
		break;

	case USR_STUDY_CMD_GET_BALANCE:
		ret = get_balance(paramTypes, params);
		break;

	case USR_STUDY_CMD_GET_EVENT: break;
	default:
		OT_LOG(LOG_ERR, "Unknow command");
		ret = TEE_ERROR_GENERIC;
		break;
	}

	return ret;
}
