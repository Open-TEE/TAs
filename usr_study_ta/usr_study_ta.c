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

struct ac_event {
	struct ac_event *next;
	void *message;
	TEE_Time time;
	uint32_t amount;
};

static struct account {
	struct ac_event *events;
	TEE_Time created;
	struct ac_general_information general_info;
} ac_info;

#define UINT32_t_MAX 0xffffffff

/*
 * Release event
 */
static void free_event(struct ac_event *event)
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
	struct ac_event *rm_event = ac_info.events, *next_event;

	while (rm_event) {
		next_event = rm_event->next;
		free_event(rm_event);
		rm_event = next_event;
	}

	ac_info.general_info.transaction_count = 0;
}

/*
 * Functions add new event
 */
static void add_event(struct ac_event *event)
{
	event->next = ac_info.events;
	ac_info.events = event;
	++ac_info.general_info.transaction_count;
}

static TEE_Result exec_transaction(uint32_t transaction_type,
				   uint32_t paramTypes, TEE_Param *params)
{
	struct ac_event *new_event = NULL;

	/* Check parameter types */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) {
		OT_LOG(LOG_ERR, "Expected currency type as a index 0 parameter")
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_MEMREF_INOUT) {
		OT_LOG(LOG_ERR, "Expected deposit message as a index 1 parameter")
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* First must check if we can complite transaction
	 * 1) overflow
	 * 2) infisiend funds */

	if (params[0].value.a > UINT32_t_MAX - ac_info.general_info.balance) {
		OT_LOG(LOG_ERR, "Transaction not executed due overflow error");
		return TEE_ERROR_OVERFLOW;
	}

	if (transaction_type == USR_STUDY_CMD_WITHDRAW &&
	    ac_info.general_info.balance < params[0].value.a) {
		OT_LOG(LOG_ERR, "Transaction not executed due infisiend funds");
		return TEE_ERROR_GENERIC;
	}

	new_event = TEE_Malloc(sizeof(struct ac_event), 0);
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

	if (transaction_type == USR_STUDY_CMD_DEPOSIT)
		ac_info.general_info.balance += params[0].value.a;
	else
		ac_info.general_info.balance -= params[0].value.a;

	TEE_MemMove(new_event->message, params[1].memref.buffer, params[1].memref.size);

	TEE_GetSystemTime(&new_event->time);

	add_event(new_event);

	return TEE_SUCCESS;
}

static TEE_Result get_status(uint32_t paramTypes, TEE_Param *params)
{
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INOUT) {
		OT_LOG(LOG_ERR, "Expected memref inout as a index 0 parameter")
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size < sizeof(struct ac_general_information)) {
		OT_LOG(LOG_ERR, "Short buffer")
		return TEE_ERROR_SHORT_BUFFER;
	}

	TEE_MemMove(params[0].memref.buffer, &ac_info.general_info,
			sizeof(struct ac_general_information));
	params[0].memref.size = sizeof(struct ac_general_information);

	return TEE_SUCCESS;
}

TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	OT_LOG(LOG_ERR, "Calling the create entry point");

	TEE_GetSystemTime(&ac_info.created);

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
		OT_LOG(LOG_ERR, "Expected account interest rate as a index 0 parameter")
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Initialize account */
	ac_info.general_info.interest_rate = params[0].value.a;
	ac_info.general_info.balance = 0;
	ac_info.events = NULL;

	return TEE_SUCCESS;
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

	case USR_STUDY_CMD_GET_STATUS:
		ret = get_status(paramTypes, params);
		break;

	default:
		OT_LOG(LOG_ERR, "Unknow command");
		ret = TEE_ERROR_GENERIC;
		break;
	}

	return ret;
}
