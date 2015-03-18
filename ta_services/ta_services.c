/*****************************************************************************
** Copyright (C) 2015 Roni Jaakkola.                                        **
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
#include "tee_logging.h"
#include "ta_services_ctrl.h"

#include <string.h>

#ifdef TA_PLUGIN
#include "tee_ta_properties.h"

SET_TA_PROPERTIES({0x3E93632E, 0xA710, 0x469E, {'C', 'O', 'U', 'N', 'T', 'E', 'R'}}, 512, 255, 1, 1,
		  1)
#endif

/* Persistent object ID */
static uint32_t object_id = 0x12345678;

static uint64_t get_counter_value()
{
	TEE_ObjectHandle counter;
	TEE_Result ret;
	uint64_t buffer = 0;
	uint64_t counter_value = 0;
	uint32_t bytes_read;

	/* Open the object here if it exists */
	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &object_id, sizeof(object_id),
				       TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE,
				       &counter);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_OpenPersistentObject failed: 0x%x", ret);
	} else {
		OT_LOG(LOG_ERR, "TEE_OpenPersistentObject succesful");

		ret = TEE_ReadObjectData(counter, (void *)&buffer, sizeof(uint64_t), &bytes_read);
		counter_value = buffer;

		/* Increment the value */
		++buffer;

		OT_LOG(LOG_ERR, "New counter value: %d", (int)buffer);

		/* Set data position back to the start of object */
		ret = TEE_SeekObjectData(counter, 0, TEE_DATA_SEEK_SET);
		if (ret != TEE_SUCCESS) {
			OT_LOG(LOG_ERR, "TEE_SeekObjectData failed: 0x%x", ret);
		}

		/* Write the new counter value back to the persistent object */
		ret = TEE_WriteObjectData(counter, (void *)&buffer, sizeof(uint64_t));
		if (ret != TEE_SUCCESS) {
			OT_LOG(LOG_ERR, "TEE_WriteObjectData failed: 0x%x\n", ret);
		}
	}

	TEE_CloseObject(counter);
	return counter_value;
}

TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	TEE_Result ret;
	uint64_t initial_value = 0;
	TEE_ObjectHandle counter;

	OT_LOG(LOG_ERR, "Calling the create entry point");

	OT_LOG(LOG_ERR, "Creating persistent object");

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &object_id, sizeof(object_id),
					 TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE,
					 NULL, &initial_value, sizeof(initial_value), &counter);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_CreatePersistentObject failed: 0x%x", ret);
	} else {
		OT_LOG(LOG_ERR, "TEE_CreatePersistentObject succesful");
	}

	TEE_CloseObject(counter);
	return TEE_SUCCESS;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{
	OT_LOG(LOG_ERR, "Calling the Destroy entry point");
}

TEE_Result TA_EXPORT
TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4], void **sessionContext)
{
	paramTypes = paramTypes;
	sessionContext = sessionContext;
	params = params;

	OT_LOG(LOG_ERR, "Calling the Open session entry point");

	return TEE_SUCCESS;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
	sessionContext = sessionContext;

	OT_LOG(LOG_ERR, "Calling the Close session entry point");
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
						uint32_t paramTypes, TEE_Param params[4])
{
	TEEC_Result ret = TEEC_SUCCESS;
	sessionContext = sessionContext;
	commandID = commandID;
	paramTypes = paramTypes;
	params = params;
	uint64_t *mem_data = (uint64_t *)(params[0].memref.buffer);

	OT_LOG(LOG_ERR, "Calling the Invoke command entry point");

	switch (commandID) {
	case CMD_GET_CTR:
		OT_LOG(LOG_ERR, "Command: GetCounter");
		*mem_data = get_counter_value();
		break;

	default:
		OT_LOG(LOG_ERR, "Unknown command");
		TEE_Free(&sessionContext);
		break;
	}

	return ret;
}
