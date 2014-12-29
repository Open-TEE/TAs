/*****************************************************************************
** Copyright (C) 2014 Mika Tammi                                            **
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
#include "tee_tui_api.h"
#include "tee_logging.h"

#include <memory.h>

TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{

}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4],
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

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
						uint32_t paramTypes, TEE_Param params[4])
{
	sessionContext = sessionContext;
	paramTypes = paramTypes;
	params = params;

	if (commandID == 1) {
		/* TODO: Use Trusted User Interface API to get input from user */
		uint32_t width;
		uint32_t height;
		uint32_t lastindex;

		TEE_TUIScreenOrientation orientation = TEE_TUI_PORTRAIT;
		TEE_TUIScreenInfo screenInfo;

		TEE_TUIScreenConfiguration screenConf;
		TEE_TUIEntryField entryfield;
		TEE_TUIButtonType button;

		char user_id_buffer[256];

		memset(&screenInfo, 0, sizeof(screenInfo));

		memset(&screenConf, 0, sizeof(screenConf));
		memset(&entryfield, 0, sizeof(entryfield));

		screenConf.screenOrientation = orientation;
		screenConf.label.text = "Label Text";
		screenConf.label.textColor[0] = 255;
		screenConf.label.textColor[1] = 128;
		screenConf.label.textColor[2] = 0;
		screenConf.label.image.source = TEE_TUI_NO_SOURCE;
		screenConf.requestedButtons[TEE_TUI_OK] = true;
		screenConf.requestedButtons[TEE_TUI_CANCEL] = true;

		entryfield.label = "User ID";
		entryfield.mode = TEE_TUI_CLEAR_MODE;
		entryfield.buffer = user_id_buffer;
		entryfield.bufferLength = sizeof(user_id_buffer);

		TEE_TUICheckTextFormat("hahaateksti", &width, &height, &lastindex);
		TEE_TUIGetScreenInfo(orientation, 4, &screenInfo);

		OT_LOG(LOG_ERR, "%s", screenInfo.buttonInfo[0].buttonText);

		TEE_TUIInitSession();

		TEE_TUIDisplayScreen(&screenConf, false, &entryfield, 1, &button);

		//TEE_TUICloseSession();

		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}
