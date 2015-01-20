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

#ifndef __USR_STUDY_TA_CTRL__
#define __USR_STUDY_TA_CTRL__

struct ac_general_information {
	uint32_t interest_rate;
	uint32_t balance;
	uint32_t transaction_count;
};

/* Commands */
#define	USR_STUDY_CMD_RESERVED		0x00000000
#define USR_STUDY_CMD_WITHDRAW		0x00000001
#define USR_STUDY_CMD_DEPOSIT		0x00000002
#define USR_STUDY_CMD_GET_STATUS	0x00000003

#endif /* __USR_STUDY_TA_CTRL__ */
