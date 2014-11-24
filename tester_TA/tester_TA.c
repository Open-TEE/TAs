#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "tee_internal_api.h" /* TA envrionment */
#include "tee_logging.h" /* OpenTEE logging functions */

#ifdef TA_PLUGIN
#include "tee_ta_properties.h" /* Setting TA properties */

/* UUID must be unique */
SET_TA_PROPERTIES(
    { 0x12345678, 0x8765, 0x4321, { 'T', 'E', 'S', 'T', 'E', 'R', '0', '0'} }, /* UUID */
        512, /* dataSize */
        255, /* stackSize */
        1, /* singletonInstance */
        1, /* multiSession */
        1) /* instanceKeepAlive */
#endif

/* SHA1 TA command IDs for this applet */
#define SHA1_UPDATE	0x00000001
#define SHA1_DO_FINAL	0x00000002

TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
    OT_LOG(LOG_ERR, "Calling the create entry point");

    /* No functionality */

    return TEE_SUCCESS;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{
    OT_LOG(LOG_ERR, "Calling the Destroy entry point");

    /* No functionality */
}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
                          TEE_Param params[4], void **sessionContext)
{
    /* Only session ctx is needed */
    paramTypes = paramTypes;
    params = params;

    OT_LOG(LOG_ERR, "Calling the Open session entry point");

    return TEE_AllocateOperation((TEE_OperationHandle *)sessionContext,
                     TEE_ALG_SHA1, TEE_MODE_DIGEST, 0);
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
    OT_LOG(LOG_ERR, "Calling the Close session entry point");

    TEE_FreeOperation(sessionContext);
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
                        uint32_t paramTypes, TEE_Param params[4])
{
    paramTypes = paramTypes;
    uint i;
    OT_LOG(LOG_ERR, "Calling the Invoke command entry point");

    OT_LOG(LOG_ERR, "buffer in TA: ");
    OT_LOG(LOG_ERR, "buffer size:");
    OT_LOG_INT(params[2].value.a);
    char* buffer = params[0].memref.buffer;
    for(i = 0; i < params[2].value.a; ++i) {
        OT_LOG(LOG_ERR, "%02x", buffer[i]);
    }
    if (commandID == SHA1_UPDATE) {

        TEE_DigestUpdate(sessionContext, params[0].memref.buffer, params[2].value.a);

    } else if (commandID == SHA1_DO_FINAL) {

        return TEE_DigestDoFinal(sessionContext, params[0].memref.buffer,
                params[2].value.a, params[1].memref.buffer,
                (uint32_t *)&params[1].memref.size);

    } else {
        OT_LOG(LOG_ERR, "Unknow command ID");
    }

    return TEE_SUCCESS;
}
