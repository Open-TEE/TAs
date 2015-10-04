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
#include "tee_logging.h"

/*
 * Commands that are supprted by the TA
 */
#define CMD_CREATE_ROOT_KEY 0x00000001
#define CMD_DO_CRYPTO 0X00000002


/*
 * The OPERATIONS that can be performed by doCrypto
 */
#define OM_OP_ENCRYPT_FILE 0
#define OM_OP_DECRYPT_FILE 1
#define OM_OP_CREATE_DIRECTORY_KEY 2

/*!
 * \brief The key_chain_data struct
 * Structure to hold all of the key hirarachy needed to protect the keys
 */
struct key_chain_data {
	uint32_t key_count;	/*!< The number of keys in the chain */
	uint32_t key_len;	/*!< The size of each key */
	uint8_t keys[];		/*!< The keys themselves */
};


#define BITS2BYTES(bits)	(bits / 8)
#define OMS_RSA_MODULU_SIZE	1024
#define OMS_AES_SIZE		256
#define OMS_AES_IV_SIZE		128


/* Omnishare TEE spesific RSA key is generated once and only once at create entry point function.
 * RSA key is saved into secure storage (ss). */
static TEE_ObjectHandle oms_RSA_keypair_object;

/* Cached root directory AES key */
static TEE_ObjectHandle oms_AES_key_object;

/* Corresponding IV vector. For simplicity sake, the IV vector in every AES operation is kept
 * as a zero and this with AES CTR mode is very very unsecure */
static uint8_t oms_aes_iv[BITS2BYTES(OMS_AES_IV_SIZE)];

#ifdef TA_PLUGIN
#include "tee_ta_properties.h" /* Setting TA properties */

/* UUID must be unique */
SET_TA_PROPERTIES(
{ 0x12345678, 0x8765, 0x4321, { 'O', 'M', 'N', 'I', 'S', 'H', 'A', 'R'} }, /* UUID */
		512, /* dataSize */
		255, /* stackSize */
		1, /* singletonInstance */
		1, /* multiSession */
		1) /* instanceKeepAlive */
#endif







/*
 *
 * Omnishare spesific functions
 *
 */

/*!
 * \brief warp_oms_RSA_operation
 * Function is using OmniShare TA specific key for executing RSA operation.
 * \param mode Supported mode are TEE_MODE_ENCRYPT and TEE_MODE_DECRYPT
 * \param in_data Input data
 * \param in_data_len Input data length
 * \param out_data Ouput data
 * \param out_data_len Output data length
 * \return
 */
static TEE_Result wrap_oms_RSA_operation(TEE_OperationMode mode,
					 void *in_data,
					 uint32_t in_data_len,
					 void *out_data,
					 uint32_t *out_data_len)
{
	TEE_OperationHandle rsa_operation = NULL;
	TEE_Result tee_rv = TEE_SUCCESS;

	tee_rv = TEE_AllocateOperation(&rsa_operation, TEE_ALG_RSAES_PKCS1_V1_5,
				       mode, OMS_RSA_MODULU_SIZE);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateOperation failed: 0x%x", tee_rv);
		goto err;
	}

	tee_rv = TEE_SetOperationKey(rsa_operation, oms_RSA_keypair_object);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_SetOperationKey failed: 0x%x", tee_rv);
		goto err;
	}

	if (mode == TEE_MODE_ENCRYPT) {

		tee_rv = TEE_AsymmetricEncrypt(rsa_operation, NULL, 0, in_data,
					       in_data_len, out_data, out_data_len);
		if (tee_rv != TEE_SUCCESS) {
			OT_LOG(LOG_ERR, "TEE_AsymmetricEncrypt failed : 0x%x", tee_rv);
			goto err;
		}

	} else if (mode == TEE_MODE_DECRYPT) {

		tee_rv = TEE_AsymmetricDecrypt(rsa_operation, NULL, 0, in_data,
					       in_data_len, out_data, out_data_len);
		if (tee_rv != TEE_SUCCESS) {
			OT_LOG(LOG_ERR, "TEE_AsymmetricDecrypt failed : 0x%x", tee_rv);
			goto err;
		}

	} else {
		OT_LOG(LOG_ERR, "Unkown RSA mode type");
		goto err;
	}

err:
	TEE_FreeOperation(rsa_operation);
	return tee_rv;
}

static TEE_Result wrap_aes_operation(TEE_ObjectHandle key,
				     TEE_OperationMode mode,
				     void *in_data,
				     uint32_t in_data_len,
				     void *out_data,
				     uint32_t *out_data_len)
{
	TEE_OperationHandle aes_operation = NULL;
	TEE_Result tee_rv = TEE_SUCCESS;

	tee_rv = TEE_AllocateOperation(&aes_operation, TEE_ALG_AES_CTR, mode, OMS_AES_SIZE);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateOperation failed (TEE_ALG_AES_CTR) : 0x%x", tee_rv);
		goto err;
	}

	tee_rv = TEE_SetOperationKey(aes_operation, key);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_SetOperationKey failed: 0x%x", tee_rv);
		goto err;
	}

	TEE_CipherInit(aes_operation, oms_aes_iv, BITS2BYTES(OMS_AES_IV_SIZE));

	tee_rv = TEE_CipherDoFinal(aes_operation, in_data, in_data_len, out_data, out_data_len);
	if (tee_rv != TEE_SUCCESS)
		OT_LOG(LOG_ERR, "TEE_CipherDoFinal failed: 0x%x", tee_rv);

err:
	TEE_FreeOperation(aes_operation);
	return tee_rv;
}

static TEE_Result create_oms_aes_key(uint8_t *aes_key,
				     uint32_t *aes_key_size,
				     TEE_ObjectHandle *aes_key_object)
{
	TEE_ObjectHandle new_aes_key_object = NULL;
	TEE_Result tee_rv = TEE_SUCCESS;

	tee_rv = TEE_AllocateTransientObject(TEE_TYPE_AES, OMS_AES_SIZE, &new_aes_key_object);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed : 0x%x", tee_rv);
		goto err;
	}

	tee_rv = TEE_GenerateKey(new_aes_key_object, OMS_AES_SIZE, NULL, 0);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_Gener ateKey failed : 0x%x", tee_rv);
		goto err;
	}

	if (aes_key) {

		if (aes_key_size == NULL) {
			OT_LOG(LOG_ERR, "Aes key buffer is not NULL, but key size is NULL");
			tee_rv = TEE_ERROR_BAD_PARAMETERS;
			goto err;
		}

		tee_rv = TEE_GetObjectBufferAttribute(new_aes_key_object, TEE_ATTR_SECRET_VALUE,
						      aes_key, aes_key_size);
		if (tee_rv != TEE_SUCCESS) {
			OT_LOG(LOG_ERR, "TEE_GetObjectBufferAttribute failed: 0x%x", tee_rv);
			goto err;
		}
	}

	if (aes_key_object)
		*aes_key_object = new_aes_key_object;
	else
		TEE_FreeTransientObject(new_aes_key_object);

	return tee_rv;

err:
	TEE_FreeTransientObject(new_aes_key_object);
	if (aes_key && aes_key_size) {
		TEE_MemFill(aes_key, 0, *aes_key_size);
		*aes_key_size = 0;
	}
	return tee_rv;
}

static TEE_Result get_file_key(uint32_t paramTypes,
			       TEE_Param *params,
			       TEE_ObjectHandle *file_key)
{
	uint32_t next_aes_key_size = BITS2BYTES(OMS_AES_SIZE);
	uint8_t next_aes_key[BITS2BYTES(OMS_AES_SIZE)];
	TEE_Attribute tee_aes_attr = {0};
	TEE_Result tee_rv = TEE_SUCCESS;
	struct key_chain_data *key_chain;
	uint32_t i = 0;

	tee_rv = TEE_AllocateTransientObject(TEE_TYPE_AES, OMS_AES_SIZE, file_key);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed: 0x%x", tee_rv);
		goto err;
	}

	TEE_CopyObjectAttributes(*file_key, oms_AES_key_object);

	if (TEE_PARAM_TYPE_GET(paramTypes, 0) == TEE_PARAM_TYPE_NONE)
		return tee_rv;

	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT) {
		OT_LOG(LOG_ERR, "Bad parameter at index 0: expexted memref input");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	key_chain = (struct key_chain_data *)params[0].memref.buffer;

	for (i = 0; i < key_chain->key_count; i++) {

		next_aes_key_size = BITS2BYTES(OMS_AES_SIZE);
		tee_rv = wrap_aes_operation(*file_key, TEE_MODE_DECRYPT,
					    key_chain->keys + (i * BITS2BYTES(OMS_AES_SIZE)),
					    BITS2BYTES(OMS_AES_SIZE),
					    next_aes_key, &next_aes_key_size);
		if (tee_rv != TEE_SUCCESS)
			goto err;

		TEE_ResetTransientObject(*file_key);
		TEE_InitRefAttribute(&tee_aes_attr, TEE_ATTR_SECRET_VALUE,
				     next_aes_key, next_aes_key_size);

		tee_rv = TEE_PopulateTransientObject(*file_key, &tee_aes_attr, 1);
		if (tee_rv != TEE_SUCCESS) {
			OT_LOG(LOG_ERR, "TEE_PopulateTransientObject failed: 0x%x", tee_rv);
			goto err;
		}
	}

	return tee_rv;

err:
	TEE_FreeTransientObject(*file_key);
	return tee_rv;
}

static TEE_Result do_crypto_create_dir_key(TEE_ObjectHandle file_key,
					   TEE_Param *params)
{
	uint32_t aes_key_size = BITS2BYTES(OMS_AES_SIZE);
	uint8_t aes_key[BITS2BYTES(OMS_AES_SIZE)];
	TEE_Result tee_rv = TEE_SUCCESS;

	if (aes_key_size > params[3].memref.size) {
		OT_LOG(LOG_ERR, "Output buffer too short");
		params[3].memref.size = aes_key_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	tee_rv = create_oms_aes_key(aes_key, &aes_key_size, NULL);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	return wrap_aes_operation(file_key, TEE_MODE_ENCRYPT, aes_key, aes_key_size,
				  params[3].memref.buffer, (uint32_t *)&params[3].memref.size);
}

static TEE_Result do_crypto_encrypt_file(TEE_ObjectHandle dir_key,
					 TEE_Param *params)
{
	uint32_t aes_key_size = BITS2BYTES(OMS_AES_SIZE);
	uint8_t aes_key[BITS2BYTES(OMS_AES_SIZE)];
	TEE_ObjectHandle new_file_key = NULL;
	TEE_Result tee_rv = TEE_SUCCESS;
	uint32_t write_bytes = params[3].memref.size;

	if (aes_key_size + params[2].memref.size > params[3].memref.size) {
		OT_LOG(LOG_ERR, "Output buffer too short");
		params[3].memref.size = aes_key_size + params[2].memref.size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	tee_rv = create_oms_aes_key(aes_key, &aes_key_size, &new_file_key);
	if (tee_rv != TEE_SUCCESS)
		goto out;

	tee_rv = wrap_aes_operation(dir_key, TEE_MODE_ENCRYPT, aes_key, aes_key_size,
				    params[3].memref.buffer, &write_bytes);
	if (tee_rv != TEE_SUCCESS)
		goto out;

	params[3].memref.size -= write_bytes;

	tee_rv = wrap_aes_operation(new_file_key, TEE_MODE_ENCRYPT,
				    params[2].memref.buffer, params[2].memref.size,
			(uint8_t *)params[3].memref.buffer + write_bytes,
			(uint32_t *)&params[3].memref.size);

	params[3].memref.size += write_bytes;
out:
	TEE_FreeTransientObject(new_file_key);
	return tee_rv;
}

static TEE_Result do_crypto_decrypt_file(TEE_ObjectHandle dir_key,
					 TEE_Param *params)
{
	uint32_t aes_key_size = BITS2BYTES(OMS_AES_SIZE);
	uint8_t aes_key[BITS2BYTES(OMS_AES_SIZE)];
	TEE_ObjectHandle file_key = NULL;
	TEE_Attribute tee_aes_attr = {0};
	TEE_Result tee_rv;

	if (aes_key_size > params[2].memref.size) {
		OT_LOG(LOG_ERR, "Input buffer too short");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[2].memref.size - aes_key_size > params[3].memref.size) {
		OT_LOG(LOG_ERR, "Output buffer too short");
		params[3].memref.size = aes_key_size + params[2].memref.size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	tee_rv = wrap_aes_operation(dir_key, TEE_MODE_DECRYPT,
				    params[2].memref.buffer, BITS2BYTES(OMS_AES_SIZE),
				    aes_key, &aes_key_size);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	tee_rv = TEE_AllocateTransientObject(TEE_TYPE_AES, OMS_AES_SIZE, &file_key);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed : 0x%x", tee_rv);
		return tee_rv;
	}

	TEE_InitRefAttribute(&tee_aes_attr, TEE_ATTR_SECRET_VALUE, aes_key, aes_key_size);

	tee_rv = TEE_PopulateTransientObject(file_key, &tee_aes_attr, 1);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_PopulateTransientObject failed: 0x%x", tee_rv);
		goto out;
	}

	tee_rv = wrap_aes_operation(file_key, TEE_MODE_DECRYPT,
				    (uint8_t *)params[2].memref.buffer + BITS2BYTES(OMS_AES_SIZE),
			params[2].memref.size - BITS2BYTES(OMS_AES_SIZE),
			params[3].memref.buffer, (uint32_t *)&params[3].memref.size);

out:
	TEE_FreeTransientObject(file_key);
	return tee_rv;
}

static TEE_Result do_crypto(uint32_t paramTypes,
			    TEE_Param *params)
{
	TEE_ObjectHandle file_key = NULL;
	TEE_Result tee_rv = TEE_SUCCESS;

	/* ParamTypes parameter is used for checking parameters type.
	 * It just agreed between CA and TA. */

	/* Crypto operation have commons following parameters. Checking parameters one by one
	 * for purpose of printing debug message */
	if (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_INPUT) {
		OT_LOG(LOG_ERR, "Bad parameter at index 1: expexted value input");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if ((params[1].value.a == OM_OP_ENCRYPT_FILE ||
	     params[1].value.a == OM_OP_DECRYPT_FILE) &&
	    TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_MEMREF_INPUT) {
		OT_LOG(LOG_ERR, "Bad parameter at index 2: expexted memref input");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_MEMREF_OUTPUT) {
		OT_LOG(LOG_ERR, "Bad parameter at index 3: expexted memref output");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	tee_rv = get_file_key(paramTypes, params, &file_key);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	switch (params[1].value.a) {
	case OM_OP_CREATE_DIRECTORY_KEY:
		tee_rv = do_crypto_create_dir_key(file_key, params);
		break;

	case OM_OP_ENCRYPT_FILE:
		tee_rv = do_crypto_encrypt_file(file_key, params);
		break;

	case OM_OP_DECRYPT_FILE:
		tee_rv = do_crypto_decrypt_file(file_key, params);
		break;
	default:
		OT_LOG(LOG_ERR, "Unknown crypto command ID");
		tee_rv = TEE_ERROR_BAD_PARAMETERS;
		break;
	}

	TEE_FreeTransientObject(file_key);
	return tee_rv;
}

static TEE_Result create_root_key(uint32_t paramTypes,
				  TEE_Param *params)
{
	uint32_t aes_key_size = BITS2BYTES(OMS_AES_SIZE);
	uint8_t aes_key[BITS2BYTES(OMS_AES_SIZE)];
	TEE_Result tee_rv = TEE_SUCCESS;

	/* ParamTypes parameter is used for checking parameters type.
	 * It just agreed between CA and TA. */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_OUTPUT) {
		OT_LOG(LOG_ERR, "Bad parameter at index 0: expexted memref output");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (BITS2BYTES(OMS_RSA_MODULU_SIZE) > params[0].memref.size) {
		OT_LOG(LOG_ERR, "Output buffer is too short");
		params[0].memref.size = BITS2BYTES(OMS_RSA_MODULU_SIZE);
		return TEE_ERROR_SHORT_BUFFER;
	}

	tee_rv = create_oms_aes_key(aes_key, &aes_key_size, NULL);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	return wrap_oms_RSA_operation(TEE_MODE_ENCRYPT, aes_key, aes_key_size,
				      params[0].memref.buffer, (uint32_t *)&params[0].memref.size);
}


static TEE_Result set_oms_aes_key(TEE_Param *params)
{
	uint32_t aes_key_size = BITS2BYTES(OMS_RSA_MODULU_SIZE);
	uint8_t aes_key[BITS2BYTES(OMS_RSA_MODULU_SIZE)];
	TEE_Attribute tee_aes_attr = {0};
	TEE_Result tee_rv = TEE_SUCCESS;

	tee_rv = wrap_oms_RSA_operation(TEE_MODE_DECRYPT, params[0].memref.buffer,
			params[0].memref.size, aes_key, &aes_key_size);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	if (aes_key_size != BITS2BYTES(OMS_AES_SIZE)) {
		OT_LOG(LOG_ERR, "RSA decrypted AES key is wrong sized");
		return TEE_ERROR_GENERIC;
	}

	tee_rv = TEE_AllocateTransientObject(TEE_TYPE_AES, OMS_AES_SIZE, &oms_AES_key_object);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed: 0x%x", tee_rv);
		return tee_rv;
	}

	TEE_InitRefAttribute(&tee_aes_attr, TEE_ATTR_SECRET_VALUE, aes_key, aes_key_size);

	tee_rv = TEE_PopulateTransientObject(oms_AES_key_object, &tee_aes_attr, 1);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_PopulateTransientObject failed: 0x%x", tee_rv);
		TEE_FreeTransientObject(oms_AES_key_object);
	}

	return tee_rv;
}






/*
 *
 * TEE Core API defined five entry point functions
 *
 */
TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	char oms_rsa_keypair_id[] = "oms_rsa_keypair_object_id";
	TEE_ObjectHandle rsa_keypair = NULL;
	TEE_Result tee_rv = TEE_SUCCESS;

	tee_rv = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					  oms_rsa_keypair_id, sizeof(oms_rsa_keypair_id),
					  0, &oms_RSA_keypair_object);
	if (tee_rv == TEE_SUCCESS) {
		return tee_rv;
	} else if (tee_rv == TEE_ERROR_ITEM_NOT_FOUND) {
		/* OK: It just is that the object is not found and therefore it need to be created*/
	} else {
		OT_LOG(LOG_ERR, "TEE_OpenPersistentObject failed: 0x%x", tee_rv);
		return tee_rv;
	}

	tee_rv = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR,
					     OMS_RSA_MODULU_SIZE, &rsa_keypair);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed: 0x%x", tee_rv);
		goto out;
	}

	tee_rv = TEE_GenerateKey(rsa_keypair, OMS_RSA_MODULU_SIZE, NULL, 0);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_GenerateKey failed: 0x%x", tee_rv);
		goto out;
	}

	tee_rv = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					    oms_rsa_keypair_id, sizeof(oms_rsa_keypair_id),
					    0, rsa_keypair, NULL, 0, &oms_RSA_keypair_object);
	if (tee_rv != TEE_SUCCESS)
		OT_LOG(LOG_ERR, "TEE_CreatePersistentObject failed: 0x%x", tee_rv);

out:
	TEE_FreeTransientObject(rsa_keypair);
	return tee_rv;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{
	TEE_CloseObject(oms_RSA_keypair_object);
}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
					      TEE_Param params[4],
void **sessionContext)
{
	sessionContext = sessionContext; /* Not used */

	/* Using paramTypes for determing the open session type (create root key or crypto
	 * operation). This is one way of doing this, because in this case we have only two
	 * possible options. Another way is just use one of the parameters for determining
	 * open session type */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) == TEE_PARAM_TYPE_NONE &&
	    TEE_PARAM_TYPE_GET(paramTypes, 1) == TEE_PARAM_TYPE_NONE &&
	    TEE_PARAM_TYPE_GET(paramTypes, 2) == TEE_PARAM_TYPE_NONE &&
	    TEE_PARAM_TYPE_GET(paramTypes, 3) == TEE_PARAM_TYPE_NONE) {
		/* Create root directory, no action */
		return TEE_SUCCESS;

	} else if (TEE_PARAM_TYPE_GET(paramTypes, 0) == TEE_PARAM_TYPE_MEMREF_INPUT &&
		   TEE_PARAM_TYPE_GET(paramTypes, 1) == TEE_PARAM_TYPE_NONE &&
		   TEE_PARAM_TYPE_GET(paramTypes, 2) == TEE_PARAM_TYPE_NONE &&
		   TEE_PARAM_TYPE_GET(paramTypes, 3) == TEE_PARAM_TYPE_NONE) {
		return set_oms_aes_key(params);

	} else {
		OT_LOG(LOG_ERR, "Bad parameter at params: not know combination : 0x%x", paramTypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
	sessionContext = sessionContext;

	TEE_FreeTransientObject(oms_AES_key_object);
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext,
						uint32_t commandID,
						uint32_t paramTypes,
						TEE_Param params[4])
{
	sessionContext = sessionContext; /* Not used */

	switch (commandID) {
	case CMD_CREATE_ROOT_KEY:
		return create_root_key(paramTypes, params);

	case CMD_DO_CRYPTO:
		return do_crypto(paramTypes, params);

	default:
		OT_LOG(LOG_ERR, "Unknown command ID");
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
