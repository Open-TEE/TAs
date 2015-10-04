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
#define OM_OP_CREATE_ROOT_DIRECTORY 3

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
static TEE_ObjectHandle oms_RSA_keypair_handle = NULL;

/* Cached root directory AES key */
static TEE_ObjectHandle oms_AES_key_handle = NULL;

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
 * Omnishare spesific functions
 */

static TEE_Result warp_oms_RSA_operation(TEE_OperationMode mode,
					 void *in_data,
					 uint32_t in_data_len,
					 void *out_data,
					 uint32_t *out_data_len)
{
	TEE_OperationHandle rsa_operation = NULL;
	TEE_Result tee_rv = TEE_SUCCESS;

	tee_rv = TEE_AllocateOperation(&rsa_operation, TEE_ALG_RSAES_PKCS1_V1_5, mode, OMS_RSA_MODULU_SIZE);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateOperation failed (TEE_ALG_RSAES_PKCS1_V1_5) : 0x%x", tee_rv);
		goto err;
	}

	tee_rv = TEE_SetOperationKey(rsa_operation, oms_RSA_keypair_handle);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_SetOperationKey failed (oms_RSA_keypair_handle) : 0x%x", tee_rv);
		goto err;
	}

	if (mode == TEE_MODE_ENCRYPT) {

		tee_rv = TEE_AsymmetricEncrypt(rsa_operation, NULL, 0, in_data, in_data_len, out_data, out_data_len);
		if (tee_rv != TEE_SUCCESS) {
			OT_LOG(LOG_ERR, "TEE_AsymmetricEncrypt failed : 0x%x", tee_rv);
			goto err;
		}

	} else if (mode == TEE_MODE_ENCRYPT) {

		tee_rv = TEE_AsymmetricDecrypt(rsa_operation, NULL, 0, in_data, in_data_len, out_data, out_data_len);
		if (tee_rv != TEE_SUCCESS) {
			OT_LOG(LOG_ERR, "TEE_AsymmetricEncrypt failed : 0x%x", tee_rv);
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

static TEE_Result warp_aes_operation(TEE_ObjectHandle key,
				     TEE_OperationMode mode,
				     void *in_data,
				     uint32_t in_data_len,
				     void *out_data,
				     uint32_t *out_data_len)
{
	TEE_OperationHandle aes_operation = NULL;
	TEE_Result tee_rv = TEE_SUCCESS;

	tee_rv = TEE_AllocateOperation(&aes_operation, TEE_ALG_AES_CTR, mode, OMS_RSA_MODULU_SIZE);
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
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_CipherDoFinal failed: 0x%x", tee_rv);
		goto err;
	}

err:
	TEE_FreeOperation(aes_operation);
	return tee_rv;
}

static TEE_Result create_oms_aes_key(uint8_t *aes_key,
				     uint32_t *aes_key_size)
{
	TEE_ObjectHandle new_aes_key_handle = NULL;
	TEE_Result tee_rv = TEE_SUCCESS;

	if (BITS2BYTES(OMS_AES_SIZE) > *aes_key_size) {
		OT_LOG(LOG_ERR, "Aes key buffer too short");
		*aes_key_size = BITS2BYTES(OMS_AES_SIZE);
		return TEE_ERROR_SHORT_BUFFER;
	}

	tee_rv = TEE_AllocateTransientObject(TEE_TYPE_AES, OMS_AES_SIZE, &new_aes_key_handle);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed : 0x%x", tee_rv);
		goto err;
	}

	tee_rv = TEE_GenerateKey(new_aes_key_handle, OMS_AES_SIZE, NULL, 0);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_GenerateKey failed : 0x%x", tee_rv);
		goto err;
	}

	tee_rv = TEE_GetObjectBufferAttribute(new_aes_key_handle, TEE_ATTR_SECRET_VALUE, aes_key, (size_t *)aes_key_size);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_GetObjectBufferAttribute failed (aes_key_handle) : 0x%x", tee_rv);
		TEE_MemFill(aes_key, 0, *aes_key_size);
		goto err;
	}
err:
	TEE_FreeTransientObject(new_aes_key_handle);
	return tee_rv;
}

static TEE_Result get_file_key(struct key_chain_data *key_chain,
			       TEE_ObjectHandle *file_key)
{
	uint32_t next_aes_key_size = BITS2BYTES(OMS_AES_SIZE);
	char next_aes_key[BITS2BYTES(OMS_AES_SIZE)];
	TEE_Result tee_rv = TEE_SUCCESS;
	TEE_Attribute aes_attr = {0};
	uint32_t i = 0;

	tee_rv = TEE_AllocateTransientObject(TEE_TYPE_AES, OMS_AES_SIZE, file_key);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed: 0x%x", tee_rv);
		goto err;
	}

	TEE_CopyObjectAttributes(*file_key, oms_AES_key_handle);

	do {
		tee_rv = warp_aes_operation(*file_key, TEE_MODE_DECRYPT,
					    key_chain->keys + (i * OMS_AES_SIZE), OMS_AES_SIZE,
					    next_aes_key, &next_aes_key_size);
		if (tee_rv != TEE_SUCCESS)
			goto err;

		TEE_ResetTransientObject(*file_key);
		TEE_InitRefAttribute(&aes_attr, TEE_ATTR_SECRET_VALUE, next_aes_key, next_aes_key_size);

		tee_rv = TEE_PopulateTransientObject(*file_key, &aes_attr, 1);
		if (tee_rv != TEE_SUCCESS) {
			OT_LOG(LOG_ERR, "TEE_PopulateTransientObject failed: 0x%x", tee_rv);
			goto err;
		}

	} while (i < key_chain->key_count);

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

	tee_rv = create_oms_aes_key(aes_key, &aes_key_size);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	return warp_aes_operation(file_key, TEE_MODE_ENCRYPT, aes_key, aes_key_size,
				  params[3].memref.buffer, (uint32_t *)&params[3].memref.size);
}

static TEE_Result do_crypto_encrypt_file(TEE_ObjectHandle file_key,
					 uint32_t paramTypes,
					 TEE_Param *params)
{
	uint32_t aes_key_size = BITS2BYTES(OMS_AES_SIZE);
	uint8_t aes_key[BITS2BYTES(OMS_AES_SIZE)];
	TEE_Result tee_rv = TEE_SUCCESS;
	uint32_t write_bytes = params[3].memref.size;

	/* Encrypt function is expecting source data */
	if (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_MEMREF_INPUT) {
		OT_LOG(LOG_ERR, "Bad parameter at index 2: expexted memref input");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	tee_rv = create_oms_aes_key(aes_key, &aes_key_size);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	tee_rv = warp_aes_operation(file_key, TEE_MODE_ENCRYPT, aes_key, aes_key_size,
				    params[3].memref.buffer, &write_bytes);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	params[3].memref.size -= write_bytes;

	tee_rv = warp_aes_operation(file_key, TEE_MODE_ENCRYPT,
				    params[2].memref.buffer, params[2].memref.size,
			(uint8_t *)params[3].memref.buffer + write_bytes,
			(uint32_t *)&params[3].memref.size);

	params[3].memref.size += write_bytes;

	return tee_rv;
}

static TEE_Result do_crypto_decrypt_file(TEE_ObjectHandle dir_key,
					 uint32_t paramTypes,
					 TEE_Param *params)
{
	TEE_ObjectHandle file_key = NULL;
	uint32_t aes_key_size = BITS2BYTES(OMS_AES_SIZE);
	uint8_t aes_key[BITS2BYTES(OMS_AES_SIZE)];
	TEE_Attribute aes_attr = {0};
	TEE_Result tee_rv;

	/* Decrypt function is expecting source data */
	if (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_MEMREF_INPUT) {
		OT_LOG(LOG_ERR, "Bad parameter at index 2: expexted memref input");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	tee_rv = warp_aes_operation(dir_key, TEE_MODE_ENCRYPT,
				    params[2].memref.buffer, aes_key_size,
			aes_key, &aes_key_size);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	tee_rv = TEE_AllocateTransientObject(TEE_TYPE_AES, OMS_AES_SIZE, &file_key);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed : 0x%x", tee_rv);
		return tee_rv;
	}

	TEE_InitRefAttribute(&aes_attr, TEE_ATTR_SECRET_VALUE, aes_key, aes_key_size);

	tee_rv = TEE_PopulateTransientObject(file_key, &aes_attr, 1);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_PopulateTransientObject failed: 0x%x", tee_rv);
		TEE_FreeTransientObject(file_key);
	}

	tee_rv = warp_aes_operation(file_key, TEE_MODE_DECRYPT,
				    (uint8_t *)params[2].memref.buffer + aes_key_size,
			params[2].memref.size - aes_key_size,
			params[3].memref.buffer,
			(uint32_t *)&params[3].memref.size);

	TEE_FreeTransientObject(file_key);
	return tee_rv;
}

static TEE_Result do_crypto(uint32_t paramTypes,
			    TEE_Param *params)
{
	TEE_ObjectHandle aes_file_key = NULL;
	TEE_Result tee_rv = TEE_SUCCESS;

	/* ParamTypes parameter is used for checking parameters type.
	 * It just agreed between CA and TA. */

	/* Crypto operation have commons following parameters. Checking parameters one by one
	 * for purpose of printing debug message */
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT) {
		OT_LOG(LOG_ERR, "Bad parameter at index 0: expexted memref input");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_INPUT) {
		OT_LOG(LOG_ERR, "Bad parameter at index 1: expexted value input");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check parameter types */
	if (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_MEMREF_OUTPUT) {
		OT_LOG(LOG_ERR, "Bad parameter at index 3: expexted memref output");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	tee_rv = get_file_key((struct key_chain_data *)&params[0], &aes_file_key);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	switch (params[1].value.a) {
	case OM_OP_CREATE_DIRECTORY_KEY:
		tee_rv = do_crypto_create_dir_key(aes_file_key, params);
		break;

	case OM_OP_ENCRYPT_FILE:
		tee_rv = do_crypto_encrypt_file(aes_file_key, paramTypes, params);
		break;

	case OM_OP_DECRYPT_FILE:
		tee_rv = do_crypto_decrypt_file(aes_file_key, paramTypes, params);
		break;
	default:
		OT_LOG(LOG_ERR, "Unknown crypto command ID");
		tee_rv = TEE_ERROR_BAD_PARAMETERS;
		break;
	}

	TEE_FreeTransientObject(aes_file_key);
	return tee_rv;
}

static TEE_Result create_root_key(uint32_t paramTypes,
				 TEE_Param *params)
{
	uint32_t aes_raw_size = BITS2BYTES(OMS_AES_SIZE);
	uint8_t aes_raw[BITS2BYTES(OMS_AES_SIZE)];
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

	tee_rv = create_oms_aes_key(aes_raw, &aes_raw_size);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	return warp_oms_RSA_operation(TEE_MODE_ENCRYPT, aes_raw, aes_raw_size,
				      params[0].memref.buffer, (uint32_t *)&params[0].memref.size);
}

static uint8_t does_ss_object_exist(void *object_id,
				    size_t object_id_len)
{
	TEE_ObjectEnumHandle tee_ss_iter = NULL;
	uint32_t ss_obj_id_len = TEE_OBJECT_ID_MAX_LEN;
	char ss_obj_id[TEE_OBJECT_ID_MAX_LEN];
	uint8_t ss_obj_found = 0;
	TEE_Result tee_rv;


	tee_rv = TEE_AllocatePersistentObjectEnumerator(&tee_ss_iter);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocatePersistentObjectEnumerator failed : 0x%x", tee_rv);
		goto out;
	}

	tee_rv = TEE_StartPersistentObjectEnumerator(tee_ss_iter, TEE_STORAGE_PRIVATE);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_StartPersistentObjectEnumerator failed : 0x%x", tee_rv);
		goto out;
	}

	for (;;) {

		ss_obj_id_len = TEE_OBJECT_ID_MAX_LEN;
		tee_rv = TEE_GetNextPersistentObject(tee_ss_iter, NULL, ss_obj_id, &ss_obj_id_len);
		if (tee_rv == TEE_SUCCESS) {

			if (ss_obj_id_len != object_id_len)
				continue;

			if (TEE_MemCompare(ss_obj_id, object_id, object_id_len)) {
				ss_obj_found = 1;
				goto out;
			}

		} else if (tee_rv == TEE_ERROR_ITEM_NOT_FOUND) {
			goto out;

		} else {
			OT_LOG(LOG_ERR, "Enumerator get next failed : 0x%x", tee_rv);
			goto out;
		}
	}

out:
	TEE_FreePersistentObjectEnumerator(tee_ss_iter);
	return ss_obj_found;
}



/*
 * TEE Core API defined five entry point functions
 */
TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
	char oms_rsa_keypair_id[] = "oms_rsa_keypair";
	TEE_ObjectHandle transient_rsa_handle = NULL;
	TEE_Result tee_rv = TEE_SUCCESS;

	if (does_ss_object_exist(oms_rsa_keypair_id, sizeof(oms_rsa_keypair_id))) {

		tee_rv = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
						  oms_rsa_keypair_id, sizeof(oms_rsa_keypair_id),
						  0, &oms_RSA_keypair_handle);
		if (tee_rv != TEE_SUCCESS)
			OT_LOG(LOG_ERR, "TEE_OpenPersistentObject failed: 0x%x", tee_rv);

		return tee_rv;

	}

	tee_rv = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, OMS_RSA_MODULU_SIZE,
					     &transient_rsa_handle);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed: 0x%x", tee_rv);
		goto out;
	}

	tee_rv = TEE_GenerateKey(transient_rsa_handle, OMS_RSA_MODULU_SIZE, NULL, 0);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_GenerateKey failed: 0x%x", tee_rv);
		goto out;
	}

	tee_rv = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					    oms_rsa_keypair_id, sizeof(oms_rsa_keypair_id),
					    0, transient_rsa_handle, NULL, 0, &oms_RSA_keypair_handle);
	if (tee_rv != TEE_SUCCESS)
		OT_LOG(LOG_ERR, "TEE_CreatePersistentObject failed: 0x%x", tee_rv);

out:
	TEE_FreeTransientObject(transient_rsa_handle);
	return tee_rv;
}

static TEE_Result init_oms_aes_key(TEE_Param *params)
{
	uint32_t aes_raw_size = BITS2BYTES(OMS_RSA_MODULU_SIZE);
	uint8_t aes_raw[BITS2BYTES(OMS_RSA_MODULU_SIZE)];
	TEE_Attribute aes_attr = {0};
	TEE_Result tee_rv = TEE_SUCCESS;

	tee_rv = warp_oms_RSA_operation(TEE_MODE_DECRYPT, params[0].memref.buffer,
			params[0].memref.size, aes_raw, &aes_raw_size);
	if (tee_rv != TEE_SUCCESS)
		return tee_rv;

	tee_rv = TEE_AllocateTransientObject(TEE_TYPE_AES, OMS_AES_SIZE, &oms_AES_key_handle);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_AllocateTransientObject failed: 0x%x", tee_rv);
		return tee_rv;
	}

	TEE_InitRefAttribute(&aes_attr, TEE_ATTR_SECRET_VALUE, aes_raw, aes_raw_size);

	tee_rv = TEE_PopulateTransientObject(oms_AES_key_handle, &aes_attr, 1);
	if (tee_rv != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "TEE_PopulateTransientObject failed: 0x%x", tee_rv);
		TEE_FreeTransientObject(oms_AES_key_handle);
	}

	return tee_rv;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{
	TEE_CloseObject(oms_RSA_keypair_handle);
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
	if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_NONE &&
	    TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_NONE &&
	    TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE &&
	    TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_NONE) {
		/* Create root directory, no action */
		return TEE_SUCCESS;

	} else if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT &&
		   TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_NONE &&
		   TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE &&
		   TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_NONE) {
		return init_oms_aes_key(params);

	} else {
		OT_LOG(LOG_ERR, "Bad parameter at params: not know combination");
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
	sessionContext = sessionContext;

	TEE_FreeTransientObject(oms_AES_key_handle);
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext,
						uint32_t commandID,
						uint32_t paramTypes,
						TEE_Param params[4])
{
	TEE_Result tee_rv = TEE_SUCCESS;

	sessionContext = sessionContext; /* Not used */

	switch (commandID) {
	case CMD_CREATE_ROOT_KEY:
		tee_rv = create_root_key(paramTypes, params);
		break;

	case CMD_DO_CRYPTO:
		tee_rv = do_crypto(paramTypes, params);
		break;
	default:
		OT_LOG(LOG_ERR, "Unknown command ID");
		tee_rv = TEE_ERROR_BAD_PARAMETERS;
	}

	return tee_rv;
}
