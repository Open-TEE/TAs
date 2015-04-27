LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libta_conn_test_app

LOCAL_SRC_FILES := \
		    ta_conn_test_app.c

LOCAL_C_INCLUDES    :=	\
			$(LOCAL_PATH)

LOCAL_SHARED_LIBRARIES := libc libdl libInternalApi

LOCAL_G_FLAGS := -DANDROID

include $(BUILD_SHARED_LIBRARY)