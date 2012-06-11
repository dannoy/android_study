LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	listservice.cpp 

LOCAL_SHARED_LIBRARIES := \
	libutils \
	libbinder

#base := $(LOCAL_PATH)/../../frameworks/base

LOCAL_C_INCLUDES := 

LOCAL_MODULE:= ljtest

include $(BUILD_EXECUTABLE)
