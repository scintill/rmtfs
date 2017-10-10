LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
	LOCAL_MODULE := rmtfsd

	LOCAL_CFLAGS := -Wall -g -DNO_UDEV
	# TODO figure out why we crash with -O2 in CFLAGS
	LOCAL_SHARED_LIBRARIES := libqrtr
	LOCAL_SRC_FILES := qmi_rmtfs.c qmi_tlv.c rmtfs.c sharedmem.c storage.c util.c
include $(BUILD_EXECUTABLE)
