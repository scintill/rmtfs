LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
	LOCAL_MODULE := rmtfsd

	LOCAL_CFLAGS := -Wall -g -DNO_UDEV -DRMTFS_PARTITION_TABLE='$(BOARD_RMTFS_PARTITION_TABLE)'
	# TODO figure out why we crash with -O2 in CFLAGS
	LOCAL_SHARED_LIBRARIES := libqrtr liblog
	LOCAL_SRC_FILES := qmi_rmtfs.c qmi_tlv.c rmtfs.c sharedmem.c storage.c util.c
include $(BUILD_EXECUTABLE)
