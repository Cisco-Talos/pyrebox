#include "windows.h"

#include <WinHvPlatform.h>
#include <WinHvEmulation.h>

#ifndef WHP_DISPATCH_H
#define WHP_DISPATCH_H


#define LIST_WINHVPLATFORM_FUNCTIONS(X) \
  X(HRESULT, WHvGetCapability, (WHV_CAPABILITY_CODE CapabilityCode, VOID* CapabilityBuffer, UINT32 CapabilityBufferSizeInBytes, UINT32* WrittenSizeInBytes)) \
  X(HRESULT, WHvCreatePartition, (WHV_PARTITION_HANDLE* Partition)) \
  X(HRESULT, WHvSetupPartition, (WHV_PARTITION_HANDLE Partition)) \
  X(HRESULT, WHvDeletePartition, (WHV_PARTITION_HANDLE Partition)) \
  X(HRESULT, WHvGetPartitionProperty, (WHV_PARTITION_HANDLE Partition, WHV_PARTITION_PROPERTY_CODE PropertyCode, VOID* PropertyBuffer, UINT32 PropertyBufferSizeInBytes, UINT32* WrittenSizeInBytes)) \
  X(HRESULT, WHvSetPartitionProperty, (WHV_PARTITION_HANDLE Partition, WHV_PARTITION_PROPERTY_CODE PropertyCode, const VOID* PropertyBuffer, UINT32 PropertyBufferSizeInBytes)) \
  X(HRESULT, WHvMapGpaRange, (WHV_PARTITION_HANDLE Partition, VOID* SourceAddress, WHV_GUEST_PHYSICAL_ADDRESS GuestAddress, UINT64 SizeInBytes, WHV_MAP_GPA_RANGE_FLAGS Flags)) \
  X(HRESULT, WHvUnmapGpaRange, (WHV_PARTITION_HANDLE Partition, WHV_GUEST_PHYSICAL_ADDRESS GuestAddress, UINT64 SizeInBytes)) \
  X(HRESULT, WHvTranslateGva, (WHV_PARTITION_HANDLE Partition, UINT32 VpIndex, WHV_GUEST_VIRTUAL_ADDRESS Gva, WHV_TRANSLATE_GVA_FLAGS TranslateFlags, WHV_TRANSLATE_GVA_RESULT* TranslationResult, WHV_GUEST_PHYSICAL_ADDRESS* Gpa)) \
  X(HRESULT, WHvCreateVirtualProcessor, (WHV_PARTITION_HANDLE Partition, UINT32 VpIndex, UINT32 Flags)) \
  X(HRESULT, WHvDeleteVirtualProcessor, (WHV_PARTITION_HANDLE Partition, UINT32 VpIndex)) \
  X(HRESULT, WHvRunVirtualProcessor, (WHV_PARTITION_HANDLE Partition, UINT32 VpIndex, VOID* ExitContext, UINT32 ExitContextSizeInBytes)) \
  X(HRESULT, WHvCancelRunVirtualProcessor, (WHV_PARTITION_HANDLE Partition, UINT32 VpIndex, UINT32 Flags)) \
  X(HRESULT, WHvGetVirtualProcessorRegisters, (WHV_PARTITION_HANDLE Partition, UINT32 VpIndex, const WHV_REGISTER_NAME* RegisterNames, UINT32 RegisterCount, WHV_REGISTER_VALUE* RegisterValues)) \
  X(HRESULT, WHvSetVirtualProcessorRegisters, (WHV_PARTITION_HANDLE Partition, UINT32 VpIndex, const WHV_REGISTER_NAME* RegisterNames, UINT32 RegisterCount, const WHV_REGISTER_VALUE* RegisterValues)) \


#define LIST_WINHVEMULATION_FUNCTIONS(X) \
  X(HRESULT, WHvEmulatorCreateEmulator, (const WHV_EMULATOR_CALLBACKS* Callbacks, WHV_EMULATOR_HANDLE* Emulator)) \
  X(HRESULT, WHvEmulatorDestroyEmulator, (WHV_EMULATOR_HANDLE Emulator)) \
  X(HRESULT, WHvEmulatorTryIoEmulation, (WHV_EMULATOR_HANDLE Emulator, VOID* Context, const WHV_VP_EXIT_CONTEXT* VpContext, const WHV_X64_IO_PORT_ACCESS_CONTEXT* IoInstructionContext, WHV_EMULATOR_STATUS* EmulatorReturnStatus)) \
  X(HRESULT, WHvEmulatorTryMmioEmulation, (WHV_EMULATOR_HANDLE Emulator, VOID* Context, const WHV_VP_EXIT_CONTEXT* VpContext, const WHV_MEMORY_ACCESS_CONTEXT* MmioInstructionContext, WHV_EMULATOR_STATUS* EmulatorReturnStatus)) \


#define WHP_DEFINE_TYPE(return_type, function_name, signature) \
    typedef return_type (WINAPI *function_name ## _t) signature;

#define WHP_DECLARE_MEMBER(return_type, function_name, signature) \
    function_name ## _t function_name;

/* Define function typedef */
LIST_WINHVPLATFORM_FUNCTIONS(WHP_DEFINE_TYPE)
LIST_WINHVEMULATION_FUNCTIONS(WHP_DEFINE_TYPE)

struct WHPDispatch {
    LIST_WINHVPLATFORM_FUNCTIONS(WHP_DECLARE_MEMBER)
    LIST_WINHVEMULATION_FUNCTIONS(WHP_DECLARE_MEMBER)
};

extern struct WHPDispatch whp_dispatch;

bool init_whp_dispatch(void);


#endif /* WHP_DISPATCH_H */
