/*++

Module p_file_path:

    FsFilter1.c

Abstract:

    This is the main module of the FsFilter1 miniFilter driver.

Environment:

    Kernel mode

--*/


///////////////////////////////////////////
/////          FILE INCLUDES          /////
///////////////////////////////////////////
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntddk.h>





///////////////////////////////////////////
/////             MACROS              /////
///////////////////////////////////////////
#define SECUREWORLD_FILENAME_TAG 'SWfn'
#define SECUREWORLD_PRE2POST_TAG 'SWpp'
#define SECUREWORLD_VOLUME_CONTEXT_TAG 'SWvx'
//#define SECUREWORLD_FILE_CONTEXT_TAG 'SWfx' // Not implemented yet. Possible optimization for filename retrieving
#define SECUREWORLD_VOLUME_NAME_TAG 'SWvn'
#define SECUREWORLD_REQUESTOR_NAME_TAG 'SWrn'

#define MIN_SECTOR_SIZE 0x200

#define MAX_FILEPATH_LENGTH 520     // 260 is enough? The correct way to do it is ask twice the function, first with buffer = 0 and then with the length the function returned (slower)

#define DEBUG_MODE 1                // Affects the PRINT() function. If 0 does not print anything. If 1 debug traces are printed.
#define CHECK_FILENAME 1            // Affects is_special_folder_get_file_name() function. If 0 function always return 0 and null filename pointer. If 1 behaves normally.
#define PROCESS_CREATE_OPERATION 1  // If 0 create operations are not processed. If 1 create operations are processed.
#define PROCESS_READ_OPERATION 1    // If 0 read operations are not processed. If 1 read operations are processed and buffer swapped.
#define PROCESS_WRITE_OPERATION 1   // If 0 write operations are not processed. If 1 write operations are processed and buffer swapped.
//TO DO    #define BUFFER_SWAP 1               // If 0 skips the buffer swap (note this is only valid for same length encription algorithms). If 1 does the buffer swap.

#define PRINT(...) do { if (DEBUG_MODE) DbgPrint(__VA_ARGS__); } while (0)

#define NOOP ((void)0);             // No-operation





///////////////////////////////////////////
/////        TYPE DEFINITIONS         /////
///////////////////////////////////////////

//typedef enum { false, true } bool;    // false = 0,  true = 1

typedef struct _VOLUME_CONTEXT {
    UNICODE_STRING Name;        // Holds the name to display
    ULONG SectorSize;           // Holds sector size for this volume
} VOLUME_CONTEXT, *PVOLUME_CONTEXT;

typedef struct _PRE_2_POST_CONTEXT {
    PVOLUME_CONTEXT VolCtx;     // Volume context to be freed on post-operation (in DPC: can't be got, but can be released)
    PVOID SwappedBuffer;        // Swapped buffer to be freed on post-operation
} PRE_2_POST_CONTEXT, *PPRE_2_POST_CONTEXT;

// Defines the type QUERY_INFO_PROCESS as a pointer to a function that returns NTSTATUS and takes as parameters the provided fields
typedef NTSTATUS(*QUERY_INFO_PROCESS) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
);





///////////////////////////////////////////
/////       FUNCTION PROTOTYPES       /////
///////////////////////////////////////////

NTSTATUS instance_setup(_In_ PCFLT_RELATED_OBJECTS flt_objects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
void cleanup_volume_context(_In_ PFLT_CONTEXT ctx, _In_ FLT_CONTEXT_TYPE ctx_type);
NTSTATUS mini_unload(FLT_FILTER_UNLOAD_FLAGS flags);
FLT_PREOP_CALLBACK_STATUS mini_pre_create(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context);
FLT_POSTOP_CALLBACK_STATUS mini_post_create(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context, FLT_POST_OPERATION_FLAGS flags);
FLT_PREOP_CALLBACK_STATUS mini_pre_read(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context);
FLT_POSTOP_CALLBACK_STATUS mini_post_read(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context, FLT_POST_OPERATION_FLAGS flags);
FLT_PREOP_CALLBACK_STATUS mini_pre_write(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context);
FLT_POSTOP_CALLBACK_STATUS mini_post_write(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context, FLT_POST_OPERATION_FLAGS flags);
FLT_PREOP_CALLBACK_STATUS mini_pre_set_information(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context);

BOOLEAN is_special_folder_get_file_name(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR** pp_file_name);
NTSTATUS get_requestor_process_image_path(_In_ PFLT_CALLBACK_DATA data, _Out_ PUNICODE_STRING img_path);
NTSTATUS get_process_image_path(_In_ HANDLE pid, _Out_ PUNICODE_STRING img_path);
FLT_PREOP_CALLBACK_STATUS pre_read_swap_buffers(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS flt_objects, _Out_ PVOID* completion_context);
FLT_POSTOP_CALLBACK_STATUS post_read_test(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS flt_objects, _In_ PVOID completion_context, _In_ FLT_POST_OPERATION_FLAGS flags);
FLT_POSTOP_CALLBACK_STATUS post_read_swap_buffers(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS flt_objects, _In_ PVOID completion_context, _In_ FLT_POST_OPERATION_FLAGS flags);
FLT_POSTOP_CALLBACK_STATUS post_read_swap_buffers_when_safe(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS flt_objects, _In_ PVOID completion_context, _In_ FLT_POST_OPERATION_FLAGS flags);
FLT_PREOP_CALLBACK_STATUS pre_write_swap_buffers(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS flt_objects, _Out_ PVOID* completion_context);
FLT_POSTOP_CALLBACK_STATUS post_write_swap_buffers(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS flt_objects, _In_ PVOID completion_context, _In_ FLT_POST_OPERATION_FLAGS flags);

void encrypt(_Out_ char* encrypted_buf, _In_ char* orig_buf, _In_ ULONG write_len);
void decrypt(_Out_ char* decrypted_buf, _In_ char* orig_buf, _In_ ULONG write_len);

void encrypt_XOR_OLD(_Out_ char* encrypted_buf, _In_ char* orig_buf, _In_ ULONG write_len);
void encrypt_XOR(_Out_ char* encrypted_buf, _In_ char* orig_buf, _In_ ULONG write_len);
void encrypt_XOR_same_buf(_Inout_ char* buf, _In_ ULONG length);
void decrypt_XOR_OLD(_Out_ char* decrypted_buf, _In_ char* orig_buf, _In_ ULONG write_len);
void decrypt_XOR(_Out_ char* decrypted_buf, _In_ char* orig_buf, _In_ ULONG write_len);
void decrypt_XOR_same_buf(_Inout_ char* buf, _In_ ULONG length);





///////////////////////////////////////////
/////        GLOBAL VARIABLES         /////
///////////////////////////////////////////

PFLT_FILTER filter_handle = NULL;

NPAGED_LOOKASIDE_LIST pre2post_context_list;

QUERY_INFO_PROCESS ZwQueryInformationProcess;


//const WCHAR* p_secure_path = L"\\Device\\HarddiskVolume2\\Users\\Sergio\\Desktop\\Testing\\Inside"; // Length = 59 characters
//const WCHAR* p_secure_path = L"\\Device\\HarddiskVolume2\\Users\\Sergio\\Desktop\\Testing\\Inside\\"; // Length = 60 characters
const WCHAR* p_secure_path = L"\\Device\\HarddiskVolume4\\"; // Length = 24 characters
const WCHAR* internal_drives[] = {L"C:", L"D:"};   // Drives with letter that have been always attached to the machine (not pendriver,external drives, etc.)


const FLT_OPERATION_REGISTRATION callbacks[] = {
   #if PROCESS_CREATE_OPERATION
    {IRP_MJ_CREATE, 0, mini_pre_create, mini_post_create},
   #endif

   #if PROCESS_READ_OPERATION
    {IRP_MJ_READ, 0, mini_pre_read, mini_post_read},
   #endif

   #if PROCESS_WRITE_OPERATION
    {IRP_MJ_WRITE, 0, mini_pre_write, mini_post_write},
   #endif
    //{IRP_MJ_SET_INFORMATION, 0, mini_pre_set_information, NULL},

    {IRP_MJ_OPERATION_END}
};

// Context definitions we currently care about. The system will create a lookAside list for the volume context because an explicit size of the context is specified.
const FLT_CONTEXT_REGISTRATION contexts[] = {
    { FLT_VOLUME_CONTEXT, 0, cleanup_volume_context, sizeof(VOLUME_CONTEXT), SECUREWORLD_VOLUME_CONTEXT_TAG },
    //{ FLT_FILE_CONTEXT, 0, cleanup_file_context, sizeof(FILE_CONTEXT), SECUREWORLD_FILE_CONTEXT_TAG },         // Not implemented yet. Possible optimization for filename retrieving
    { FLT_CONTEXT_END }
};

const FLT_REGISTRATION filter_registration = {
    sizeof(FLT_REGISTRATION),       // Size
    FLT_REGISTRATION_VERSION,       // Version
    0,                              // Flags
    contexts,                       // Context
    callbacks,                      // Calbacks
    mini_unload,                    // Unload
    instance_setup,                 // InstanceSetup
    NULL,                           // InstanceQueryTeardown
    NULL,                           // InstanceTeardownStart
    NULL,                           // InstanceTeardownComplete
    NULL,                           // GenerateFileName
    NULL,                           // GenerateDestinationFileName
    NULL                            // NormalizeNameComponent
};





///////////////////////////////////////////
/////    FUNCTION IMPLEMENTATIONS     /////
///////////////////////////////////////////

/////     MINIFILTER CALLBACKS     /////
/**
* The filter manager calls this routine on the first operation after a new volume is mounted. Checks if the minifilter is allowed to be attached to the volume.
* Tries to attach to all volumes. Tries to get a "DOS" name for the given volume, if it es not posssible, tries with the "NT" name for the volume (which is what happens on network volumes).  If a name is retrieved a volume context will be created with that name.
*
* @param PCFLT_RELATED_OBJECTS flt_objects
*       The callback operation data.
* @param FLT_INSTANCE_SETUP_FLAGS flags
*       Bitmask of flags that indicate why the instance is being attached
* @param DEVICE_TYPE volume_device_type
*       Device type of the file system volume (CD/Disk/Network)
* @param FLT_FILESYSTEM_TYPE volume_filesystem_type
*       File system type of the volume (unknown, RAW, NTFS, etc.)
* 
* @return NTSTATUS
*       STATUS_SUCCESS - Minifilter attaches to the volume
*       STATUS_FLT_DO_NOT_ATTACH - Minifilter does not attach to the volume
*/
NTSTATUS instance_setup(_In_ PCFLT_RELATED_OBJECTS flt_objects, _In_ FLT_INSTANCE_SETUP_FLAGS flags, _In_ DEVICE_TYPE volume_device_type, _In_ FLT_FILESYSTEM_TYPE volume_filesystem_type) {
    PDEVICE_OBJECT dev_obj = NULL;
    PVOLUME_CONTEXT ctx = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG ret_len;
    PUNICODE_STRING working_name;
    USHORT size;
    UCHAR vol_prop_buffer[sizeof(FLT_VOLUME_PROPERTIES) + 512];
    PFLT_VOLUME_PROPERTIES vol_prop = (PFLT_VOLUME_PROPERTIES)vol_prop_buffer;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(volume_device_type);
    UNREFERENCED_PARAMETER(volume_filesystem_type);

    try {
        // Allocate a volume context structure.
        status = FltAllocateContext(flt_objects->Filter, FLT_VOLUME_CONTEXT, sizeof(VOLUME_CONTEXT), NonPagedPool, &ctx);
        if (!NT_SUCCESS(status)) {
            leave;
        }

        // Get volume properties
        status = FltGetVolumeProperties(flt_objects->Volume, vol_prop, sizeof(vol_prop_buffer), &ret_len);
        if (!NT_SUCCESS(status)) {
            leave;
        }

        // Save the sector size in the context for later use
        FLT_ASSERT((vol_prop->SectorSize == 0) || (vol_prop->SectorSize >= MIN_SECTOR_SIZE));
        ctx->SectorSize = max(vol_prop->SectorSize, MIN_SECTOR_SIZE);

        // Init the buffer field (which may be allocated later).
        ctx->Name.Buffer = NULL;

        // Get the storage device object we want a name for.
        status = FltGetDiskDeviceObject(flt_objects->Volume, &dev_obj);
        if (NT_SUCCESS(status)) {
            // Try to get the DOS name. If it succeeds we will have an allocated name buffer. If not, it will be NULL
            status = IoVolumeDeviceToDosName(dev_obj, &ctx->Name);
        }

        // If we could not get a DOS name, get the NT name.
        if (!NT_SUCCESS(status)) {
            FLT_ASSERT(ctx->Name.Buffer == NULL);

            // Figure out which name to use from the properties
            if (vol_prop->RealDeviceName.Length > 0) {
                working_name = &vol_prop->RealDeviceName;
            } else if (vol_prop->FileSystemDeviceName.Length > 0) {
                working_name = &vol_prop->FileSystemDeviceName;
            } else {
                // No name, don't save the context
                status = STATUS_FLT_DO_NOT_ATTACH;
                leave;
            }

            // Get size of buffer to allocate. This is the length of the string plus room for a trailing colon.
            size = working_name->Length + sizeof(WCHAR);

            // Now allocate a buffer to hold this name
            #pragma prefast(suppress:__WARNING_MEMORY_LEAK, "ctx->Name.Buffer will not be leaked because it is freed in cleanup_volume_context")
            ctx->Name.Buffer = ExAllocatePoolWithTag(NonPagedPool, size, SECUREWORLD_VOLUME_NAME_TAG);
            if (ctx->Name.Buffer == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                leave;
            }

            // Init the rest of the fields
            ctx->Name.Length = 0;
            ctx->Name.MaximumLength = size;

            // Copy the name in, and add a colon (just for visual purpose)
            RtlCopyUnicodeString(&ctx->Name, working_name);
            RtlAppendUnicodeToString(&ctx->Name, L":");
        }

        // Set the context (already defined is OK)
        status = FltSetVolumeContext(flt_objects->Volume, FLT_SET_CONTEXT_KEEP_IF_EXISTS, ctx, NULL);
        if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
            status = STATUS_SUCCESS;
        }

        /////////////////////////////////////////////
        // If volume is not letter "T:" do not attach
        //SW: InstanceSetup:     Real SectSize=0x0000, Used SectSize=0x0200, Name="\Device\Mup:"
        //SW: InstanceSetup:     Real SectSize=0x0200, Used SectSize=0x0200, Name="C:"
        //SW: InstanceSetup:     Real SectSize=0x0200, Used SectSize=0x0200, Name="\\?\Volume{55679090-0000-0000-0000-100000000000}"
        //SW: InstanceSetup:     Real SectSize=0x0200, Used SectSize=0x0200, Name="\\?\Volume{55679090-0000-0000-0000-d05f0c000000}"
        //SW: InstanceSetup:     Real SectSize=0x0200, Used SectSize=0x0200, Name="K:"
        //--------------------------------------------------------------------------------
        // K:               \\?\Volume{820c6478-0000-0000-0000-100000000000}\
        // C:               \\?\Volume{55679090-0000-0000-0000-300300000000}\
        // System reserved  \\?\Volume{55679090-0000-0000-0000-100000000000}\
        // Recovery         \\?\Volume{55679090-0000-0000-0000-d05f0c000000}\
        // \Device\Mup: (Multiple UNC Provider) Kernel-mode component that uses UNC names to channel remote file system accesses to a network redirector (UNC provider) cappable of handling them.

        //if (RtlCompareUnicodeString(&ctx->Name, L"T:", FALSE)) {
        if (wcscmp(ctx->Name.Buffer, L"K:") == 0) {
            status = STATUS_SUCCESS;
            PRINT("SW: InstanceSetup:       K:      -->  Attached");
        } else {
            status = STATUS_FLT_DO_NOT_ATTACH;
            PRINT("SW: InstanceSetup:       Not K:  -->  Not attached");
        }

        PRINT("SW: InstanceSetup:     Real SectSize=0x%04x, Used SectSize=0x%04x, Name=\"%wZ\"\n", vol_prop->SectorSize, ctx->SectorSize, &ctx->Name);

    } finally {

        // Always release the context. If the set failed, it will free the context. If not, it will remove the reference added by the set.
        // Note that the name buffer in the ctx will get freed by the context cleanup routine.
        if (ctx) {
            FltReleaseContext(ctx);
        }

        // Remove the reference added to the device object by FltGetDiskDeviceObject
        if (dev_obj) {
            ObDereferenceObject(dev_obj);
        }
    }

    return status;
}

/**
* Frees the name buffer associated to the volume context
*
* @param PFLT_CONTEXT ctx
*       The context being freed
* @param FLT_CONTEXT_TYPE ctx_type
*       The context type.
*/
VOID cleanup_volume_context(_In_ PFLT_CONTEXT ctx, _In_ FLT_CONTEXT_TYPE ctx_type) {
    PVOLUME_CONTEXT vol_ctx = ctx;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(ctx_type);

    FLT_ASSERT(ctx_type == FLT_VOLUME_CONTEXT);

    if (vol_ctx->Name.Buffer != NULL) {
        ExFreePool(vol_ctx->Name.Buffer);
        vol_ctx->Name.Buffer = NULL;
    }
}

NTSTATUS mini_unload(FLT_FILTER_UNLOAD_FLAGS flags) {
    PRINT("SW: Driver unload \r\n");
    FltUnregisterFilter(filter_handle);

    // Delete lookaside list for pre2post
    ExDeleteNPagedLookasideList(&pre2post_context_list);
    return STATUS_SUCCESS;
};

FLT_PREOP_CALLBACK_STATUS mini_pre_create(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context) {
    UNICODE_STRING img_path;
    if (NT_SUCCESS(get_requestor_process_image_path(data, &img_path)) && img_path.Length>0) {
        PRINT("SW: PreCreate from %wZ", img_path);
        ExFreePoolWithTag(img_path.Buffer, SECUREWORLD_REQUESTOR_NAME_TAG);
    } else {
        PRINT("SW: PreCreate from ???");
    }

    WCHAR* p_file_name = NULL;
    if (is_special_folder_get_file_name(data, &p_file_name)) {
        if (p_file_name) {
            PRINT("SW: PreCreate in special folder           (%ws)\r\n", p_file_name);
            ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);
            p_file_name = NULL;
        }
    } else {
        if (p_file_name) {
            PRINT("SW: PreCreate NOT in special folder       (%ws)\r\n", p_file_name);
            ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);
            p_file_name = NULL;
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK; // FLT_PREOP_SUCCESS_WITH_CALLBACK;
};

FLT_POSTOP_CALLBACK_STATUS mini_post_create(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context, FLT_POST_OPERATION_FLAGS flags) {
    WCHAR* p_file_name = NULL;
    if (is_special_folder_get_file_name(data, &p_file_name)) {
        if (p_file_name) {
            PRINT("SW: PostCreate in special folder          (%ws)\r\n", p_file_name);

            ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);
            p_file_name = NULL;
        }
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
};

FLT_PREOP_CALLBACK_STATUS mini_pre_read(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context) {
    //FLT_PREOP_CALLBACK_STATUS ret_value = FLT_PREOP_SUCCESS_NO_CALLBACK;    // By default does not call post filter

    WCHAR* p_file_name = NULL;
    if (is_special_folder_get_file_name(data, &p_file_name)) {
        if (p_file_name) {
            PRINT("SW: PreRead in special folder             (%ws)\r\n", p_file_name);
            ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);
            p_file_name = NULL;

            /*PRINT("SW: irp operation flag: %d", FlagOn(FLTFL_CALLBACK_DATA_IRP_OPERATION, data->Flags));
            PRINT("SW: FastIO operation flag: %d", FLT_IS_FASTIO_OPERATION(data));
            PRINT("SW: irp nocache flag: %d", FlagOn(IRP_NOCACHE, data->Iopb->IrpFlags));
            PRINT("SW: irp buffered flag: %d", FlagOn(IRP_BUFFERED_IO, data->Iopb->IrpFlags));
            PRINT("SW: irp paging flag: %d", FlagOn(IRP_PAGING_IO, data->Iopb->IrpFlags));

            data->IoStatus.Status = STATUS_INVALID_PARAMETER;
            data->IoStatus.Information = 0;

            ret_value = FLT_PREOP_COMPLETE;*/
        }
    } else {
        if (p_file_name) {
            PRINT("SW: PreRead NOT in special folder         (%ws)\r\n", p_file_name);
            ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);
            p_file_name = NULL;
        }
    }
    PRINT("SW: irp operation flag: %d", FlagOn(FLTFL_CALLBACK_DATA_IRP_OPERATION, data->Flags));
    PRINT("SW: FastIO operation flag: %d", FLT_IS_FASTIO_OPERATION(data));
    PRINT("SW: irp nocache flag: %d", FlagOn(IRP_NOCACHE, data->Iopb->IrpFlags));
    PRINT("SW: irp buffered flag: %d", FlagOn(IRP_BUFFERED_IO, data->Iopb->IrpFlags));
    PRINT("SW: irp paging flag: %d", FlagOn(IRP_PAGING_IO, data->Iopb->IrpFlags));


    return pre_read_swap_buffers(data, flt_objects, completion_context);
}

FLT_POSTOP_CALLBACK_STATUS mini_post_read(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context, FLT_POST_OPERATION_FLAGS flags) {
    /*WCHAR* p_file_name = NULL;
    if (is_special_folder_get_file_name(data, &p_file_name)) {
        if (p_file_name) {
            PRINT("SW: PostRead in special folder            (%ws)\r\n", p_file_name);

            ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);
            p_file_name = NULL;
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;*/
    
    return post_read_swap_buffers(data, flt_objects, completion_context, flags);
    //return post_read_test(data, flt_objects, completion_context, flags);

};

/* OLD version of         mini_pre_write       that prevents from saving (writting) in the secure folder
FLT_PREOP_CALLBACK_STATUS mini_pre_write(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context) {
    WCHAR* p_file_name = NULL;
    if (is_special_folder_get_file_name(data, &p_file_name)) {
        if (p_file_name) {
            PRINT("SW: PreWrite in special folder            (%ws)\r\n", p_file_name);
            //PRINT("SW: Failed write request due to prohibited name: %ws \r\n", p_file_path);

            ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);
            p_file_name = NULL;
        }
        data->IoStatus.Status = STATUS_INVALID_PARAMETER;
        data->IoStatus.Information = 0;

        return FLT_PREOP_COMPLETE; // Operation is not further processed
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK; // Operation continues processing but will not call the post filter
};
*/

FLT_PREOP_CALLBACK_STATUS mini_pre_write(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context) {
    //FLT_PREOP_CALLBACK_STATUS ret_value = FLT_PREOP_SUCCESS_NO_CALLBACK;    // By default do not call post filter

    WCHAR* p_file_name = NULL;
    if (is_special_folder_get_file_name(data, &p_file_name)) {
        if (p_file_name) {
            PRINT("SW: PreWrite in special folder            (%ws)\r\n", p_file_name);
            ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);
            p_file_name = NULL;
        }
    } else {
        if (p_file_name) {
            PRINT("SW: PreWrite NOT in special folder        (%ws)\r\n", p_file_name);
            ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);
            p_file_name = NULL;
        }
    }

    return pre_write_swap_buffers(data, flt_objects, completion_context);;
};

FLT_POSTOP_CALLBACK_STATUS mini_post_write(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context, FLT_POST_OPERATION_FLAGS flags) {
    return post_write_swap_buffers(data, flt_objects, completion_context, flags);
}

FLT_PREOP_CALLBACK_STATUS mini_pre_set_information(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context) {
    WCHAR *p_file_name = NULL;
    if (is_special_folder_get_file_name(data, &p_file_name)) {
        if (p_file_name) {
            PRINT("SW: PreSetInformtion in special folder    (%ws)\r\n", p_file_name);

            ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);
            p_file_name = NULL;
            //return FLT_PREOP_SUCCESS_WITH_CALLBACK; // Operation continues processing and will call the post filter
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK; // Operation continues processing but will not call the post filter
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    PRINT("SW: Driver entry\r\n");

    // Initialize look aside list for pre2post
    ExInitializeNPagedLookasideList(&pre2post_context_list, NULL, NULL, 0, sizeof(PRE_2_POST_CONTEXT), SECUREWORLD_PRE2POST_TAG, 0);

    status = FltRegisterFilter(DriverObject, &filter_registration, &filter_handle);
    if (NT_SUCCESS(status)) {
        PRINT("SW: Driver entry register success\r\n");
        
        status = FltStartFiltering(filter_handle);
        if (!NT_SUCCESS(status)) {
            PRINT("SW: Driver entry start filtering success\r\n");
            FltUnregisterFilter(filter_handle);
        }
    }

    return status;
}



/////     CUSTOM FUNCTIONS     /////

/**
* Checks if the operation is taking place in the secure folder or not.
* 
* @param PFLT_CALLBACK_DATA data
*       The callback operation data.
* @param WCHAR **pp_file_name
*       Empty pointer used to output the name if the function returns TRUE.
*       May be NULL if allocation did not succeed.
*       Memory is allocated inside, remember to free it with "ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);".
* 
* @return BOOLEAN
*       If the operation is taking place in the secure folder.
*/
BOOLEAN is_special_folder_get_file_name(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR **pp_file_name) {
    if (!CHECK_FILENAME) {
        *pp_file_name = NULL;
        return TRUE;
    }

    PFLT_FILE_NAME_INFORMATION file_name_info;
    NTSTATUS status;
    WCHAR p_file_path[MAX_FILEPATH_LENGTH] = { 0 };
    WCHAR *p_path_match = NULL;
    BOOLEAN ret_value = FALSE;

    status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &file_name_info);

    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(file_name_info);
        if (NT_SUCCESS(status)) {
            if (file_name_info->Name.MaximumLength < MAX_FILEPATH_LENGTH) {
                RtlCopyMemory(p_file_path, file_name_info->Name.Buffer, file_name_info->Name.MaximumLength);

                p_path_match = wcsstr(p_file_path, p_secure_path);
                if (p_path_match!=NULL && p_path_match==p_file_path) {
                    ret_value = TRUE;   // Match

                    *pp_file_name = (WCHAR *)ExAllocatePoolWithTag(PagedPool, MAX_FILEPATH_LENGTH *sizeof(WCHAR), (ULONG)SECUREWORLD_FILENAME_TAG);
                    //WCHAR pp_file_name[MAX_FILEPATH_LENGTH];

                    if (*pp_file_name) {
                        const WCHAR secure_path_len = wcslen(p_secure_path);
                        size_t file_name_len = wcslen(p_file_path) - secure_path_len;

                        wcsncpy(*pp_file_name, &p_file_path[secure_path_len], file_name_len);
                        (*pp_file_name)[file_name_len] = L'\0';

                        //PRINT("SW: FilePath: %ws - Length: %zu \r\n", p_file_path, wcslen(p_file_path));
                        //PRINT("SW: File name: %ws - Length: %zu \r\n", *pp_file_name, wcslen(*pp_file_name));
                    }
                } else {
                    ret_value = FALSE;  // NO match

                    *pp_file_name = (WCHAR*)ExAllocatePoolWithTag(PagedPool, MAX_FILEPATH_LENGTH * sizeof(WCHAR), (ULONG)SECUREWORLD_FILENAME_TAG);
                    if (*pp_file_name) {
                        size_t file_name_len = wcslen(p_file_path);

                        wcsncpy(*pp_file_name, p_file_path, file_name_len);
                        (*pp_file_name)[file_name_len] = L'\0';
                    }
                } // Check filename matches secure path
                FltReleaseFileNameInformation(file_name_info);
                return ret_value;
            }// length >260  buffer not big enough
        } else {// Could not parse
            PRINT("SW: ERROR retrieving filename.");
        }
        FltReleaseFileNameInformation(file_name_info);
    }// Could not get
    *pp_file_name = NULL;
    return ret_value;
}

/**
* Gets the full image path of the process which pid is passed by parameter
*
* @param PFLT_CALLBACK_DATA data
*       The callback data of the pre/post operation which caller process path wants to be retrieved.
* @param PUNICODE_STRING p_img_path
*       Empty pointer used to output the name if the function returns a valid status.
*       May be NULL if allocation failed (when STATUS_INSUFFICIENT_RESOURCES is returned).
*       Memory is allocated inside, remember to free it with "ExFreePoolWithTag(p_img_path->Buffer, SECUREWORLD_REQUESTOR_NAME_TAG);".
*
* @return NTSTATUS
*       A status corresponding to the success or failure of the operation.
*/
NTSTATUS get_requestor_process_image_path(_In_ PFLT_CALLBACK_DATA data, _Out_ PUNICODE_STRING p_img_path) {
    NTSTATUS status;
    PEPROCESS obj_process = NULL;
    HANDLE proc_handle;

    obj_process = IoThreadToProcess(data->Thread);

    proc_handle = PsGetProcessId(obj_process);

    p_img_path->Length = 0;
    p_img_path->MaximumLength = MAX_FILEPATH_LENGTH;
    p_img_path->Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, MAX_FILEPATH_LENGTH, SECUREWORLD_REQUESTOR_NAME_TAG);
    if (p_img_path->Buffer) {
        status = get_process_image_path(proc_handle, p_img_path);
        if (NT_SUCCESS(status)) {
            NOOP
            //PRINT("SW: ---> requestor: %wZ", p_img_path);
        } else{
            ExFreePoolWithTag(p_img_path->Buffer, SECUREWORLD_REQUESTOR_NAME_TAG);
        }
    } else {
        status = STATUS_INSUFFICIENT_RESOURCES;
        p_img_path->Buffer = NULL;
    }

    return status;
}

/**
* Gets the full image path of the process which pid is passed by parameter
* Copied from: https://stackoverflow.com/a/40507407/7505211
*
* @param HANDLE pid
*       A handle (process ID) of the process which path wants to be retrieved.
* @param PUNICODE_STRING p_img_path
*       Empty pointer used to output the name if the function returns a valid status.
*       May be NULL if allocation did not succeed.
*       Memory is allocated inside, remember to free it with "ExFreePoolWithTag(p_img_path->Buffer, SECUREWORLD_REQUESTOR_NAME_TAG);".
*
* @return NTSTATUS
*       A status corresponding to the success or failure of the operation.
*/
NTSTATUS get_process_image_path(_In_ HANDLE pid, _Out_ PUNICODE_STRING p_img_path) {
    NTSTATUS status;
    ULONG returned_length;
    ULONG buffer_length;
    HANDLE h_process = NULL;
    PVOID buffer;
    PEPROCESS p_eprocess;
    PUNICODE_STRING p_tmp_img_path;

    PAGED_CODE(); // This eliminates the possibility of the IDLE Thread/Process

    status = PsLookupProcessByProcessId(pid, &p_eprocess);

    if (NT_SUCCESS(status)) {
        status = ObOpenObjectByPointer(p_eprocess, 0, NULL, 0, 0, KernelMode, &h_process);
        if (NT_SUCCESS(status)) {
        } else {
            PRINT("SW: ObOpenObjectByPointer Failed: %08x\n", status);
        }
        ObDereferenceObject(p_eprocess);
    } else {
        PRINT("SW: PsLookupProcessByProcessId Failed: %08x\n", status);
    }

    if (NULL == ZwQueryInformationProcess) {
        UNICODE_STRING routine_name;
        RtlInitUnicodeString(&routine_name, L"ZwQueryInformationProcess");

        ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routine_name);

        if (NULL == ZwQueryInformationProcess) {
            PRINT("SW: Cannot resolve ZwQueryInformationProcess\n");
        }
    }

    // Query the actual size of the process path
    status = ZwQueryInformationProcess(h_process, ProcessImageFileName, NULL, 0, &returned_length);

    if (STATUS_INFO_LENGTH_MISMATCH != status) {
        return status;
    }

    // Check if there is enough space to store the actual process path when it is found. If not return an error with the required size
    buffer_length = returned_length - sizeof(UNICODE_STRING);
    if (p_img_path->MaximumLength < buffer_length) {
        p_img_path->MaximumLength = (USHORT)buffer_length;
        return STATUS_BUFFER_OVERFLOW;
    }

    // Allocate a temporary buffer to store the path name
    buffer = ExAllocatePoolWithTag(NonPagedPool, returned_length, SECUREWORLD_REQUESTOR_NAME_TAG);

    if (NULL == buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Retrieve the process path from the handle to the process
    status = ZwQueryInformationProcess(h_process, ProcessImageFileName, buffer, returned_length, &returned_length);

    if (NT_SUCCESS(status)) {
        // Copy the path name
        p_tmp_img_path = (PUNICODE_STRING)buffer;
        RtlCopyUnicodeString(p_img_path, p_tmp_img_path);
    }

    // Free the temp buffer which stored the path
    ExFreePoolWithTag(buffer, SECUREWORLD_REQUESTOR_NAME_TAG);

    return status;
}



/////     BUFFER SWAP FUNCTIONS     /////

/**
* Performs the buffer swap before the reading operation
* Note that it handles all errors by simply not doing the buffer swap.
*
* @param PFLT_CALLBACK_DATA data
*       The callback operation data.
* @param PCFLT_RELATED_OBJECTS flt_objects
*       Pointer to the FLT_RELATED_OBJECTS data structure containing opaque handles to this filter, instance, its associated volume and file object.
* @param PVOID* completion_context
*       Pointer that allows information to be passed from pre to post operation
*
* @return FLT_PREOP_CALLBACK_STATUS
*       FLT_PREOP_SUCCESS_WITH_CALLBACK - mark success and demand post operation callback
*       FLT_PREOP_SUCCESS_NO_CALLBACK - mark success and do not perform post operation callback
*       FLT_PREOP_COMPLETE - marks the request as completed so the operation is not performed
*/
FLT_PREOP_CALLBACK_STATUS pre_read_swap_buffers(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS flt_objects, _Out_ PVOID* completion_context) {
    FLT_PREOP_CALLBACK_STATUS ret_value = FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_IO_PARAMETER_BLOCK iopb = data->Iopb;
    PVOID new_buf = NULL;
    PMDL new_mdl = NULL;
    PVOLUME_CONTEXT vol_ctx = NULL;
    PPRE_2_POST_CONTEXT p2p_ctx;
    NTSTATUS status;
    ULONG read_len = iopb->Parameters.Read.Length;

    try {
        // If reading 0 bytes, do not swap buffers
        PRINT("SW: SwapPreReadBuffers:           Reading %d Bytes", read_len);
        if (read_len == 0) {
            leave;
        }

        // Get volume context
        status = FltGetVolumeContext(flt_objects->Filter, flt_objects->Volume, &vol_ctx);
        if (!NT_SUCCESS(status)) {
            PRINT("SW: SwapPreReadBuffers:           Error getting volume context, status=%x\n", status);
            leave;
        }

        // If this is a non-cached I/O, round the length up to the sector size for this device
        if (FlagOn(IRP_NOCACHE, iopb->IrpFlags)) {
            read_len = (ULONG)ROUND_TO_SIZE(read_len, vol_ctx->SectorSize);
        }

        // Allocate aligned nonPaged memory for the buffer we are swapping to. This is really only necessary for noncached IO but we always
        // do it here for simplification. If we fail to get the memory, just don't swap buffers on this operation.
        new_buf = FltAllocatePoolAlignedWithTag(flt_objects->Instance, NonPagedPool, (SIZE_T)read_len, SECUREWORLD_PRE2POST_TAG);
        if (new_buf == NULL) {
            PRINT("SW: SwapPreReadBuffers:           %wZ Failed to allocate %d bytes of memory\n", &vol_ctx->Name, read_len);
            leave;
        }

        // If it is an IRP operation, build a MDL (Fast I/O does not need it)
        if (FLT_IS_IRP_OPERATION(data)) {

            // Allocate a MDL for the new allocated memory.
            new_mdl = IoAllocateMdl(new_buf, read_len, FALSE, FALSE, NULL);
            if (new_mdl == NULL) {
                PRINT("SW: SwapPreReadBuffers:       %wZ Failed to allocate MDL\n", &vol_ctx->Name);
                leave;
            }

            // Setup the MDL for the non-paged pool we just allocated
            MmBuildMdlForNonPagedPool(new_mdl);
        }
        
        // We are ready to swap buffers, get a pre2Post context structure. We need it to pass the volume context and the allocate memory buffer to the post operation callback.
        p2p_ctx = ExAllocateFromNPagedLookasideList(&pre2post_context_list);
        if (p2p_ctx == NULL) {
            PRINT("SW: SwapPreReadBuffers:           %wZ Failed to allocate pre2Post context structure\n", &vol_ctx->Name);
            leave;
        }

        // Set the new buffers and mark as dirty
        PRINT("SW: SwapPreReadBuffers:               %wZ newB=%p newMdl=%p oldB=%p oldMdl=%p len=%d\n", &vol_ctx->Name, new_buf, new_mdl, iopb->Parameters.Read.ReadBuffer, iopb->Parameters.Read.MdlAddress, read_len);
        iopb->Parameters.Read.ReadBuffer = new_buf;
        iopb->Parameters.Read.MdlAddress = new_mdl;
        FltSetCallbackDataDirty(data);

        // Pass state to our post-operation callback.
        p2p_ctx->SwappedBuffer = new_buf;
        p2p_ctx->VolCtx = vol_ctx;
        *completion_context = p2p_ctx;

        // Return we want a post-operation callback
        ret_value = FLT_PREOP_SUCCESS_WITH_CALLBACK;

    } finally {
        // If we don't want a post-operation callback, free all pointers
        if (ret_value != FLT_PREOP_SUCCESS_WITH_CALLBACK) {
            if (new_buf != NULL) {
                FltFreePoolAlignedWithTag(flt_objects->Instance, new_buf, SECUREWORLD_PRE2POST_TAG);
            }

            if (new_mdl != NULL) {
                IoFreeMdl(new_mdl);
            }

            if (vol_ctx != NULL) {
                FltReleaseContext(vol_ctx);
            }
        }
    }

    return ret_value;
}

//////////////////////////////////////////////////////////////////////
FLT_POSTOP_CALLBACK_STATUS post_read_test(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS flt_objects, _In_ PVOID completion_context, _In_ FLT_POST_OPERATION_FLAGS flags) {
    PVOID copy_buf;
    PFLT_IO_PARAMETER_BLOCK iopb = data->Iopb;
    FLT_POSTOP_CALLBACK_STATUS ret_value = FLT_POSTOP_FINISHED_PROCESSING;
    PPRE_2_POST_CONTEXT p2p_ctx = completion_context;
    BOOLEAN clean_allocated_buffer = TRUE;
    try {
        if (!NT_SUCCESS(data->IoStatus.Status) || (data->IoStatus.Information == 0)) {
            PRINT("SW: post_read_test:          %wZ newB=%p No data read, status=%x, info=%Iu\n", &p2p_ctx->VolCtx->Name, p2p_ctx->SwappedBuffer, data->IoStatus.Status, data->IoStatus.Information);
            leave;
        }
        PRINT("SW: hola");
        PRINT("SW: irp operation flag: %d", FlagOn(FLTFL_CALLBACK_DATA_IRP_OPERATION, data->Flags));
        PRINT("SW: irp nocache flag: %d", FlagOn(IRP_NOCACHE, iopb->IrpFlags));
        PRINT("SW: irp buffered flag: %d", FlagOn(IRP_BUFFERED_IO, iopb->IrpFlags));
        PRINT("SW: irp paging flag: %d", FlagOn(IRP_PAGING_IO, iopb->IrpFlags));

        copy_buf = ExAllocatePoolWithTag(NonPagedPool, data->IoStatus.Information, 'TEST');
        if (copy_buf != NULL) {
            //RtlCopyMemory(copy_buf, p2p_ctx->SwappedBuffer, data->IoStatus.Information);
            //decrypt(p2p_ctx->SwappedBuffer, copy_buf, data->IoStatus.Information);
            PRINT("SW:::::::::: already decrypted 1: p2p->swap: %.*s", data->IoStatus.Information, p2p_ctx->SwappedBuffer);
            PRINT("SW::::::::: already decrypted 1: ReadBuffer: %.*s", 15, iopb->Parameters.Read.ReadBuffer);
            PRINT("SW::::::::: already decrypted 1: MdlAddress: %.*s", 15, iopb->Parameters.Read.MdlAddress);

            ((char*)iopb->Parameters.Read.ReadBuffer)[0] = 'a';
            ((char*)iopb->Parameters.Read.ReadBuffer)[1] = 'a';
            ((char*)iopb->Parameters.Read.ReadBuffer)[2] = 'a';
            ((char*)iopb->Parameters.Read.ReadBuffer)[3] = 'a';
            ((char*)iopb->Parameters.Read.ReadBuffer)[4] = 'a';

            ((char*)p2p_ctx->SwappedBuffer)[0] = 'b';
            ((char*)p2p_ctx->SwappedBuffer)[1] = 'b';
            ((char*)p2p_ctx->SwappedBuffer)[2] = 'b';
            ((char*)p2p_ctx->SwappedBuffer)[3] = 'b';
            ((char*)p2p_ctx->SwappedBuffer)[4] = 'b';
            PRINT("SW:::::::::: already decrypted 1: p2p->swap: %.*s", data->IoStatus.Information, p2p_ctx->SwappedBuffer);
            PRINT("SW::::::::: already decrypted 1: ReadBuffer: %.*s", 15, iopb->Parameters.Read.ReadBuffer);
            PRINT("SW::::::::: already decrypted 1: MdlAddress: %.*s", 15, iopb->Parameters.Read.MdlAddress);
            FltSetCallbackDataDirty(data);

        } else {
            PRINT("SW: ERROR cannot allocate");
        }


    } finally {
        // If we are supposed to, cleanup the allocated memory and release the volume context. The freeing of the MDL (if there is one) is handled by FltMgr.
        if (clean_allocated_buffer) {
            PRINT("SW: post_read_test:          %wZ newB=%p info=%Iu Freeing\n",
                &p2p_ctx->VolCtx->Name, p2p_ctx->SwappedBuffer, data->IoStatus.Information);
            FltFreePoolAlignedWithTag(flt_objects->Instance, p2p_ctx->SwappedBuffer, SECUREWORLD_PRE2POST_TAG);
            FltReleaseContext(p2p_ctx->VolCtx);
            ExFreeToNPagedLookasideList(&pre2post_context_list, p2p_ctx);
        }
    }
    return ret_value;
}


/**
* Performs the buffer swap after the reading operation (includes decryption)
* Note that it handles all errors by simply not doing the buffer swap.
*
* @param PFLT_CALLBACK_DATA data
*       The callback operation data.
* @param PCFLT_RELATED_OBJECTS flt_objects
*       Pointer to the FLT_RELATED_OBJECTS data structure containing opaque handles to this filter, instance, its associated volume and file object.
* @param PVOID* completion_context
*       Pointer that allows information to be passed from pre to post operation.
*
* @return FLT_PREOP_CALLBACK_STATUS
*       FLT_POSTOP_FINISHED_PROCESSING - operation has finished.
*       FLT_POSTOP_MORE_PROCESSING_REQUIRED - operation is pending more processing.
*/
FLT_POSTOP_CALLBACK_STATUS post_read_swap_buffers(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS flt_objects, _In_ PVOID completion_context, _In_ FLT_POST_OPERATION_FLAGS flags) {
    FLT_POSTOP_CALLBACK_STATUS ret_value = FLT_POSTOP_FINISHED_PROCESSING;
    PVOID orig_buf;
    PFLT_IO_PARAMETER_BLOCK iopb = data->Iopb;
    PPRE_2_POST_CONTEXT p2p_ctx = completion_context;
    BOOLEAN clean_allocated_buffer = TRUE;

    // Verify the draining flag is not set.
    FLT_ASSERT(!FlagOn(flags, FLTFL_POST_OPERATION_DRAINING));

    try {
        // If the operation failed or the count is zero, there is no data so just return now.
        if (!NT_SUCCESS(data->IoStatus.Status) || (data->IoStatus.Information == 0)) {
            PRINT("SW: SwapPostReadBuffers:          %wZ newB=%p No data read, status=%x, info=%Iu\n", &p2p_ctx->VolCtx->Name, p2p_ctx->SwappedBuffer, data->IoStatus.Status,data->IoStatus.Information);
            leave;
        }

        // We need to copy the read data back into the users buffer. Note that the parameters passed in are for the users original buffers not our swapped buffers.
        if (iopb->Parameters.Read.MdlAddress != NULL) {
            // This should be a simple MDL. We don't expect chained MDLs this high up the stack
            FLT_ASSERT(((PMDL)iopb->Parameters.Read.MdlAddress)->Next == NULL);

            // Since there is a MDL defined for the original buffer, get a system address for it so we can copy the data back to it.
            // We must do this because we don't know what thread context we are in.
            orig_buf = MmGetSystemAddressForMdlSafe(iopb->Parameters.Read.MdlAddress, NormalPagePriority | MdlMappingNoExecute);

            if (orig_buf == NULL) {
                PRINT("SW: SwapPostReadBuffers:      %wZ Failed to get system address for MDL: %p\n", &p2p_ctx->VolCtx->Name, iopb->Parameters.Read.MdlAddress);

                // If we failed to get a SYSTEM address, mark that the read failed and return.
                data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                data->IoStatus.Information = 0;
                leave;
            }

        } else if (FlagOn(data->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) || FlagOn(data->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION)) {
            // If this is a system buffer, just use the given address because it is valid in all thread contexts.
            // If this is a FASTIO operation, we can just use the buffer (inside a try/except) since we know we are in the correct thread context (you can't pend FASTIO's).
            orig_buf = iopb->Parameters.Read.ReadBuffer;

        } else {
            // They don't have a MDL and this is not a system buffer or a fastio so this is probably some arbitrary user.
            // We can not do the processing at DPC level so try and get to a safe IRQL so we can do the processing.
            if (FltDoCompletionProcessingWhenSafe(data, flt_objects, completion_context, flags, post_read_swap_buffers_when_safe, &ret_value)) {
                // This operation has been moved to a safe IRQL, the called routine will do (or has done) the freeing so don't do it in our routine.
                clean_allocated_buffer = FALSE;
            } else {
                // We are in a state where we can not get to a safe IRQL and we do not have a MDL. There is nothing we can do to safely copy the data back to the users buffer, 
                // fail the operation and return. This shouldn't ever happen because in those situations where it is not safe to post, we should have a MDL.
                PRINT("SW: SwapPostReadBuffers:      %wZ Unable to post to a safe IRQL\n", &p2p_ctx->VolCtx->Name);
                data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                data->IoStatus.Information = 0;
            }
            leave;
        }

        // We either have a system buffer or this is a fastio operation so we are in the proper context. Copy the data handling an exception.
        try {
            RtlCopyMemory(orig_buf, p2p_ctx->SwappedBuffer, data->IoStatus.Information);
            //PRINT("SW::::::::::: going to decrypt 1: p2p->swap: %.*s", data->IoStatus.Information, p2p_ctx->SwappedBuffer);
            //PRINT("SW::::::::::: going to decrypt 1: orig_buff: %.*s", data->IoStatus.Information, orig_buf);
            decrypt(orig_buf, p2p_ctx->SwappedBuffer, data->IoStatus.Information);
            //PRINT("SW:::::::::: already decrypted 1: p2p->swap: %.*s", data->IoStatus.Information, p2p_ctx->SwappedBuffer);
            //PRINT("SW:::::::::: already decrypted 1: orig_buff: %.*s", data->IoStatus.Information, orig_buf);
            //PRINT("SW::::::::: already decrypted 1: ReadBuffer: %.*s", 15, iopb->Parameters.Read.ReadBuffer);
            //PRINT("SW::::::::: already decrypted 1: MdlAddress: %.*s", 15, iopb->Parameters.Read.MdlAddress);
            //FltSetCallbackDataDirty(data);
        } except(EXCEPTION_EXECUTE_HANDLER) {
            // The copy failed, return an error, failing the operation.
            data->IoStatus.Status = GetExceptionCode();
            data->IoStatus.Information = 0;
            PRINT("SW: SwapPostReadBuffers:          %wZ Invalid user buffer, oldB=%p, status=%x\n", &p2p_ctx->VolCtx->Name, orig_buf, data->IoStatus.Status);
        }

    } finally {
        // If we are supposed to, cleanup the allocated memory and release the volume context. The freeing of the MDL (if there is one) is handled by FltMgr.
        if (clean_allocated_buffer) {
            PRINT("SW: SwapPostReadBuffers:          %wZ newB=%p info=%Iu Freeing\n",
                &p2p_ctx->VolCtx->Name, p2p_ctx->SwappedBuffer, data->IoStatus.Information);
            FltFreePoolAlignedWithTag(flt_objects->Instance, p2p_ctx->SwappedBuffer, SECUREWORLD_PRE2POST_TAG);
            FltReleaseContext(p2p_ctx->VolCtx);
            ExFreeToNPagedLookasideList(&pre2post_context_list, p2p_ctx);
        }
    }

    return ret_value;
}

/**
* When trying to perform the buffer swap after the reading operation, there was an arbitrary users buffer without MDL, so needed to get to safe IRQL to lock it. (includes decryption)
* Note that it handles all errors by simply not doing the buffer swap.
*
* @param PFLT_CALLBACK_DATA data
*       The callback operation data.
* @param PCFLT_RELATED_OBJECTS flt_objects
*       Pointer to the FLT_RELATED_OBJECTS data structure containing opaque handles to this filter, instance, its associated volume and file object.
* @param PVOID* completion_context
*       Pointer that allows information to be passed from pre to post operation
* @param FLT_POST_OPERATION_FLAGS flags
*       Flags corresponding to the operation (if it is completed of being drained)
*
* @return FLT_PREOP_CALLBACK_STATUS
*       Always returns FLT_POSTOP_FINISHED_PROCESSING indicating the operation has finished
*/
FLT_POSTOP_CALLBACK_STATUS post_read_swap_buffers_when_safe(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS flt_objects, _In_ PVOID completion_context, _In_ FLT_POST_OPERATION_FLAGS flags) {
    PFLT_IO_PARAMETER_BLOCK iopb = data->Iopb;
    PPRE_2_POST_CONTEXT p2p_ctx = completion_context;
    PVOID orig_buf;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(flt_objects);
    UNREFERENCED_PARAMETER(flags);
    FLT_ASSERT(data->IoStatus.Information != 0);

    // This is some sort of user buffer without a MDL, lock the user buffer so we can access it. This will create a MDL for it.
    status = FltLockUserBuffer(data);

    if (!NT_SUCCESS(status)) {
        PRINT("SW: SwapPostReadBuffersWhenSafe:    %wZ Could not lock user buffer, oldB=%p, status=%x\n", &p2p_ctx->VolCtx->Name, iopb->Parameters.Read.ReadBuffer, status);

        // If we can't lock the buffer, fail the operation
        data->IoStatus.Status = status;
        data->IoStatus.Information = 0;
    } else {
        // Get a system address for this buffer.
        orig_buf = MmGetSystemAddressForMdlSafe(iopb->Parameters.Read.MdlAddress, NormalPagePriority | MdlMappingNoExecute);

        // If we couldn't get a SYSTEM buffer address, fail the operation
        if (orig_buf == NULL) {
            PRINT("SW: SwapPostReadBuffersWhenSafe:    %wZ Failed to get system address for MDL: %p\n", &p2p_ctx->VolCtx->Name, iopb->Parameters.Read.MdlAddress);
            data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            data->IoStatus.Information = 0;
        } else {
            //RtlCopyMemory(p2p_ctx->SwappedBuffer, orig_buf, data->IoStatus.Information);
            //decrypt(orig_buf, p2p_ctx->SwappedBuffer, data->IoStatus.Information);

            // Copy the data back to the original buffer. Note that we don't need a try/except because we will always have a system buffer address.
            RtlCopyMemory(orig_buf, p2p_ctx->SwappedBuffer, data->IoStatus.Information);
            //PRINT("SW::::::::::: going to decrypt 2: p2p->swap: %.*s", data->IoStatus.Information, p2p_ctx->SwappedBuffer);
            //PRINT("SW::::::::::: going to decrypt 2: orig_buff: %.*s", data->IoStatus.Information, orig_buf);
            decrypt(orig_buf, p2p_ctx->SwappedBuffer, data->IoStatus.Information);
            //PRINT("SW:::::::::: already decrypted 2: p2p->swap: %.*s", data->IoStatus.Information, p2p_ctx->SwappedBuffer);
            //PRINT("SW:::::::::: already decrypted 2: orig_buff: %.*s", data->IoStatus.Information, orig_buf);
            //PRINT("SW::::::::: already decrypted 2: ReadBuffer: %.*s", 15, iopb->Parameters.Read.ReadBuffer);
            //PRINT("SW::::::::: already decrypted 2: MdlAddress: %.*s", 15, iopb->Parameters.Read.MdlAddress);
            //FltSetCallbackDataDirty(data);
        }
    }

    // Free allocated memory and release the volume context
    PRINT("SW: SwapPostReadBuffersWhenSafe:    %wZ newB=%p info=%Iu Freeing\n", &p2p_ctx->VolCtx->Name, p2p_ctx->SwappedBuffer, data->IoStatus.Information);
    FltFreePoolAlignedWithTag(flt_objects->Instance, p2p_ctx->SwappedBuffer, SECUREWORLD_PRE2POST_TAG);
    FltReleaseContext(p2p_ctx->VolCtx);
    ExFreeToNPagedLookasideList(&pre2post_context_list, p2p_ctx);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

/**
* Performs the buffer swap before the writting operation (includes encryption)
* Note that it handles all errors by simply not doing the buffer swap.
*
* @param PFLT_CALLBACK_DATA data
*       The callback operation data.
* @param PCFLT_RELATED_OBJECTS flt_objects
*       Pointer to the FLT_RELATED_OBJECTS data structure containing opaque handles to this filter, instance, its associated volume and file object.
* @param PVOID* completion_context
*       Pointer that allows information to be passed from pre to post operation
*
* @return FLT_PREOP_CALLBACK_STATUS
*       FLT_PREOP_SUCCESS_WITH_CALLBACK - mark success and demand post operation callback
*       FLT_PREOP_SUCCESS_NO_CALLBACK - mark success and do not perform post operation callback
*       FLT_PREOP_COMPLETE - marks the request as completed so the operation is not performed
*/
FLT_PREOP_CALLBACK_STATUS pre_write_swap_buffers(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS flt_objects, _Out_ PVOID* completion_context) {
    FLT_PREOP_CALLBACK_STATUS ret_value = FLT_PREOP_SUCCESS_NO_CALLBACK;
    PFLT_IO_PARAMETER_BLOCK iopb = data->Iopb;
    ULONG write_len = iopb->Parameters.Write.Length;
    PVOID new_buf = NULL;
    PMDL new_mdl = NULL;
    PVOID orig_buf;
    PVOLUME_CONTEXT vol_ctx = NULL;
    PPRE_2_POST_CONTEXT p2p_ctx;
    NTSTATUS status;

    try {
        if (write_len == 0) {
            PRINT("SW: Writting NOTHING");
            leave;
        } else {
            PRINT("SW: Writting %d Bytes", write_len);
        }

        // Get the volume context
        status = FltGetVolumeContext(flt_objects->Filter, flt_objects->Volume, &vol_ctx);
        if (!NT_SUCCESS(status)) {
            PRINT("SW: SwapPreWriteBuffers:   Error getting volume context, status=%x\n", status);
            leave;
        }

        // If this is a non-cached I/O, round the length up to the sector size for this device
        if (FlagOn(IRP_NOCACHE, iopb->IrpFlags)) {
            write_len = (ULONG)ROUND_TO_SIZE(write_len, vol_ctx->SectorSize);
        }

        // Allocate aligned nonPaged memory for the buffer we are swapping to. This is really only necessary for noncached IO but we always
        // do it here for simplification. If we fail to get the memory, just don't swap buffers on this operation.
        new_buf = FltAllocatePoolAlignedWithTag(flt_objects->Instance, NonPagedPool, (SIZE_T)write_len, SECUREWORLD_PRE2POST_TAG);
        if (new_buf == NULL) {
            PRINT("SW: SwapPreWriteBuffers:          %wZ Failed to allocate %d bytes of memory.\n", &vol_ctx->Name, write_len);
            leave;
        }

        // If it is an IRP operation, build a MDL (Fast I/O does not need it)
        if (FlagOn(data->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION)) {

            // Allocate a MDL for the new allocated memory.
            new_mdl = IoAllocateMdl(new_buf, write_len, FALSE, FALSE, NULL);
            if (new_mdl == NULL) {
                PRINT("SW: SwapPreWriteBuffers:      %wZ Failed to allocate MDL.\n", &vol_ctx->Name);
                leave;
            }

            // Setup the MDL for the non-paged pool we just allocated
            MmBuildMdlForNonPagedPool(new_mdl);
        }

        // If the users original buffer had a MDL, get a system address.
        if (iopb->Parameters.Write.MdlAddress != NULL) {

            // This should be a simple MDL. We don't expect chained MDLs this high up the stack
            FLT_ASSERT(((PMDL)iopb->Parameters.Write.MdlAddress)->Next == NULL);

            orig_buf = MmGetSystemAddressForMdlSafe(iopb->Parameters.Write.MdlAddress, NormalPagePriority | MdlMappingNoExecute);
            if (orig_buf == NULL) {
                PRINT("SW: SwapPreWriteBuffers:            %wZ Failed to get system address for MDL: %p\n", &vol_ctx->Name, iopb->Parameters.Write.MdlAddress);

                // If we could not get a system address for the users buffer, then we are going to fail this operation.
                data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                data->IoStatus.Information = 0;
                ret_value = FLT_PREOP_COMPLETE;
                leave;
            }
        } else {
            // There was no MDL defined, use the given buffer address.
            orig_buf = iopb->Parameters.Write.WriteBuffer;
        }

        // Copy the memory, we must do this inside the try/except because we may be using a users buffer address
        try {
            //RtlCopyMemory(new_buf, orig_buf, write_len);
            encrypt(new_buf, orig_buf, write_len);
        } except(EXCEPTION_EXECUTE_HANDLER) {
            // The copy failed, return an error, failing the operation.
            PRINT("SW: SwapPreWriteBuffers:            %wZ Invalid user buffer, oldB=%p, status=%x\n", &vol_ctx->Name, orig_buf, data->IoStatus.Status);

            data->IoStatus.Status = GetExceptionCode();
            data->IoStatus.Information = 0;
            ret_value = FLT_PREOP_COMPLETE;

            leave;
        }

        // Ready to swap buffers. Get a pre2Post context structure to pass the volume context and memory buffer to the post-operation.
        p2p_ctx = ExAllocateFromNPagedLookasideList(&pre2post_context_list);
        if (p2p_ctx == NULL) {
            PRINT("SW: SwapPreWriteBuffers:                  %wZ Failed to allocate pre2Post context structure\n", &vol_ctx->Name);
            leave;
        }

        // Set the new buffers and mark as dirty
        PRINT("SW: SwapPreWriteBuffers:                  %wZ newB=%p newMdl=%p oldB=%p oldMdl=%p len=%d\n",
            &vol_ctx->Name, new_buf, new_mdl, iopb->Parameters.Write.WriteBuffer, iopb->Parameters.Write.MdlAddress, write_len);
        iopb->Parameters.Write.WriteBuffer = new_buf;
        iopb->Parameters.Write.MdlAddress = new_mdl;
        FltSetCallbackDataDirty(data);

        // Pass state to our post-operation callback.
        p2p_ctx->SwappedBuffer = new_buf;
        p2p_ctx->VolCtx = vol_ctx;

        *completion_context = p2p_ctx;

        // Return we want a post-operation callback
        ret_value = FLT_PREOP_SUCCESS_WITH_CALLBACK;

    } finally {
        // If we don't want a post-operation callback, free all pointers
        if (ret_value != FLT_PREOP_SUCCESS_WITH_CALLBACK) {
            if (new_buf != NULL) {
                FltFreePoolAlignedWithTag(flt_objects->Instance, new_buf, SECUREWORLD_PRE2POST_TAG);
            }

            if (new_mdl != NULL) {
                IoFreeMdl(new_mdl);
            }

            if (vol_ctx != NULL) {
                FltReleaseContext(vol_ctx);
            }
        }
    }

    return ret_value;
}

/**
* Frees buffers associated with the buffer swap of the writting operation
*
* @param PFLT_CALLBACK_DATA data
*       The callback operation data.
* @param PCFLT_RELATED_OBJECTS flt_objects
*       Pointer to the FLT_RELATED_OBJECTS data structure containing opaque handles to this filter, instance, its associated volume and file object.
* @param PVOID* completion_context
*       Pointer that allows information to be passed from pre to post operation
* @param FLT_POST_OPERATION_FLAGS flags
*       Flags corresponding to the operation (if it is completed of being drained)
*
* @return FLT_POSTOP_CALLBACK_STATUS
*       Always returns FLT_POSTOP_FINISHED_PROCESSING indicating the operation has finished
*/
FLT_POSTOP_CALLBACK_STATUS post_write_swap_buffers(_Inout_ PFLT_CALLBACK_DATA data, _In_ PCFLT_RELATED_OBJECTS flt_objects, _In_ PVOID completion_context, _In_ FLT_POST_OPERATION_FLAGS flags) {

    PPRE_2_POST_CONTEXT p2p_ctx = completion_context;

    UNREFERENCED_PARAMETER(flt_objects);
    UNREFERENCED_PARAMETER(flags);

    PRINT("SW: SwapPostWriteBuffers:                         %wZ newB=%p info=%Iu Freeing\n", &p2p_ctx->VolCtx->Name, p2p_ctx->SwappedBuffer, data->IoStatus.Information);

    // Free all
    FltFreePoolAlignedWithTag(flt_objects->Instance, p2p_ctx->SwappedBuffer, SECUREWORLD_PRE2POST_TAG);
    FltReleaseContext(p2p_ctx->VolCtx);
    ExFreeToNPagedLookasideList(&pre2post_context_list, p2p_ctx);

    return FLT_POSTOP_FINISHED_PROCESSING;
}



/////     ENCRYPTION/DECRYPTION FUNCTIONS     /////

///  Base encription functions
/**
* Encrypts the data in original buffer and outputs it in the encrypted buffer
*
* @param char* orig_buf
*       Pointer to the original buffer
* @param char* encrypted_buf
*       Pointer to output encrypted buffer
* @param ULONG length
*       Number of bytes to encrypt
*/
void encrypt(_Out_ char* encrypted_buf, _In_ char* orig_buf, _In_ ULONG length) {
    encrypt_XOR(encrypted_buf, orig_buf, length);
}
/**
* Decrypts the data in original buffer and outputs it in the decrypted buffer
*
* @param char* orig_buf
*       Pointer to the original buffer
* @param char* decrypted_buf
*       Pointer to output decrypted buffer
* @param ULONG length
*       Number of bytes to decrypt
*/
void decrypt(_Out_ char* decrypted_buf, _In_ char* orig_buf, _In_ ULONG length) {
    decrypt_XOR(decrypted_buf, orig_buf, length);
}


///  XOR with 0xFF based encription
/**
* Encrypts the data in original buffer and outputs it in the encrypted buffer. Applies XOR with 0xff byte to byte.
*
* @param char* orig_buf
*       Pointer to the original buffer
* @param char* encrypted_buf
*       Pointer to output encrypted buffer
* @param ULONG length
*       Number of bytes to encrypt
*/
void encrypt_XOR_OLD(_Out_ char* encrypted_buf, _In_ char* orig_buf, _In_ ULONG length) {
    for (size_t i = 0; i < length; i++) {
        encrypted_buf[i] = orig_buf[i] ^ 0xff;
    }
    if (length >= 3) {
        encrypted_buf[0] = 'e';
        encrypted_buf[1] = '-';
    }
    PRINT("SW: encrypt_XOR: (len=%d) %.*s --> %.*s", length, (length <= 30) ? length : 30, orig_buf, (length <= 30) ? length : 30, encrypted_buf);
}
void encrypt_XOR(_Out_ char* encrypted_buf, _In_ char* orig_buf, _In_ ULONG length) {
    size_t num_blocks = length / 8; // blocks of uint_64

    for (size_t i = 0; i < num_blocks; i++) {
        ((UINT64*)encrypted_buf)[i] = ((UINT64*)orig_buf)[i] ^ 0xffffffffffffffff;
    }
    for (size_t i = 0; i < length - num_blocks * 8; i++) {
        encrypted_buf[i] = orig_buf[i] ^ 0xff;
    }
    //if (length >= 3) {
    //    encrypted_buf[0] = 'e';
    //    encrypted_buf[1] = '-';
    //}
    //PRINT("SW: encrypt_XOR: (len=%d) %.*s --> %.*s", length, (length <= 30) ? length : 30, orig_buf, (length <= 30) ? length : 30, encrypted_buf);
}
void encrypt_XOR_same_buf(_Inout_ char* buf, _In_ ULONG length) {
    size_t num_blocks = length / 8; // blocks of uint_64

    for (size_t i = 0; i < num_blocks; i++) {
        ((UINT64*)buf)[i] = ((UINT64*)buf)[i] ^ 0xffffffffffffffff;
    }
    for (size_t i = 0; i < length-num_blocks*8; i++) {
        buf[i] = buf[i] ^ 0xff;
    }
    //if (length >= 3) {
    //    buf[0] = 'e';
    //    buf[1] = '-';
    //}
}

/**
* Decrypts the data in original buffer and outputs it in the decrypted buffer. Applies XOR with 0xff byte to byte.
*
* @param char* orig_buf
*       Pointer to the original buffer
* @param char* decrypted_buf
*       Pointer to output decrypted buffer
* @param ULONG length
*       Number of bytes to decrypt
*/
void decrypt_XOR_OLD(_Out_ char* decrypted_buf, _In_ char* orig_buf, _In_ ULONG length) {
    for (size_t i = 0; i < length; i++) {
        decrypted_buf[i] = orig_buf[i] ^ 0xff;
    }
    if (length >= 3) {
        decrypted_buf[0] = 'd';
        decrypted_buf[1] = '-';
    }
    PRINT("SW: decrypt_XOR: (len=%d) %.*s --> %.*s", length, (length <= 30) ? length : 30, orig_buf, (length <= 30) ? length : 30, decrypted_buf);
}
void decrypt_XOR(_Out_ char* decrypted_buf, _In_ char* orig_buf, _In_ ULONG length) {
    size_t num_blocks = length / 8; // blocks of uint_64

    for (size_t i = 0; i < num_blocks; i++) {
        ((UINT64*)decrypted_buf)[i] = ((UINT64*)orig_buf)[i] ^ 0xffffffffffffffff;
    }
    for (size_t i = 0; i < length - num_blocks * 8; i++) {
        decrypted_buf[i] = orig_buf[i] ^ 0xff;
    }
    //if (length >= 3) {
    //    decrypted_buf[0] = 'd';
    //    decrypted_buf[1] = '-';
    //}
    //PRINT("SW: decrypt_XOR: (len=%d) %.*s --> %.*s", length, (length <= 30) ? length : 30, orig_buf, (length <= 30) ? length : 30, decrypted_buf);
}
void decrypt_XOR_same_buf(_Inout_ char* buf, _In_ ULONG length) {
    size_t num_blocks = length / 8; // blocks of uint_64

    for (size_t i = 0; i < num_blocks; i++) {
        ((UINT64*)buf)[i] = ((UINT64*)buf)[i] ^ 0xffffffffffffffff;
    }
    for (size_t i = 0; i < length - num_blocks * 8; i++) {
        buf[i] = buf[i] ^ 0xff;
    }
    //if (length >= 3) {
    //    buf[0] = 'd';
    //    buf[1] = '-';
    //}
}




//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////

// From here onwards everything is commented out. Only for testing purposes
/*


/////     HOW TO PRINT DIFFERENT TYPES     /////

PUNICODE_STRING         %wZ
ULONG                   %d
char                    %c





//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <wchar.h>

const wchar_t * p_secure_path = L"\\Device\\HarddiskVolume2\\Users\\Sergio\\Desktop\\Testing\\Inside\\"; // Len: 60
const wchar_t * p_file_path = L"\\Device\\HarddiskVolume2\\Users\\Sergio\\Desktop\\Testing\\Inside\\fichero.txt"; // Len: ?
wchar_t * p_path_match = NULL;

int main()
{
    p_path_match = wcsstr(p_file_path, p_secure_path);
    wprintf (L"p1 %p \r\np2: %p \r\n", p_file_path, p_path_match);
    if (p_file_path==p_path_match) wprintf(L"IGUALES \r\n");

    int SecureFolderPathLen = (int)wcslen(p_secure_path);
    wprintf (L"Secure path: %ls \r\n", p_secure_path);
    wprintf (L"Length: %d \r\n", SecureFolderPathLen);

    int FilePathLen = (int)wcslen(p_file_path);
    wprintf (L"File path: %ls \r\n", p_file_path);
    wprintf (L"Length: %d \r\n", FilePathLen);

    wchar_t pp_file_name[260];
    int file_name_len = wcslen(p_file_path) - wcslen(p_secure_path);
    wcsncpy( pp_file_name, &p_file_path[SecureFolderPathLen], (size_t)file_name_len+1 );

    wprintf (L"File name: %ls \r\n", pp_file_name);
    wprintf (L"Length: %d \r\n", (int)wcslen(pp_file_name));
    wprintf (L"Length: %d \r\n", file_name_len);

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


///// THIS WORKS to know the process which requested the operation /////

PEPROCESS objCurProcess = NULL;
HANDLE hProcess;
UNICODE_STRING fullPath;
NTSTATUS status;

objCurProcess = IoThreadToProcess(data->Thread);

hProcess = PsGetProcessId(objCurProcess);

fullPath.Length = 0;
fullPath.MaximumLength = 520;
fullPath.Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, 520, 'uUT1');
if (fullPath.Buffer) {
    status = get_process_image_path(hProcess, &fullPath);
    DbgPrint("SW: PreCreate requestor status: %d", (int)status);

    if (NT_SUCCESS(status)) {
        DbgPrint("SW: PreCreate from: %wZ", fullPath);
    }
    ExFreePoolWithTag(fullPath.Buffer, 'uUT1');
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



*/