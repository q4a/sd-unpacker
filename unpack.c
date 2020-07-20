/*
** SafeDisc v3 unpacker - unpack.c
** Author: Fatbag
** Revision: 2014-02-18
** License: Public domain (no warranties, express or implied)
** From: http://niotso.org/??
** Compile: gcc -m32 -Wall -Wextra -pedantic -ansi -Os -s -mconsole -o unpack.exe unpack.c -ludis86
*/

/*
** SafeDisc v3 works in the following manner for all games.
**
** The game process extracts various DLLs, loads one of them into memory, and
** then spawns a child process that debugs the game process. Once the debugger
** is attached, the game process spins up the disc and reads off a symmetric
** encryption key, unpacks most of itself, and jumps to the game's original
** entry point.
**
** At this point, all non-code sections of the game are completely unpacked
** and the code section is mostly unpacked, except that:
** 1. various instructions have been overwritten with 0xCC bytes (int 3
**    breakpoints);
** 2. various instructions have been overwritten with calls to a function
**    (and sometimes scrambled data after that call) which jumps to one of the
**    extracted DLLs and eventually restores the original instructions, flushes
**    the CPU cache, and jumps back; and
** 3. various addresses of imported DLLs have been overwritten with addresses
**    to one of the extracted DLLs, which, using the return address as a
**    deciding factor, eventually jump to the original imported function.
**
** The debugger process is debugging the game process this whole time. When a
** 0xCC instruction is executed by some thread in the game process, the game
** process traps to the debugger, and the debugger replaces those 0xCC bytes
** with the original bytes, flushes the CPU cache, and resumes the process.
**
** The spurious 0xCC bytes of method 1 are called nanomites. The spurious calls
** of method 2 are called stolen bytes. The call redirections of method 3 form
** import address table obfuscation. The solution to all of these methods is to
** simply run the algorithm against itself.
**
** When SetEvent is called in the game process, this is a reliable indicator
** that section unpacking has finished and that the debugger will attach in a
** subsequent call to WaitForSingleObject. So we hook SetEvent to enable the
** hook for WaitForSingleObject, which subsequently signals to our tool to dump
** all sections in memory and then fix up the code section.
**
** To fix up the code section, we disassemble its contents and perform the
** following steps:
** 1. Suspend all running threads, and hook EnterCriticalSection and
**    LeaveCriticalSection to make function calls reentrant.
** 2. Search for 0xCC instructions that do not appear to be function padding or
**    intermixed data, and for each one, create a new thread directly(*) on
**    that instruction, let the debugger trip and patch those bytes, and then
**    terminate the thread.
** 3. Search for jumps or calls to the functions of method 2, and for each one,
**    create a new thread directly(*) on that instruction, let the function
**    patch those bytes, and then terminate the thread.
** 4. Step 2 may have produced more stolen bytes and step 3 may have produced
**    more nanomites, so repeat steps 2 and 3 until they no longer perform any
**    fixups.
** 5. Enumerate all exported functions in all DLLs loaded in the game process
**    and use this information to find the locations of the game's original
**    import table and block of import address tables; these, together with the
**    ordinal-name tables and ordinal-name RVA tables, have all been modified
**    slightly by SafeDisc.
** 6. Hook every function from each DLL loaded in the game process, and then
**    search for jumps or calls to the functions of method 3, and for each one,
**    create a new thread directly(*) on that instruction, let the function
**    reach one of our functions, and then terminate the thread, marking that
**    that function was referenced.
** 7. Reconstruct the import table, its associated data, and the import address
**    tables, and patch each imported jump/call instruction to refer to the
**    correct function in the correct import address table.
**
** (*) Our thread will actually be created in our own code which sets up a
** structured exception handler before jumping to the instruction.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <tlhelp32.h>
#include <udis86.h>

#define write_uint32(dest, src) do *(uint32_t*)(dest) = (uint32_t)(src); while(0)

static uint8_t hook_code[] = {
    /* stack_frame: */
        0x00, 0x00, 0x00, 0x00,                         /* db 0x04 */
    /* WaitForSingleObject_flag: */
        0x00,                                           /* db 0x01 */
    /* LeaveCriticalSection_flag: */
        0x00,                                           /* db 0x01 */

    /* signal_and_wait: */
        0x89, 0x25, 0x00, 0x00, 0x00, 0x00,             /* mov dword ptr [stack_frame], esp */
        0xff, 0x74, 0xe4, 0x04,                         /* push dword ptr [esp+0x04] */
        0xe8, 0x00, 0x00, 0x00, 0x00,                   /* call SetEvent_after_hotpatch */
        0x6a, 0xff,                                     /* push -1 */
        0xff, 0x74, 0xe4, 0x0c,                         /* push dword ptr [esp+0x0c] */
        0xe8, 0x00, 0x00, 0x00, 0x00,                   /* call WaitForSingleObject_after_hotpatch ; returns 0 */
        0xc2, 0x08, 0x00,                               /* ret 0x08 */

    /* entry_point_hook: */
        0x68, 0x00, 0x00, 0x00, 0x00,                   /* push (game|debugger)_entry_point_response */
        0x68, 0x00, 0x00, 0x00, 0x00,                   /* push (game|debugger)_entry_point_event */
        0xe8, 0xd4, 0xff, 0xff, 0xff,                   /* call signal_and_wait */
        0xe9, 0x00, 0x00, 0x00, 0x00,                   /* jmp entry_point */

    /* CreateProcessA_hook: */
        0x68, 0x00, 0x00, 0x00, 0x00,                   /* push CreateProcessA_response */
        0x68, 0x00, 0x00, 0x00, 0x00,                   /* push CreateProcessA_event */
        0xe8, 0xc0, 0xff, 0xff, 0xff,                   /* call signal_and_wait */
        0x40,                                           /* inc eax */
        0xc2, 0x28, 0x00,                               /* ret 0x28 */

    /* SetEvent_hook: */
        0xc6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01,       /* mov byte ptr [WaitForSingleObject_flag], 0x01 */
        0xe9, 0x00, 0x00, 0x00, 0x00,                   /* jmp SetEvent_after_hotpatch */

    /* WaitForSingleObject_hook: */
        0xf6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01,       /* test byte ptr [WaitForSingleObject_flag], 0x01 */
        0x0f, 0x84, 0x00, 0x00, 0x00, 0x00,             /* jz WaitForSingleObject_after_hotpatch */
        0x6a, 0xff,                                     /* push -1 */
        0xff, 0x74, 0xe4, 0x08,                         /* push dword ptr [esp+0x08] */
        0xe8, 0x00, 0x00, 0x00, 0x00,                   /* call WaitForSingleObject_after_hotpatch */
    /* WaitForSingleObject_hook_call: */
        0x68, 0x00, 0x00, 0x00, 0x00,                   /* push current_thread_handle ; suspend indefinitely */
        0x68, 0x00, 0x00, 0x00, 0x00,                   /* push WaitForSingleObject_event */
        0xe8, 0x89, 0xff, 0xff, 0xff,                   /* call signal_and_wait */

    /* VirtualProtect_hook: */
        0x81, 0x7c, 0xe4, 0x04, 0x00, 0x00, 0x00, 0x00, /* cmp dword ptr [esp+0x04], stolen_bytes_address */
        0x0f, 0x94, 0x05, 0x00, 0x00, 0x00, 0x00,       /* sete byte ptr [LeaveCriticalSection_flag] */
        0xe9, 0x00, 0x00, 0x00, 0x00,                   /* jmp VirtualProtect_after_hotpatch */

    /* address_range_compare: */
        0x8b, 0x44, 0xe4, 0x04,                         /* mov eax, dword ptr [esp+4] */
        0x3d, 0x00, 0x00, 0x00, 0x00,                   /* cmp eax, address_start */
        0x72, 0x09,                                     /* jb address_range_compare_return */
        0x3d, 0x00, 0x00, 0x00, 0x00,                   /* cmp eax, address_end */
        0x77, 0x02,                                     /* ja address_range_compare_return */
        0x39, 0xc0,                                     /* cmp eax, eax */
    /* address_range_compare_return: */
        0xc3,                                           /* ret */

    /* EnterCriticalSection_hook: */
        0xe8, 0xe6, 0xff, 0xff, 0xff,                   /* call address_range_compare */
        0x0f, 0x85, 0x00, 0x00, 0x00, 0x00,             /* jnz EnterCriticalSection_after_hotpatch */
    /* EnterCriticalSection_hook_return: */
        0xc2, 0x04, 0x00,                               /* ret 0x04 */

    /* LeaveCriticalSection_hook: */
        0xe8, 0xd8, 0xff, 0xff, 0xff,                   /* call address_range_compare */
        0x0f, 0x85, 0x00, 0x00, 0x00, 0x00,             /* jnz LeaveCriticalSection_after_hotpatch */
        0xf6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01,       /* test byte ptr [LeaveCriticalSection_hook], 0x01 */
        0x74, 0xe9,                                     /* jz EnterCriticalSection_hook_return */
    /* LeaveCriticalSection_hook_terminate */
        0x68, 0x00, 0x00, 0x00, 0x00,                   /* push current_thread_handle */
        0xe8, 0x00, 0x00, 0x00, 0x00,                   /* call TerminateThread_after_hotpatch */

    /* exported_function_hook: ; enabled only for fix_imports() and overwrites all the other hooks */
        0x5a,                                           /* pop edx */
        0x58,                                           /* pop eax */
        0x50,                                           /* push eax */
        0x3d, 0x00, 0x00, 0x00, 0x00,                   /* cmp eax, new_thread_exception_handler */
        0x0f, 0x94, 0x05, 0x00, 0x00, 0x00, 0x00,       /* sete byte ptr [WaitForSingleObject_flag] ; jump vs. call flag */
        0x74, 0x07,                                     /* jz exported_function_hook_install_jump_or_call */
        0xe8, 0xa9, 0xff, 0xff, 0xff,                   /* call address_range_compare */
        0x75, 0x08,                                     /* jnz exported_function_hook_return */
    /* exported_function_hook_terminate */
        0x89, 0x15, 0x00, 0x00, 0x00, 0x00,             /* mov dword ptr [stack_frame], edx */
        0xeb, 0xd6,                                     /* jmp LeaveCriticalSection_hook_terminate */
    /* exported_function_hook_return: */
        0x42,                                           /* inc edx */
        0x42,                                           /* inc edx */
        0xff, 0xe2,                                     /* jmp edx */

    /* new_thread_entry_point: */
        0x31, 0xc0,                                     /* xor eax, eax */
        0x6a, 0xff,                                     /* push -1 */
        0x68, 0x00, 0x00, 0x00, 0x00,                   /* push new_thread_exception_handler */
        0x64, 0xff, 0x30,                               /* push dword ptr fs:[eax] */
        0x64, 0x89, 0x20,                               /* mov dword ptr fs:[eax], esp */
        0xe8, 0x00, 0x00, 0x00, 0x00,                   /* call new_thread_destination */
    /* new_thread_exception_handler: */
        0x68, 0x00, 0x00, 0x00, 0x00,                   /* push exception_handler_response */
        0x68, 0x00, 0x00, 0x00, 0x00,                   /* push exception_handler_event */
        0xe8, 0xed, 0xfe, 0xff, 0xff,                   /* call signal_and_wait */
        0xc3                                            /* ret */
};

enum {
    game_entry_point_event,
    CreateProcessA_event,
    WaitForSingleObject_event,
    exception_handler_event,
    debugger_entry_point_event,
    game_entry_point_response,
    CreateProcessA_response,
    exception_handler_response,
    debugger_entry_point_response,
    event_count
};
static HANDLE events[event_count] = {NULL};

struct process_context {
    PROCESS_INFORMATION pi;
    uint32_t pe_header_offset;
    uint16_t pe_header_size;
    uint16_t number_of_sections;
    uint32_t text_section_address;
    uint32_t text_section_size;
    uint32_t text_section_index;
    uint8_t dos_header[1024];
    uint8_t pe_header[1024];
    uint8_t section_table[64][40];
    uint8_t *section_data[64];
    uint32_t section_address[64];
    uint32_t section_size[64];
    uint8_t *text_section_references, *nanomite_false_positives;
    uint32_t entry_point;
    uint32_t image_base;
    uint32_t hook_code_address;
    uint32_t original_entry_point;
    HANDLE new_thread;
};
static struct process_context game_ctx, debugger_ctx;

enum {
    SetEvent_api,
    WaitForSingleObject_api,
    CreateProcessA_api,
    VirtualProtect_api,
    EnterCriticalSection_api,
    LeaveCriticalSection_api,
    TerminateThread_api,
    api_count
};
static const char *const api_string[api_count] = {
    "SetEvent",
    "WaitForSingleObject",
    "CreateProcessA",
    "VirtualProtect",
    "EnterCriticalSection",
    "LeaveCriticalSection",
    "TerminateThread"
};
static uint32_t api_address[api_count];

struct exported_symbol {
    struct imported_dll *parent_dll;
    char name[268];
    uint16_t ordinal;
    uint32_t address;
    int is_executable;
    int is_referenced;
};

struct export_table_desc {
    uint32_t pe_header;
    uint32_t symbol_count;
    uint32_t export_table;
    uint32_t export_table_size;
    uint32_t address_table;
    uint32_t name_table;
    uint32_t ordinal_table;
};

struct imported_dll {
    char name[268];
    uint32_t base;
    uint32_t size;
    struct export_table_desc et;
    struct exported_symbol *symbols;
    uint32_t referenced_symbol_count;
};

struct import_descriptor {
    struct imported_dll *dll;
    uint32_t ordinal_name_rva_table_address;
    uint32_t dll_name_address;
    uint32_t iat_address;
};

struct exe_import_table {
    uint32_t import_section_index;
    uint32_t import_table_region_address;
    uint32_t import_table_region_size;
    uint32_t import_table_desc_count;
    uint32_t ordinal_name_rva_region_address;
    uint32_t ordinal_name_rva_region_size;
    uint32_t ordinal_name_region_address;
    uint32_t ordinal_name_region_size;
    uint32_t iat_section_index;
    uint32_t iat_region_address;
    uint32_t iat_region_size;
    struct import_descriptor descriptors[64];
};

static struct imported_dll *imported_dlls = NULL;
static uint32_t imported_dll_count;
static uint32_t unpack_dll_index;
static uint32_t total_symbol_count;
static uint32_t *sorted_symbol_addresses = NULL;
static struct exported_symbol **sorted_symbol_ptrs;
static struct exe_import_table import_table;

static ud_t ud;
static uint32_t kernel32_base, ntdll_base;
static uint32_t current_thread_handle;
static char outfile[268] = "";
static HANDLE hOutFile = INVALID_HANDLE_VALUE;
static HANDLE hSnapshot = INVALID_HANDLE_VALUE;
static volatile int shutting_down = 0;

static int Shutdown(const char *function_name)
{
    uint32_t i;
    int ret = EXIT_SUCCESS;
    shutting_down = 1;

    if(function_name){
        DWORD error;
        char error_message[256] = "";
        ret = EXIT_FAILURE;
        error = GetLastError();
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, LANG_USER_DEFAULT, error_message, 256, NULL);
        fprintf(stderr, "unpack: Error: %s failed (GetLastError() = %lu: %s).\n", function_name, error, error_message);
    }

    if(debugger_ctx.pi.hThread)
        CloseHandle(debugger_ctx.pi.hThread);
    if(debugger_ctx.pi.hProcess){
        TerminateProcess(debugger_ctx.pi.hProcess, 0);
        CloseHandle(debugger_ctx.pi.hProcess);
    }
    if(game_ctx.pi.hThread)
        CloseHandle(game_ctx.pi.hThread);
    if(game_ctx.pi.hProcess){
        TerminateProcess(game_ctx.pi.hProcess, 0);
        CloseHandle(game_ctx.pi.hProcess);
    }
    for(i=0; i<64; i++)
        free(game_ctx.section_data[i]);
    for(i=0; i<64; i++)
        free(debugger_ctx.section_data[i]);
    if(game_ctx.text_section_references)
        free(game_ctx.text_section_references);
    if(debugger_ctx.text_section_references)
        free(debugger_ctx.text_section_references);
    if(imported_dlls){
        for(i=0; i<imported_dll_count; i++)
            free(imported_dlls[i].symbols);
        free(imported_dlls);
    }
    if(sorted_symbol_addresses)
        free(sorted_symbol_addresses);
    for(i=0; i<event_count; i++)
        if(events[i])
            CloseHandle(events[i]);
    if(hOutFile != INVALID_HANDLE_VALUE){
        CloseHandle(hOutFile);
        if(ret != EXIT_SUCCESS && outfile[0] != '\0')
            DeleteFile(outfile);
    }

    return ret;
}

static BOOL WINAPI HandlerRoutine(DWORD dwCtrlType)
{
    if(shutting_down) /* if we are interrupted in the middle of shutting down, don't do anything */
        return TRUE;

    if(dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_CLOSE_EVENT)
        Shutdown(NULL);

    return FALSE;
}

static int sub_error(const char *Message){
    fprintf(stderr, "unpack: Error: %s failed.\n", Message);
    return 0;
}

static int read_process_memory(HANDLE hProcess, uint32_t dest, void *source, uint32_t size)
{
    SIZE_T bytes_transferred;

    return (ReadProcessMemory(hProcess, (void*)dest, source, size, &bytes_transferred) != FALSE && bytes_transferred == size);
}

static int write_process_memory(HANDLE hProcess, uint32_t dest, void *source, uint32_t size)
{
    DWORD mem_protection;
    SIZE_T bytes_transferred;
    int result = 1;

    if(VirtualProtectEx(hProcess, (void*)dest, size, PAGE_EXECUTE_READWRITE, &mem_protection) == FALSE)
        return 0;

    result &= (WriteProcessMemory(hProcess, (void*)dest, source, size, &bytes_transferred) != FALSE
        && bytes_transferred == size);
    result &= (VirtualProtectEx(hProcess, (void*)dest, size, mem_protection, &mem_protection) != FALSE);
    result &= (FlushInstructionCache(hProcess, (void*)dest, size) != FALSE);
    return result;
}

static int parse_exe_header(struct process_context *pctx)
{
    HANDLE hProcess;
    unsigned index;

    hProcess = pctx->pi.hProcess;

    if(!read_process_memory(hProcess, pctx->image_base+0x3c, &pctx->pe_header_offset, 4))
        return sub_error("read_process_memory for the PE header location");
    if(pctx->pe_header_offset == 0 || pctx->pe_header_offset > 1024)
        return sub_error("pe_header has invalid range; read_process_memory");

    if(!read_process_memory(hProcess, pctx->image_base, pctx->dos_header, pctx->pe_header_offset))
        return sub_error("read_process_memory for the DOS header");

    if(!read_process_memory(hProcess, pctx->image_base+pctx->pe_header_offset+0x14, &pctx->pe_header_size, 2))
        return sub_error("read_process_memory for the PE optional header size");
    if(pctx->pe_header_size < 224 || pctx->pe_header_size > 1024-24)
        return sub_error("pe_header_size has invalid range; read_process_memory");
    pctx->pe_header_size += 24;

    if(!read_process_memory(hProcess, pctx->image_base+pctx->pe_header_offset, pctx->pe_header, pctx->pe_header_size))
        return sub_error("read_process_memory for the PE header");
    memcpy(&pctx->number_of_sections, pctx->pe_header+0x06, 2);
    if(pctx->number_of_sections == 0 || pctx->number_of_sections > 64)
        return sub_error("number_of_sections has invalid range; read_process_memory");

    if(!read_process_memory(hProcess, pctx->image_base+pctx->pe_header_offset+pctx->pe_header_size,
        pctx->section_table, pctx->number_of_sections*40))
        return sub_error("read_process_memory for the section table");

    for(index=0; index<pctx->number_of_sections; index++){
        memcpy(&pctx->section_size[index], pctx->section_table[index] + 0x08, 4);
        if(pctx->section_size[index] == 0 || pctx->section_size[index] >= 0x80000000)
            return sub_error("section size has invalid range; read_process_memory");
        memcpy(&pctx->section_address[index], pctx->section_table[index] + 0x0c, 4);
        if(pctx->section_address[index] == 0 || pctx->section_address[index] > 0xFFFFFFFF - pctx->image_base
            || (pctx->section_address[index] += pctx->image_base) > 0xFFFFFFFF - pctx->section_size[index])
            return sub_error("section address has invalid range; read_process_memory");
    }

    for(index=0; index<pctx->number_of_sections; index++)
        if(!strcmp((char*)pctx->section_table[index], ".text"))
            break;
    if(index == pctx->number_of_sections)
        return sub_error(".text section not found; read_process_memory");

    pctx->text_section_index = index;
    if(pctx->section_size[index] < 1024)
        return sub_error(".text section size has invalid range; read_process_memory");
    printf("* .text section index: %u\n", index);
    printf("* .text section memory size: %08X\n", pctx->section_size[index]);
    printf("* .text section memory address: %08X\n", pctx->section_address[index]);

    return 1;
}

static int create_process_and_inject_hook_code(struct process_context *pctx, const char *executable_name,
    char *command, const char *directory, WORD show_window, HANDLE hook_event, HANDLE hook_response)
{
    HANDLE hProcess, hThread;
    STARTUPINFO si = {0};
    CONTEXT ctx;
    uint32_t hook_code_address;

    /* create the process with dwCreationFlags = CREATE_SUSPENDED so we can inject our code and hook,
    ** and with bInheritHandles = TRUE so it can inherit the event objects and hProcess */
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = show_window;
    if(CreateProcess(executable_name, command, NULL, NULL, TRUE, CREATE_SUSPENDED | NORMAL_PRIORITY_CLASS,
        NULL, directory, &si, &pctx->pi) == FALSE)
        return sub_error("CreateProcess");
    hProcess = pctx->pi.hProcess;
    hThread = pctx->pi.hThread;
    printf("* hProcess: %08x (process id: %08X)\n", (unsigned)hProcess, (unsigned)pctx->pi.dwProcessId);
    printf("* hThread: %08x (thread id: %08X)\n", (unsigned)hThread, (unsigned)pctx->pi.dwThreadId);

    /* use GetThreadContext to read eax (holding the entry point of the process)
    ** and ebx (holding the pointer to the process environment block, which will tell us the image base) */
    ctx.ContextFlags = CONTEXT_INTEGER;
    if(GetThreadContext(hThread, &ctx) == FALSE)
        return sub_error("GetThreadContext");
    pctx->entry_point = ctx.Eax;
    printf("* Initial entry point: %08X\n", (uint32_t)ctx.Eax);
    printf("* Process environment block: %08X\n", (uint32_t)ctx.Ebx);

    if(!read_process_memory(hProcess, ctx.Ebx+0x08, &pctx->image_base, 4))
        return sub_error("read_process_memory for the image base");
    printf("* Image base: %08x\n", pctx->image_base);

    if(!parse_exe_header(pctx))
        return sub_error("parse_exe_header");

    /* allocate readable, writeable, executable memory for our injected code */
    hook_code_address = (uint32_t) VirtualAllocEx(hProcess, NULL, sizeof(hook_code),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(!hook_code_address)
        return sub_error("VirtualAllocEx");
    pctx->hook_code_address = hook_code_address;
    printf("* Hook code location: %08X\n", hook_code_address);

    /* fill in API references (relative to eip) */
    write_uint32(hook_code + 0x11, api_address[SetEvent_api] + 0x02 - (hook_code_address + 0x11 + 0x04));
    write_uint32(hook_code + 0x52, api_address[SetEvent_api] + 0x02 - (hook_code_address + 0x52 + 0x04));
    write_uint32(hook_code + 0x1c, api_address[WaitForSingleObject_api] + 0x02 - (hook_code_address + 0x1c + 0x04));
    write_uint32(hook_code + 0x5f, api_address[WaitForSingleObject_api] + 0x02 - (hook_code_address + 0x5f + 0x04));
    write_uint32(hook_code + 0x6a, api_address[WaitForSingleObject_api] + 0x02 - (hook_code_address + 0x6a + 0x04));
    write_uint32(hook_code + 0x8d, api_address[VirtualProtect_api] + 0x02 - (hook_code_address + 0x8d + 0x04));
    write_uint32(hook_code + 0xad, api_address[EnterCriticalSection_api] + 0x02 - (hook_code_address + 0xad + 0x04));
    write_uint32(hook_code + 0xbb, api_address[LeaveCriticalSection_api] + 0x02 - (hook_code_address + 0xbb + 0x04));
    write_uint32(hook_code + 0xce, api_address[TerminateThread_api] + 0x02 - (hook_code_address + 0xce + 0x04));

    /* event objects (absolute) */
    write_uint32(hook_code + 0x29, hook_event);
    write_uint32(hook_code + 0x24, hook_response);
    write_uint32(hook_code + 0x3d, events[CreateProcessA_event]);
    write_uint32(hook_code + 0x38, events[CreateProcessA_response]);
    write_uint32(hook_code + 0x74, events[WaitForSingleObject_event]);
    write_uint32(hook_code + 0x6f, current_thread_handle);
    write_uint32(hook_code + 0xc9, current_thread_handle);
    write_uint32(hook_code + 0x110, events[exception_handler_event]);
    write_uint32(hook_code + 0x10b, events[exception_handler_response]);

    /* stack frame field (absolute) */
    write_uint32(hook_code + 0x08, hook_code_address + 0x00);
    write_uint32(hook_code + 0xec, hook_code_address + 0x00);

    /* WaitForSingleObject flag (absolute) */
    write_uint32(hook_code + 0x4c, hook_code_address + 0x04);
    write_uint32(hook_code + 0x58, hook_code_address + 0x04);
    write_uint32(hook_code + 0xdd, hook_code_address + 0x04);

    /* LeaveCriticalSection flag (absolute) */
    write_uint32(hook_code + 0x88, hook_code_address + 0x05);
    write_uint32(hook_code + 0xc1, hook_code_address + 0x05);

    /* exception handler field (absolute) */
    write_uint32(hook_code + 0xd6, hook_code_address + 0x10a);
    write_uint32(hook_code + 0xfb, hook_code_address + 0x10a);

    /* unconditional jump to the process's original entry point (relative to eip) */
    write_uint32(hook_code + 0x33, ctx.Eax - (hook_code_address + 0x33 + 0x04));

    /* inject the code */
    if(!write_process_memory(hProcess, hook_code_address, hook_code, sizeof(hook_code)))
        return sub_error("write_process_memory");

    /* relocate the entry point to entry_point_hook */
    ctx.Eax = hook_code_address + 0x23;
    if(SetThreadContext(hThread, &ctx) == FALSE)
        return sub_error("SetThreadContext");

    /* resume the thread and wait until the entry point has been reached (which assures that kernel32.dll has loaded) */
    if(ResumeThread(hThread) == (DWORD)-1)
        return sub_error("ResumeThread");
    if(WaitForSingleObject(hook_event, INFINITE) != WAIT_OBJECT_0)
        return sub_error("WaitForSingleObject");

    return 1;
}

static int find_game_oep()
{
    HANDLE hProcess;
    uint32_t text_section_address, text_section_size;
    uint8_t buffer[5];
    uint32_t ptr;

    hProcess = game_ctx.pi.hProcess;
    text_section_address = game_ctx.section_address[game_ctx.text_section_index];
    text_section_size = game_ctx.section_size[game_ctx.text_section_index];

    /* start at the initial entry point, and search for the first unconditional jmp with
    ** a 4-byte operand into the text section */
    ptr = game_ctx.entry_point;
    while(1){
        if(!read_process_memory(hProcess, ptr, buffer, 5))
            return sub_error("read_process_memory for the jump instruction");
        if(buffer[0] == 0xe9){
            uint32_t destination;
            memcpy(&destination, buffer+1, 4);
            destination += ptr + 5;
            if(destination >= text_section_address && destination - text_section_address < text_section_size){
                game_ctx.original_entry_point = destination;
                printf("* original entry point: %08X\n", destination);
                break;
            }
        }
        ptr++;
    }

    return 1;
}

static int install_hotpatch(uint32_t api_address, uint32_t hooked_version_address, uint8_t jump_or_call_opcode)
{
    HANDLE hProcess;
    uint8_t hotpatch_bytes[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0xeb, 0xf9};

    hProcess = game_ctx.pi.hProcess;
    hotpatch_bytes[0] = jump_or_call_opcode;

    write_uint32(hotpatch_bytes + 0x01, hooked_version_address - api_address);

    if(!write_process_memory(hProcess, api_address - 0x05, hotpatch_bytes, 7))
        return sub_error("write_process_memory");

    return 1;
}

static int install_game_hooks()
{
    if(!install_hotpatch(api_address[CreateProcessA_api], game_ctx.hook_code_address + 0x37, 0xe9))
        return sub_error("install_hotpatch for CreateProcessA");
    if(!install_hotpatch(api_address[SetEvent_api], game_ctx.hook_code_address + 0x4a, 0xe9))
        return sub_error("install_hotpatch for SetEvent");
    if(!install_hotpatch(api_address[WaitForSingleObject_api], game_ctx.hook_code_address + 0x56, 0xe9))
        return sub_error("install_hotpatch for WaitForSingleObject");
    if(!install_hotpatch(api_address[VirtualProtect_api], game_ctx.hook_code_address + 0x7d, 0xe9))
        return sub_error("install_hotpatch for VirtualProtect");
    if(!install_hotpatch(api_address[EnterCriticalSection_api], game_ctx.hook_code_address + 0xa6, 0xe9))
        return sub_error("install_hotpatch for EnterCriticalSection");
    if(!install_hotpatch(api_address[LeaveCriticalSection_api], game_ctx.hook_code_address + 0xb4, 0xe9))
        return sub_error("install_hotpatch for LeaveCriticalSection");
    return 1;
}

static int get_debugger_process_args(char *executable_name, char *command, char *directory, uint32_t *pi_address)
{
    HANDLE hProcess;
    uint32_t stack_frame;
    uint32_t args[11]; /* args[0] is the return address;
                       ** the only arguments we care about are args[1] (lpApplicationName),
                       ** args[2] (lpCommandLine), args[8] (lpCurrentDirectory), and
                       ** args[10] (lpProcessInformation) */

    hProcess = game_ctx.pi.hProcess;

    /* read the value of esp that we wrote to stack_frame in CreateProcessA_hook */
    if(!read_process_memory(hProcess, game_ctx.hook_code_address+0x00, &stack_frame, 4))
        return sub_error("read_process_memory for stack frame");
    stack_frame += 0x0c; /* skip over the stack frame for signal_and_wait */

    if(!read_process_memory(hProcess, stack_frame, args, 4*11))
        return sub_error("read_process_memory for CreateProcessA arguments");

    if(!read_process_memory(hProcess, args[1], executable_name, 266))
        return sub_error("read_process_memory for debugger's executable name");
    executable_name[266] = '\0';
    printf("* Executable name: %s\n", executable_name);

    if(!read_process_memory(hProcess, args[2], command, 266))
        return sub_error("read_process_memory for debugger's command");
    command[266] = '\0';
    printf("* Command: %s\n", command);

    if(!read_process_memory(hProcess, args[8], directory, 266))
        return sub_error("read_process_memory for debugger's directory");
    directory[266] = '\0';
    printf("* Directory: %s\n", directory);

    *pi_address = args[10];

    return 1;
}

static int read_export_table(HANDLE hProcess, uint32_t image_base, struct export_table_desc *et)
{
    /* read the PE header location */
    if(!read_process_memory(hProcess, image_base + 0x3c, &et->pe_header, 4))
        return sub_error("read_process_memory for the PE header location");
    if(et->pe_header == 0 || et->pe_header > 1024)
        return sub_error("pe_header has invalid range; read_process_memory");
    et->pe_header += image_base;

    /* read the export table location (DataDirectory[0].address of the PE optional header) */
    if(!read_process_memory(hProcess, et->pe_header + 0x78, &et->export_table, 4))
        return sub_error("read_process_memory for the export table location");
    if(et->export_table >= 0x80000000 || et->export_table > 0xFFFFFFFF - image_base)
        return sub_error("export_table has invalid range; read_process_memory");
    if(et->export_table == 0)
        return 1;
    et->export_table += image_base;

    /* read the export table location (DataDirectory[0].size of the PE optional header) */
    if(!read_process_memory(hProcess, et->pe_header + 0x7c, &et->export_table_size, 4))
        return sub_error("read_process_memory for the export table location");
    if(et->export_table_size == 0 || et->export_table_size > 0xFFFFFFFF - et->export_table)
        return sub_error("export_table_size has invalid range; read_process_memory");

    /* read the export symbol count */
    if(!read_process_memory(hProcess, et->export_table + 0x18, &et->symbol_count, 4))
        return sub_error("read_process_memory for the export symbol count");

    /* read the export address table location */
    if(!read_process_memory(hProcess, et->export_table + 0x1c, &et->address_table, 4))
        return sub_error("read_process_memory for the export address table location");
    if(et->address_table >= 0x80000000 || et->address_table > 0xFFFFFFFF - image_base)
        return sub_error("address_table has invalid range; read_process_memory");
    if(et->address_table == 0)
        return 1;
    et->address_table += image_base;

    /* read the export name table location */
    if(!read_process_memory(hProcess, et->export_table + 0x20, &et->name_table, 4))
        return sub_error("read_process_memory for the export name table location");
    if(et->name_table >= 0x80000000 || et->name_table > 0xFFFFFFFF - image_base)
        return sub_error("name_table has invalid range; read_process_memory");
    if(et->name_table != 0)
        et->name_table += image_base;

    /* read the export ordinal table location */
    if(!read_process_memory(hProcess, et->export_table + 0x24, &et->ordinal_table, 4))
        return sub_error("read_process_memory for the export ordinal table location");
    if(et->ordinal_table >= 0x80000000 || et->ordinal_table > 0xFFFFFFFF - image_base)
        return sub_error("ordinal_table has invalid range; read_process_memory");
    if(et->ordinal_table != 0)
        et->ordinal_table += image_base;

    return 1;
}

static int install_debugger_hooks()
{
    HANDLE hProcess;
    uint32_t index, TerminateThread_offset;
    uint16_t ordinal;
    struct export_table_desc et = {0};

    hProcess = debugger_ctx.pi.hProcess;

    if(!read_export_table(hProcess, kernel32_base, &et))
        return sub_error("read_export_table");

    /* find SetThreadContext */
    index = 0;
    for(index=0; index<et.symbol_count; index++){
        uint32_t name_pointer;
        char name[17];

        /* read the export name location */
        if(!read_process_memory(hProcess, et.name_table + index*4, &name_pointer, 4))
            return sub_error("read_process_memory for the export name pointer");
        name_pointer += kernel32_base;

        /* read the export name */
        if(!read_process_memory(hProcess, name_pointer, &name, 17))
            continue; /* no name provided */

        if(!strcmp(name, "SetThreadContext"))
            break;
    }
    if(index == et.symbol_count)
        return sub_error("SetThreadContext not found; read_process_memory");

    /* read the ordinal (the index into the export address table) */
    if(!read_process_memory(hProcess, et.ordinal_table + 2*index, &ordinal, 2))
        return sub_error("read_process_memory for the export ordinal");
    printf("* SetThreadContext index in name table: %u, ordinal: %u\n", index, ordinal);

    /* write the pointer to TerminateThread at this spot in the export address table */
    et.address_table += ordinal*4;
    TerminateThread_offset = api_address[TerminateThread_api] - kernel32_base;
    if(!write_process_memory(hProcess, et.address_table, &TerminateThread_offset, 4))
        return sub_error("write_process_memory");

    return 1;
}

static int continue_game_thread(uint32_t pi_address)
{
    HANDLE hProcess;

    hProcess = game_ctx.pi.hProcess;

    /* copy the process information structure to the game process */
    if(!write_process_memory(hProcess, pi_address, &debugger_ctx.pi, sizeof(debugger_ctx.pi)))
        return sub_error("write_process_memory");

    /* and signal CreateProcessA_hook to return */
    SetEvent(events[CreateProcessA_response]);

    return 1;
}

static int suspend_game_threads()
{
    DWORD dwProcessId;
    THREADENTRY32 te32;

    dwProcessId = game_ctx.pi.dwProcessId;
    te32.dwSize = sizeof(te32);

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if(hSnapshot == INVALID_HANDLE_VALUE)
        return sub_error("CreateToolhelp32Snapshot");
    if(Thread32First(hSnapshot, &te32) == FALSE)
        return sub_error("Thread32First");
    do {
        if(te32.th32OwnerProcessID == dwProcessId){
            HANDLE hThread;
            DWORD ret;
            hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
            if(hThread == NULL){
                CloseHandle(hThread);
                return sub_error("OpenThread");
            }
            ret = SuspendThread(hThread);
            CloseHandle(hThread);
            if(ret == (DWORD)-1)
                return sub_error("SuspendThread");
        }
    } while(Thread32Next(hSnapshot, &te32) != FALSE);
    if(GetLastError() != ERROR_NO_MORE_FILES)
        return sub_error("Thread32Next");
    CloseHandle(hSnapshot);
    hSnapshot = INVALID_HANDLE_VALUE;

    return 1;
}

static int dump_game_sections()
{
    HANDLE hProcess;
    unsigned i;

    hProcess = game_ctx.pi.hProcess;

    for(i=0; i<game_ctx.number_of_sections; i++){
        game_ctx.section_data[i] = malloc(game_ctx.section_size[i]);
        if(!game_ctx.section_data[i])
            return sub_error("malloc for the section data");
        if(!read_process_memory(hProcess, game_ctx.section_address[i], game_ctx.section_data[i], game_ctx.section_size[i]))
        return sub_error("read_process_memory for the section data");
    }

    game_ctx.text_section_references = malloc(game_ctx.section_size[game_ctx.text_section_index]);
    if(!game_ctx.text_section_references)
        return sub_error("malloc for text section references");
    game_ctx.nanomite_false_positives = malloc(game_ctx.section_size[game_ctx.text_section_index]);
    if(!game_ctx.nanomite_false_positives)
        return sub_error("malloc for nanomite false positives");
    memset(game_ctx.nanomite_false_positives, 0, game_ctx.section_size[game_ctx.text_section_index]);

    return 1;
}

static int enumerate_imported_dlls()
{
    HANDLE hProcess;
    DWORD dwProcessId;
    MODULEENTRY32 me32;
    uint32_t ntdll_index, i, j, k;

    hProcess = game_ctx.pi.hProcess;
    dwProcessId = game_ctx.pi.dwProcessId;
    me32.dwSize = sizeof(me32);

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
    if(hSnapshot == INVALID_HANDLE_VALUE)
        return sub_error("CreateToolhelp32Snapshot");

    /* count the number of dlls and allocate the list for them */
    if(Module32First(hSnapshot, &me32) == FALSE)
        return sub_error("Module32First");
    for(i=1; Module32Next(hSnapshot, &me32) != FALSE; i++)
    if(GetLastError() != ERROR_NO_MORE_FILES)
        return sub_error("Module32Next");
    imported_dll_count = i;

    if(imported_dll_count > 0xFFFFFFFF/sizeof(*imported_dlls) ||
        (imported_dlls = malloc(imported_dll_count * sizeof(*imported_dlls))) == NULL)
        return sub_error("malloc for imported dlls");
    memset(imported_dlls, 0, imported_dll_count * sizeof(*imported_dlls));

    i = 0;
    ntdll_index = (uint32_t)~0;
    unpack_dll_index = (uint32_t)~0;
    if(Module32First(hSnapshot, &me32) == FALSE)
        return sub_error("Module32First");
    do {
        char *ptr;
        struct export_table_desc *et = &imported_dlls[i].et;
        size_t length;

        if(me32.modBaseSize == 0 || me32.modBaseSize >= 0x80000000)
            return sub_error("modBaseSize has invalid range; Module32Next");
        if(me32.modBaseAddr == 0 || (uint32_t)me32.modBaseAddr > 0xFFFFFFFF - me32.modBaseSize)
            return sub_error("modBaseAddr has invalid range; Module32Next");
        imported_dlls[i].base = (uint32_t)me32.modBaseAddr;
        imported_dlls[i].size = me32.modBaseSize;

        /* get just the file name of the dll, and make it lowercase */
        length = strlen(me32.szExePath);
        if(length == 0 || length >= 267)
            return sub_error("dll name length has invalid range; Module32Next");
        ptr = strrchr((char*)me32.szExePath, '\\');
        if(!ptr || ptr[1] == '\0')
            return sub_error("dll name incorrectly formatted; Module32Next");
        ptr++;
        for(k=0; ptr[k]; k++){
            imported_dlls[i].name[k] = ptr[k];
            if(imported_dlls[i].name[k] >= 'A' && imported_dlls[i].name[k] <= 'Z')
                imported_dlls[i].name[k] += 'a'-'A';
        }
        imported_dlls[i].name[k] = '\0';

        /* check if this is the unpack dll, by checking that the dll path name ends in ".tmp" or ".TMP"
        ** and that a tilde exists somewhere after the last backslash in the dll path name */
        if(length >= 5 && (!strcmp(me32.szExePath+length-4, ".tmp") || !strcmp(me32.szExePath+length-4, ".TMP"))
            && strrchr(me32.szExePath, '~') >= ptr){
            if(unpack_dll_index != (uint32_t)~0)
                return sub_error("Found unpack dll twice; Module32Next");
            printf("\nUnpack dll:\n");
            printf("* Location: %s\n", me32.szExePath);
            printf("* Image base: %08X\n", (uint32_t) me32.modBaseAddr);
            printf("* Image size: %08X\n", (uint32_t) me32.modBaseSize);
            unpack_dll_index = i;
        }else if((uint32_t)me32.modBaseAddr == ntdll_base)
            ntdll_index = i;

        if(!read_export_table(hProcess, (uint32_t)me32.modBaseAddr, et))
            return sub_error("read_export_table");

        if(et->symbol_count == 0)
            continue;

        imported_dlls[i].symbols = malloc(et->symbol_count * sizeof(struct exported_symbol));
        if(imported_dlls[i].symbols == NULL)
            return sub_error("malloc for symbols list");
        memset(imported_dlls[i].symbols, 0, et->symbol_count * sizeof(struct exported_symbol));

        /* enumerate the symbols in this dll */
        for(j=0; j<et->symbol_count; j++){
            uint32_t address, name_pointer;
            MEMORY_BASIC_INFORMATION mbi;
            struct exported_symbol *symbol;

            symbol = imported_dlls[i].symbols + j;
            symbol->parent_dll = &imported_dlls[i];

            /* ordinal */
            if(!read_process_memory(hProcess, et->ordinal_table + 2*j, &symbol->ordinal, 2))
                continue;

            /* name */
            if(!read_process_memory(hProcess, et->name_table + 4*j, &name_pointer, 4)
                || !read_process_memory(hProcess, (uint32_t)me32.modBaseAddr + name_pointer, symbol->name, 267))
                symbol->name[0] = '\0';
            else
                symbol->name[267] = '\0';

            /* address */
            if(!read_process_memory(hProcess, et->address_table + 4*symbol->ordinal, &address, 4)
                || address == 0
                || VirtualQueryEx(hProcess, (void*)((uint32_t)me32.modBaseAddr + address), &mbi, sizeof(mbi)) != sizeof(mbi)
                || mbi.State != MEM_COMMIT)
                symbol->address = 0;
            else{
                uint8_t buffer[2];
                const uint8_t hotpatch_before[] = {0x8b, 0xff}, hotpatch_after[] = {0xeb, 0xf9};
                symbol->address = (uint32_t)me32.modBaseAddr + address;
                symbol->is_executable = ((mbi.Protect & 0xF0) != 0 && i != unpack_dll_index
                    && ((uint32_t)me32.modBaseAddr != ntdll_base || (read_process_memory(hProcess, symbol->address,
                    buffer, 2) != 0 && (!memcmp(buffer, hotpatch_before, 2) || !memcmp(buffer, hotpatch_after, 2)))));
            }
        }

        i++;
    } while(Module32Next(hSnapshot, &me32) != FALSE && i != imported_dll_count);
    if(GetLastError() != ERROR_NO_MORE_FILES || i != imported_dll_count)
        return sub_error("Module32Next");
    if(unpack_dll_index == (uint32_t)~0)
        return sub_error("Could not find unpack dll; Module32Next");
    if(ntdll_index == (uint32_t)~0)
        return sub_error("Could not find ntdll; Module32Next");

    /* resolve all forwarded symbols (e.g. EnterCriticalSection in kernel32 to RtlEnterCriticalSection in ntdll) */
    for(i=0; i<imported_dll_count; i++){
        struct export_table_desc *et = &imported_dlls[i].et;

        /* find all symbols whose addresses lie inside the export table */
        for(j=0; j<et->symbol_count; j++){
            struct exported_symbol *symbol;
            symbol = imported_dlls[i].symbols + j;
            if(symbol->address >= et->export_table && symbol->address - et->export_table < et->export_table_size){
                char buffer[268], dll_name[268+4];
                char *symbol_name;
                struct imported_dll *dest_dll;

                symbol->is_executable = 0;

                if(!read_process_memory(hProcess, symbol->address, buffer, 267))
                    continue;
                buffer[267] = '\0';

                symbol_name = strrchr(buffer, '.');
                if(!symbol_name || symbol_name[1] == '\0')
                    continue;
                *symbol_name = '\0';
                symbol_name++;

                /* append ".dll" to the destination dll name, and make it lowercase */
                for(k=0; buffer[k]; k++){
                    dll_name[k] = buffer[k];
                    if(dll_name[k] >= 'A' && dll_name[k] <= 'Z')
                        dll_name[k] += 'a'-'A';
                }
                strcpy(dll_name+k, ".dll");

                /* find the destination dll */
                for(k=0; k<imported_dll_count; k++)
                    if(!strcmp(imported_dlls[k].name, dll_name))
                        break;
                if(k == imported_dll_count)
                    continue;
                dest_dll = imported_dlls + k;

                /* find the destination symbol in the dll */
                for(k=0; k<dest_dll->et.symbol_count; k++)
                    if(!strcmp(dest_dll->symbols[k].name, symbol_name))
                        break;
                if(k == dest_dll->et.symbol_count)
                    continue;

                /* copy over the information and remove the other symbol by setting its address to 0 */
                symbol->address = dest_dll->symbols[k].address;
                symbol->is_executable = dest_dll->symbols[k].is_executable;
                dest_dll->symbols[k].address = dest_dll->symbols[k].is_executable = 0;
            }
        }

        /* find all symbols whose addresses have already been exported by ntdll
        ** (e.g. DefWindowProcA in user32 -> Ntdll_DefWindowProc_a in ntdll) */
        if(i == ntdll_index)
            continue;
        for(j=0; j<et->symbol_count; j++){
            struct exported_symbol *symbol;
            struct imported_dll *ntdll;
            uint32_t ntdll_symbol_count;

            symbol = imported_dlls[i].symbols + j;
            ntdll = &imported_dlls[ntdll_index];
            ntdll_symbol_count = ntdll->et.symbol_count;
            for(k=0; k<ntdll_symbol_count; k++)
                if(ntdll->symbols[k].address == symbol->address)
                    break;
            if(k == ntdll_symbol_count)
                continue;

            /* remove the other symbol by setting its address to 0 */
            ntdll->symbols[k].address = ntdll->symbols[k].is_executable = 0;
        }
    }

    return 1;
}

static int fixup_direct_jumps()
{
    HANDLE hProcess;
    uint32_t text_section_index, text_section_address, text_section_size;
    uint8_t *text_section_data;
    uint32_t i, address;
    uint8_t buffer[2];
    MEMORY_BASIC_INFORMATION mbi;

    hProcess = game_ctx.pi.hProcess;
    text_section_index = game_ctx.text_section_index;
    text_section_address = game_ctx.section_address[text_section_index];
    text_section_size = game_ctx.section_size[text_section_index];
    text_section_data = game_ctx.section_data[text_section_index];

    /* SafeDisc replaces some imported jumps/calls with direct jumps/calls to
    ** another executable section of the exe; since these take up 5 bytes instead of 6,
    ** the 6th byte is replaced with a random byte, which throws off our disassembly
    ** (and often nanomites are placed directly this byte); so we replace this byte with a nop */
    for(i=0; i<text_section_size-6; i++){ /* minimum of 7 bytes */
        if(text_section_data[i] != 0xe8 && text_section_data[i] != 0xe9)
            continue;

        memcpy(&address, text_section_data+i+1, 4);
        address += text_section_address+i+5;

        /* verify that the destination is not in the text section,
        ** and that it points to valid executable memory */
        if(address >= text_section_address && address - text_section_address < text_section_size)
            continue;
        if(VirtualQueryEx(hProcess, (void*)address, &mbi, sizeof(mbi)) != sizeof(mbi)
            || mbi.State != MEM_COMMIT || (mbi.Protect & 0xF0) == 0)
            continue;

        /* verify that the destination starts with "push ebx; jmp/call ..." */
        if(!read_process_memory(hProcess, address, buffer, 2))
            continue;
        if(buffer[0] != 0x53 || (buffer[1] != 0xe8 && buffer[1] != 0xe9 && buffer[1] != 0xeb))
            continue;

        /* fix up the jump by replacing the byte that comes after the operand with a nop,
        ** but do not commit the change to the process */
        text_section_data[i+5] = 0x90;
        i += 5;
    }

    return 1;
}

static int build_references()
{
    HANDLE hProcess;
    uint32_t text_section_index, text_section_address, text_section_size;
    uint8_t *text_section_data;
    uint32_t i;
    uint8_t *references;

    hProcess = game_ctx.pi.hProcess;
    text_section_index = game_ctx.text_section_index;
    text_section_address = game_ctx.section_address[text_section_index];
    text_section_size = game_ctx.section_size[text_section_index];
    text_section_data = game_ctx.section_data[text_section_index];

    if(!read_process_memory(hProcess, text_section_address, text_section_data, text_section_size))
        return sub_error("read_process_memory for the text section\n");

    if(!fixup_direct_jumps())
        return Shutdown("fixup_direct_jumps");

    references = game_ctx.text_section_references;
    memset(references, 0, text_section_size);

    /* check for absolute references from all sections */
    for(i=0; i<game_ctx.number_of_sections; i++){
        uint32_t section_size;
        uint8_t *ptr;
        section_size = game_ctx.section_size[i];
        if(section_size < 4)
            continue;
        for(ptr = game_ctx.section_data[i], section_size -= 3; section_size; ptr++, section_size--){
            uint32_t address;
            memcpy(&address, ptr, 4);
            if(address >= text_section_address && address - text_section_address < text_section_size)
                references[address - text_section_address] |= 1;
        }
    }

    /* check for relative references by jump or call instructions in the text section */
    ud_set_input_buffer(&ud, text_section_data, text_section_size);
    ud_set_pc(&ud, text_section_address);
    while(ud_disassemble(&ud)){
        const ud_operand_t *operand;
        uint32_t address;

        operand = ud_insn_opr(&ud, 0);
        if(operand == NULL || operand->type != UD_OP_JIMM)
            continue;
        address = ud_insn_off(&ud);
        if(address < text_section_address || address - text_section_address >= text_section_size)
            return sub_error("ud_insn_off");

        address++;
        if(operand->size == 8) address += 1 + operand->lval.sbyte;
        else if(operand->size == 16) address += 2 + operand->lval.sword;
        else if(operand->size == 32) address += 4 + operand->lval.sdword;
        else if(operand->size == 64) address += 8 + operand->lval.sqword;
        else continue;
        if(address >= text_section_address && address - text_section_address < text_section_size)
            references[address - text_section_address] |= 2;
    }

    return 1;
}

static uint32_t find_reference_to_block(uint32_t offset, uint32_t size, uint32_t mask)
{
    uint32_t i;
    for(i=0; i<size; i++){
        if((game_ctx.text_section_references[offset+i] & mask) != 0)
            return i;
    }
    return (uint32_t)-1;
}

static int get_padding_size(uint32_t address, uint32_t offset, uint8_t *text_section_data, uint32_t bytes_remaining)
{
    /* verify that no other code or data in the exe makes an absolute reference to the padding, and that either:
    ** a. the padding goes to the next 16-byte boundary, or
    ** b. the padding goes to the next 4-byte boundary and something makes an absolute or relative reference to
    **    the address following the padding */
    uint32_t i, ref = (uint32_t)-1, padding_size;
    if(bytes_remaining == 0)
        return 1;
    padding_size = 16 - (address&15); /* a number 1 through 16 */
    if(padding_size == 16) /* if we are already on a 16-byte boundary, this is not padding */
        return 0;

    if(padding_size > bytes_remaining)
        padding_size = bytes_remaining;
    for(i=0; i<padding_size; i++)
        if(text_section_data[offset + i] != 0xCC)
            break;

    if(i == padding_size && (ref = find_reference_to_block(offset + 1, padding_size - 1, 1)) == (uint32_t)-1)
        return padding_size;
    padding_size = 4 - (address&3); /* a number 1 through 4 */
    if(padding_size == 4) /* if we are already on a 4-byte boundary, this is not padding */
        return 0;
    if(padding_size > bytes_remaining)
        padding_size = bytes_remaining;
    if(i < padding_size || ref < padding_size)
        return 0;

    if((game_ctx.text_section_references[offset + padding_size] & 3) != 0)
        return padding_size;
    return 0;
}

static int handle_exception()
{
    /* if we receive an exception in the remote thread, skip over the offending instruction */
    HANDLE hProcess;
    uint32_t text_section_index, text_section_address, text_section_size;
    uint8_t *text_section_data;
    uint32_t stack_frame, exception, eip, offset, instruction_size;
    enum ud_mnemonic_code ins;
    uint32_t args[4]; /* args[0] is the return address;
                      ** the only arguments we care about are args[1] (ExceptionRecord)
                      ** and args[3] (ContextRecord) */

    hProcess = game_ctx.pi.hProcess;
    text_section_index = game_ctx.text_section_index;
    text_section_address = game_ctx.section_address[text_section_index];
    text_section_size = game_ctx.section_size[text_section_index];
    text_section_data = game_ctx.section_data[text_section_index];

    /* read the value of esp that we wrote to stack_frame in new_thread_exception_handler */
    if(!read_process_memory(hProcess, game_ctx.hook_code_address+0x00, &stack_frame, 4))
        return sub_error("read_process_memory for stack frame");
    stack_frame += 0x0c; /* skip over the stack frame for signal_and_wait */

    if(!read_process_memory(hProcess, stack_frame, args, 4*4))
        return sub_error("read_process_memory for exception handler arguments");

    if(!read_process_memory(hProcess, args[1] + 0x00, &exception, 4))
        return sub_error("read_process_memory for exception code");

    printf("Exception: %08X\n", exception);

    if(!read_process_memory(hProcess, args[3] + 0xb8, &eip, 4))
        return sub_error("read_process_memory for eip");
    if(eip < text_section_address || eip - text_section_address >= text_section_size)
        return sub_error("eip has invalid range; read_process_memory");
    offset = eip - text_section_address;

    ud_set_input_buffer(&ud, text_section_data + offset, text_section_size - offset);
    ud_set_pc(&ud, text_section_address + offset);
    if(!ud_disassemble(&ud))
        return sub_error("ud_disassemble");

    ins = ud_insn_mnemonic(&ud);
    if(ins == UD_Iint3){
        /* actually, this was not a nanomite */
        game_ctx.nanomite_false_positives[offset] = 0x01;
        if(TerminateThread(game_ctx.new_thread, 0) == FALSE)
            return sub_error("TerminateThread");
        printf("* Received int3 exception (nanomite false positive)\n");
        return 1;
    }

    instruction_size = ud_insn_len(&ud);
    if(instruction_size == 0 || instruction_size >= 16 || instruction_size >= text_section_size - offset)
        return sub_error("ud_insn_len");
    printf("* Received exception 0x%08X: eip = %08X, instruction size = %u\n", exception, eip, instruction_size);

    eip += instruction_size;
    if(!write_process_memory(hProcess, args[3] + 0xb8, &eip, 4))
        return sub_error("write_process_memory");

    SetEvent(events[exception_handler_response]); /* continue the thread */
    return 1;
}

static int create_and_wait_for_thread(uint32_t address, uint32_t compare_start, uint32_t compare_end)
{
    HANDLE hProcess;
    HANDLE handle_list[2];
    uint32_t hook_code_address, call_destination;

    hProcess = game_ctx.pi.hProcess;
    handle_list[1] = events[exception_handler_event];
    hook_code_address = game_ctx.hook_code_address;

    /* set the comparison addresses for address_range_compare
    ** that enable the hooks for EnterCriticalSection and LeaveCriticalSection */
    write_uint32(hook_code + 0x96, compare_start);
    write_uint32(hook_code + 0x9d, compare_end);

    /* set the comparison address for VirtualProtect */
    write_uint32(hook_code + 0x81, address);

    /* clear the LeaveCriticalSection flag */
    hook_code[0x05] = 0x00;

    /* disable the WaitForSingleObject hook */
    hook_code[0x5c] = 0x02;

    /* install unconditional call to the address (relative to eip) */
    call_destination = address - (hook_code_address + 0x106 + 0x04);
    write_uint32(hook_code + 0x106, call_destination);

    /* create the thread */
    if(!write_process_memory(hProcess, hook_code_address, hook_code, sizeof(hook_code)))
        return sub_error("write_process_memory");
    ResetEvent(handle_list[1]);
    game_ctx.new_thread = handle_list[0] = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE) (hook_code_address + 0xf6), NULL, 0, NULL);
    if(handle_list[0] == NULL)
        return sub_error("CreateRemoteThread");

    /* wait for an event */
    while(1){
        DWORD event_value;
        event_value = WaitForMultipleObjects(2, handle_list, FALSE, INFINITE) - WAIT_OBJECT_0;
        if((unsigned)event_value > 2)
            return sub_error("WaitForMultipleObjects");
        if(event_value == 0)
            break;

        if(!handle_exception())
            return sub_error("handle_exception");
    }
    CloseHandle(handle_list[0]);

    return 1;
}

static int fix_nanomites(int *patched)
{
    uint32_t text_section_index, text_section_address, text_section_size;
    uint32_t i, ref, address, offset;
    uint8_t *text_section_data;
    enum ud_mnemonic_code ins, prev_ins;

    text_section_index = game_ctx.text_section_index;
    text_section_address = game_ctx.section_address[text_section_index];
    text_section_size = game_ctx.section_size[text_section_index];
    text_section_data = game_ctx.section_data[text_section_index];

    if(!build_references())
        return sub_error("build_references");
    ud_set_input_buffer(&ud, text_section_data, text_section_size);
    ud_set_pc(&ud, text_section_address);

    for(prev_ins = UD_Iint3; ud_disassemble(&ud); prev_ins = ins){
        ins = ud_insn_mnemonic(&ud);

        if(ins != UD_Iint3)
            continue;

        address = ud_insn_off(&ud);
        if(address < text_section_address || (offset = address - text_section_address) >= text_section_size)
            return sub_error("ud_insn_off");

        /* if this is padding after the end of a function or after a thunk, skip it */
        if(prev_ins == UD_Iret || prev_ins == UD_Ijmp){
            uint32_t padding_size;
            padding_size = get_padding_size(address, offset, text_section_data, text_section_size - offset);
            if(padding_size != 0){
                ud_set_input_buffer(&ud, text_section_data + offset + padding_size,
                    text_section_size - (offset + padding_size));
                ud_set_pc(&ud, text_section_address + offset + padding_size);
                continue;
            }
        }

        /* if this byte is part of a valid address to the text section, skip it */
        for(i=0; i<4; i++){
            uint32_t dword;
            memcpy(&dword, text_section_data + offset - i, 4);
            if(dword >= text_section_address && dword - text_section_address < text_section_size)
                break;
        }
        if(i != 4){
            ud_set_input_buffer(&ud, text_section_data + offset + 4 - i, text_section_size - (offset + 4 - i));
            ud_set_pc(&ud, text_section_address + offset + 4 - i);
            continue;
        }

        /* if some other code or data in the exe makes an absolute reference to this
        ** or one of the previous 3 bytes, skip it */
        ref = find_reference_to_block(offset - 3, 4, 1);
        if(ref != (uint32_t)-1){
            ud_set_input_buffer(&ud, text_section_data + offset + ref + 1, text_section_size - (offset + ref + 1));
            ud_set_pc(&ud, text_section_address + offset + ref + 1);
            continue;
        }

        /* if it is on the false positives list, it is not a nanomite, so skip it */
        if(game_ctx.nanomite_false_positives[offset])
            continue;

        /* otherwise, it is probably a nanomite, so fix it */
        printf("Nanomite: %08X\n", address);
        if(!create_and_wait_for_thread(address, 0, 0))
            return sub_error("create_and_wait_for_thread");

        /* start over the disassembly with the new information */
        if(!build_references())
            return sub_error("build_references");
        ud_set_input_buffer(&ud, text_section_data, text_section_size);
        ud_set_pc(&ud, text_section_address);
        *patched = 1;
    }
    return 1;
}

static int fix_stolen_bytes(int *patched)
{
    uint32_t text_section_index, text_section_address, text_section_size, compare_start, compare_end;
    uint32_t i, j, k;
    uint8_t *text_section_data;

    text_section_index = game_ctx.text_section_index;
    text_section_address = game_ctx.section_address[text_section_index];
    text_section_size = game_ctx.section_size[text_section_index];
    text_section_data = game_ctx.section_data[text_section_index];
    compare_start = imported_dlls[unpack_dll_index].base;
    compare_end = imported_dlls[unpack_dll_index].base + imported_dlls[unpack_dll_index].size;

    if(!build_references())
        return sub_error("build_references");

    /* search for "mov eax, dword ptr [eax]; jmp eax" */
    for(i=9; i<text_section_size-3; i++){ /* minimum of 4 bytes */
        const uint8_t buffer[4] = {0x8b, 0x00, 0xff, 0xe0};
        if(memcmp(text_section_data+i, buffer, 4))
            continue;

        /* search for references to this function (beginning 9 bytes earlier) */
        for(j=3; j<text_section_size-3; j++){ /* minimum of 4 bytes */
            uint32_t jump_offset_1 = i - 9 - (j + 4);
            if(text_section_data[j-1] != 0xe8 || memcmp(text_section_data+j, &jump_offset_1, 4))
                continue;

            /* search for references to this function (beginning 3 bytes earlier) */
            for(k=1; k<text_section_size-3; k++){ /* minimum of 4 bytes */
                uint32_t jump_offset_2 = j - 3 - (k + 4);
                if(text_section_data[k-1] != 0xe8 || memcmp(text_section_data+k, &jump_offset_2, 4))
                    continue;

                printf("Stolen bytes call: %08X\n", text_section_address + k-1);

                /* create a new thread here, and terminate once VirtualQueryEx has been called on the
                ** address of the stolen bytes and LeaveCriticalSection has subsequently been called by
                ** the unpack dll (whose address space ranges from compare_start to compare_end here) */
                if(!create_and_wait_for_thread(text_section_address + k-1, compare_start, compare_end))
                    return sub_error("create_and_wait_for_thread");

                *patched = 1;
            }
        }
    }

    return 1;
}

static int hook_all_imported_functions()
{
    uint32_t i, j, hook_code_address;

    hook_code_address = game_ctx.hook_code_address;

    for(i=0; i<imported_dll_count; i++){
        uint32_t symbol_count;

        symbol_count = imported_dlls[i].et.symbol_count;
        for(j=0; j<symbol_count; j++){
            uint32_t offset;
            struct exported_symbol *symbol = imported_dlls[i].symbols + j;

            if(!strcmp(symbol->name, "LdrInitializeThunk"))
                offset = 0xf6; /* new_thread_entry_point */
            else if(symbol->is_executable)
                offset = 0xd2; /* exported_function_hook */
            else continue;

            printf("Hooking %s in %s (address %08X)\n", symbol->name, imported_dlls[i].name, symbol->address);
            if(!install_hotpatch(symbol->address, hook_code_address + offset, 0xe8))
                return sub_error("install_hotpatch");
        }
    }
    return 1;
}

static int build_sorted_symbol_list()
{
    uint32_t i, j, max_symbol_count, symbol_index;

    /* using binary search is necessary as linear search has been tried and
    ** was observed to be far too slow on 2014 hardware */

    /* allocate two parallel arrays so that the address list is small to improve locality */
    max_symbol_count = 0;
    for(i=0; i<imported_dll_count; i++){
        if(imported_dlls[i].et.symbol_count > 0xFFFFFFFF - max_symbol_count)
            return sub_error("et.symbol_count overflowed; building sorted symbol list");
        max_symbol_count += imported_dlls[i].et.symbol_count;
    }
    if(max_symbol_count == 0 || max_symbol_count > 0xFFFFFFFF/(sizeof(uint32_t) + sizeof(struct exported_symbol *)))
        return sub_error("max_symbol_count overflowed; building sorted symbol list");
    sorted_symbol_addresses = malloc(max_symbol_count * (sizeof(uint32_t) + sizeof(struct exported_symbol *)));
    if(!sorted_symbol_addresses)
        return sub_error("malloc");
    sorted_symbol_ptrs = (struct exported_symbol **) ((uint8_t*)sorted_symbol_addresses + max_symbol_count * sizeof(uint32_t));

    symbol_index = 0;
    for(i=0; i<imported_dll_count; i++){
        struct export_table_desc *et = &imported_dlls[i].et;
        for(j=0; j<et->symbol_count; j++){
            struct exported_symbol *symbol = imported_dlls[i].symbols + j;
            if(symbol->address){ /* non-zero addresses in the list only; these are the only ones we consider valid */
                sorted_symbol_addresses[symbol_index] = symbol->address;
                sorted_symbol_ptrs[symbol_index] = symbol;
                symbol_index++;
            }
        }
    }
    if(symbol_index == 0 || symbol_index == (unsigned)~0)
        return sub_error("no symbols valid; building sorted symbol list");
    total_symbol_count = symbol_index;

    /* use insertion sort, as the data should already be mostly sorted */
    for(i=1; i<total_symbol_count; i++){
        uint32_t t1 = sorted_symbol_addresses[i];
        struct exported_symbol *t2 = sorted_symbol_ptrs[i];
        for(j=i; j > 0 && sorted_symbol_addresses[j-1] > t1; j--){
            sorted_symbol_addresses[j] = sorted_symbol_addresses[j-1];
            sorted_symbol_ptrs[j] = sorted_symbol_ptrs[j-1];
        }
        sorted_symbol_addresses[j] = t1;
        sorted_symbol_ptrs[j] = t2;
    }

    return 1;
}

static struct exported_symbol * binary_search_address(uint32_t address)
{
    uint32_t *const a = sorted_symbol_addresses;
    uint32_t index_min, index_max;

    if(address == 0)
        return 0;

    index_min = 0;
    index_max = total_symbol_count; /* earlier, we guarded against the case that total_symbol_count is 0xFFFFFFFF */

    do {
        uint32_t i = (index_min>>1) + (index_max>>1);
        if(a[i] == address)
            return sorted_symbol_ptrs[i];
        else if(a[i] < address)
            index_min = i + 1;
        else index_max = i - 1;
    } while(index_min < index_max); /* so this is safe */

    return (a[index_min] == address) ? sorted_symbol_ptrs[index_min] : NULL;
}

static int find_import_table_and_iat_region()
{
    uint32_t image_base, import_section_index = 0, import_section_address = 0, import_section_size = 0;
    uint8_t *import_section_data = NULL;
    uint32_t iat_section_index = 0, iat_section_address = 0, iat_section_size = 0;
    uint32_t import_table_region_address = 0;
    uint32_t import_table_desc_count, iat_region_address;
    uint32_t section_count;
    uint32_t offset, i, j;

    image_base = game_ctx.image_base;
    section_count = game_ctx.number_of_sections;

    /* find an import descriptor by searching for a reference to a dll name */
    for(import_section_index=0; import_section_index<section_count; import_section_index++){
        import_section_address = game_ctx.section_address[import_section_index];
        import_section_size = game_ctx.section_size[import_section_index];
        import_section_data = game_ctx.section_data[import_section_index];
        if(import_section_size < 32)
            continue;

        import_table_region_address = 0;
        for(offset=1; offset<import_section_size-3; offset++){ /* minimum of 4 bytes */
            if(strcmp((char*)import_section_data + offset, ".DLL") != 0
                && strcmp((char*)import_section_data + offset, ".dll") != 0)
                continue;

            for(i=offset-1; import_section_data[i] != '\0' && import_section_data[i] < 0x80 && i != (uint32_t)-1; i--){
                uint32_t dll_name_rva, iat_address, symbol_address;
                dll_name_rva = import_section_address - image_base + i;
                for(j=12; j<import_section_size-7; j++){ /* minimum of 8 bytes */
                    if(memcmp(import_section_data + j, &dll_name_rva, 4) != 0)
                        continue;

                    /* verify that the next field in the descriptor is a valid RVA
                    ** to an import address table; SafeDisc does not touch this field */
                    memcpy(&iat_address, import_section_data + j + 4, 4);
                    iat_address += image_base;

                    /* the import address table can be in a different section from the import table */
                    for(iat_section_index=0; iat_section_index<section_count; iat_section_index++){
                        iat_section_address = game_ctx.section_address[iat_section_index];
                        iat_section_size = game_ctx.section_size[iat_section_index];
                        if(iat_address >= iat_section_address &&
                            iat_address - iat_section_address < iat_section_size)
                            break;
                    }
                    if(iat_section_index == section_count)
                        continue;

                    memcpy(&symbol_address, import_section_data + iat_address - import_section_address, 4);
                    if(!binary_search_address(symbol_address))
                        continue;

                    import_table_region_address = import_section_address + j - 12;
                    break;
                }
                if(import_table_region_address)
                    break;
            }
            if(import_table_region_address)
                break;
        }
        if(import_table_region_address)
            break;
    }
    if(!import_table_region_address)
        return sub_error("no import descriptors found; finding import table");

    printf("* Import section index: %u\n", import_section_index);

    /* start from this import descriptor and walk backwards to find the beginning of the import table */
    while(import_table_region_address - import_section_address >= 20){
        uint32_t dll_name_address, dll_name_offset, iat_address;
        uint8_t last_byte;
        int result;

        /* verify the dll name */
        memcpy(&dll_name_address, import_section_data + import_table_region_address - import_section_address - 8, 4);
        dll_name_address += image_base;
        if(dll_name_address < import_section_address ||
            (dll_name_offset = dll_name_address - import_section_address) >= import_section_size)
            break;

        last_byte = import_section_data[import_section_size-1];
        import_section_data[import_section_size-1] = 0;
        result = strstr((char*)import_section_data + dll_name_offset, ".DLL") != NULL
            || strstr((char*)import_section_data + dll_name_offset, ".dll") != NULL;
        import_section_data[import_section_size-1] = last_byte;
        if(!result)
            break;

        /* verify the import address table */
        memcpy(&iat_address, import_section_data + import_table_region_address - import_section_address - 4, 4);
        iat_address += image_base;
        if(iat_address < import_section_address || iat_address - import_section_address >= import_section_size)
            break;

        import_table_region_address -= 20;
    }

    printf("* Import table address: %08X\n", import_table_region_address);

    /* enumerate the descriptors in the import table */
    iat_region_address = (uint32_t)-1;
    import_table_desc_count = 0;
    for(offset=import_table_region_address-import_section_address;
        offset<import_section_size-19; offset+=20){ /* minimum of 20 bytes, skipping 20 bytes at a time */
        struct imported_dll *dll;
        struct import_descriptor *descriptor;
        char buffer[268];
        uint32_t length, dll_name_address, dll_name_offset, iat_address;

        /* if this descriptor is all zeros, leave */
        for(i=0; i<20; i++)
            if(import_section_data[offset + i] != 0)
                break;
        if(i == 20)
            break;

        descriptor = import_table.descriptors + import_table_desc_count;
        if(++import_table_desc_count == 64)
            return sub_error("too many descriptors in the import table; reading import table");

        /* find the loaded dll that corresponds with this import descriptor by the dll name */
        memcpy(&dll_name_address, import_section_data + offset + 12, 4);
        if(!dll_name_address || (dll_name_address += image_base) < import_section_address ||
            (dll_name_offset = dll_name_address - import_section_address) >= import_section_size)
            return sub_error("dll_name_address is out of range; reading import table");
        length = 267;
        if(length > import_section_size - dll_name_offset)
            length = import_section_size - dll_name_offset;
        memcpy(buffer, import_section_data + dll_name_offset, length);
        buffer[length] = '\0';
        for(i=0; buffer[i]; i++)
            if(buffer[i] >= 'A' && buffer[i] <= 'Z')
                buffer[i] += 'a'-'A';
        for(i=0; i<imported_dll_count; i++)
            if(!strcmp(buffer, imported_dlls[i].name))
                break;
        if(i == imported_dll_count)
            return sub_error("imported dll name does not appear in loaded dll list; reading import table");
        dll = imported_dlls + i;

        /* copy over the capitalization for the dll name */
        memcpy(dll->name, import_section_data + dll_name_offset, length);
        dll->name[length] = '\0';
        descriptor->dll = dll;

        /* update the IAT region address */
        memcpy(&iat_address, import_section_data + offset + 16, 4);
        if(iat_address == 0)
            break;
        if(!iat_address || (iat_address += image_base) < iat_section_address
            || iat_address - iat_section_address >= iat_section_size)
                return sub_error("invalid import address table RVA; reading import table");
        if(iat_address < iat_region_address)
            iat_region_address = iat_address;
    }

    printf("* Import table descriptor count: %u\n", import_table_desc_count);
    printf("* Import table size: %u\n", (1 + import_table_desc_count) * 20);
    printf("* Import address table region address: %08X\n", iat_region_address);

    import_table.import_section_index = import_section_index;
    import_table.import_table_region_address = import_table_region_address;
    import_table.import_table_region_size = (1 + import_table_desc_count) * 20;
    import_table.ordinal_name_rva_region_address = import_table.import_table_region_address +
        import_table.import_table_region_size;
    import_table.import_table_desc_count = import_table_desc_count;
    import_table.iat_region_address = iat_region_address;
    import_table.iat_section_index = iat_section_index;
    return 1;
}

static int reconstruct_import_table_and_data()
{
    uint32_t image_base, import_section_index, iat_section_index;
    uint32_t import_section_address, import_section_size;
    uint8_t *import_section_data;
    uint32_t iat_section_address, iat_section_size;
    uint8_t *iat_section_data;
    uint32_t ordinal_name_rva_region_address, iat_region_address;
    uint32_t import_table_desc_count, rva_region_size;
    uint32_t import_table_offset, ordinal_name_rva_offset, ordinal_name_offset, iat_offset, i, j;

    image_base = game_ctx.image_base;
    import_section_index = import_table.import_section_index;
    import_section_address = game_ctx.section_address[import_section_index];
    import_section_size = game_ctx.section_size[import_section_index];
    import_section_data = game_ctx.section_data[import_section_index];
    iat_section_index = import_table.iat_section_index;
    iat_section_address = game_ctx.section_address[iat_section_index];
    iat_section_size = game_ctx.section_size[iat_section_index];
    iat_section_data = game_ctx.section_data[iat_section_index];
    ordinal_name_rva_region_address = import_table.ordinal_name_rva_region_address;
    iat_region_address = import_table.iat_region_address;

    /* calculate the space for the RVA tables */
    rva_region_size = 0;
    import_table_desc_count = import_table.import_table_desc_count;
    for(i=0; i<import_table_desc_count; i++)
        rva_region_size += 4*(1+import_table.descriptors[i].dll->referenced_symbol_count);

    if(rva_region_size >= import_section_size - (ordinal_name_rva_region_address - import_section_address)
        || rva_region_size >= iat_section_size - (iat_region_address - iat_section_address))
        return sub_error("rva_region_size is out of range; reconstructing import table");

    import_table.ordinal_name_rva_region_size = import_table.iat_region_size = rva_region_size;
    import_table.ordinal_name_region_address = ordinal_name_rva_region_address + rva_region_size;

    /* reconstruct the ordinal-name tables, the ordinal-name RVA tables, and
    ** the linked version of the imported address table */
    ordinal_name_rva_offset = import_table.ordinal_name_rva_region_address - import_section_address;
    ordinal_name_offset = import_table.ordinal_name_region_address - import_section_address;
    iat_offset = import_table.iat_region_address - iat_section_address;
    import_table_offset = import_table.import_table_region_address - import_section_address;
    for(i=0; i<import_table_desc_count; i++){
        struct import_descriptor *descriptor;
        struct imported_dll *dll;
        uint32_t rva, length, symbol_count;

        descriptor = import_table.descriptors + i;
        dll = descriptor->dll;
        symbol_count = dll->et.symbol_count;

        descriptor->ordinal_name_rva_table_address = import_section_address + ordinal_name_rva_offset;
        descriptor->iat_address = iat_region_address + iat_offset;

        for(j=0; j<symbol_count; j++){
            struct exported_symbol *symbol;

            symbol = dll->symbols + j;
            if(!symbol->is_referenced)
                continue;

            /* write the address to the import address table */
            if(iat_offset > iat_section_size - 4)
                return sub_error("iat_offset is out of range; building import address table");
            write_uint32(iat_section_data + iat_offset, symbol->address);
            iat_offset += 4;

            /* write either the ordinal-name RVA or the ordinal directly (if no name is provided)
            ** to the ordinal-name RVA table */
            length = strlen(symbol->name);
            if(!length){
                memcpy(import_section_data + ordinal_name_rva_offset, &symbol->ordinal, 4);
                ordinal_name_rva_offset += 4;
                continue;
            }

            /* we will not use padding for ordinals or symbol names because we can't be 100% sure what the original
            ** order of the symbols was, and there's a potential of overflowing */
            length += 3;
            if(length > import_section_size - ordinal_name_offset)
                return sub_error("ordinal-name pair overflows ordinal-name table; reconstructing ordinal-name table");

            rva = import_section_address + ordinal_name_offset - image_base;
            memcpy(import_section_data + ordinal_name_rva_offset, &rva, 4);
            ordinal_name_rva_offset += 4;
            memcpy(import_section_data + ordinal_name_offset, &symbol->ordinal, 2);
            strcpy((char*)import_section_data + ordinal_name_offset + 2, symbol->name);
            ordinal_name_offset += length;
        }

        /* write terminating zeros to the import address table and the ordinal-name RVA table */
        rva = 0;
        memcpy(iat_section_data + iat_offset, &rva, 4);
        iat_offset += 4;
        memcpy(import_section_data + ordinal_name_rva_offset, &rva, 4);
        ordinal_name_rva_offset += 4;

        /* write the dll name */
        length = strlen(dll->name) + 1;
        if(length > import_section_size - ordinal_name_offset)
            return sub_error("dll name overflows ordinal-name table; recontructing ordinal-name table");
        descriptor->dll_name_address = import_section_address + ordinal_name_offset;
        strcpy((char*)import_section_data + ordinal_name_offset, dll->name);
        ordinal_name_offset += length;

        /* update the pointers for this descriptor in the import table */
        write_uint32(import_section_data + import_table_offset + 0, descriptor->ordinal_name_rva_table_address - image_base);
        write_uint32(import_section_data + import_table_offset + 12, descriptor->dll_name_address - image_base);
        write_uint32(import_section_data + import_table_offset + 16, descriptor->iat_address - image_base);
        import_table_offset += 20;
    }

    import_table.ordinal_name_region_size = import_section_address + ordinal_name_offset
        - import_table.ordinal_name_region_address;

    return 1;
}

static int fix_imports()
{
    HANDLE hProcess;
    uint32_t hook_code_address, text_section_index, text_section_address, text_section_size;
    uint8_t *text_section_data;
    uint32_t import_section_index, import_section_address, ordinal_name_rva_region_address = 0;
    uint8_t *import_section_data;
    uint32_t iat_section_index, iat_section_address, iat_region_address = 0, iat_region_size = 0;
    uint8_t *iat_section_data;
    uint32_t i;
    int pass = 0;

    hProcess = game_ctx.pi.hProcess;
    hook_code_address = game_ctx.hook_code_address;
    text_section_index = game_ctx.text_section_index;
    text_section_address = game_ctx.section_address[text_section_index];
    text_section_size = game_ctx.section_size[text_section_index];
    text_section_data = game_ctx.section_data[text_section_index];

    if(!build_references())
        return sub_error("build_references");
    if(!build_sorted_symbol_list())
        return sub_error("build_sorted_symbol_list");
    if(!find_import_table_and_iat_region())
        return sub_error("find_import_table_and_iat_region");

    import_section_index = import_table.import_section_index;
    import_section_address = game_ctx.section_address[import_section_index];
    import_section_data = game_ctx.section_data[import_section_index];
    iat_section_index = import_table.iat_section_index;
    iat_section_address = game_ctx.section_address[iat_section_index];
    iat_section_data = game_ctx.section_data[iat_section_index];

    for(pass=0; pass<2; pass++){
        ud_set_input_buffer(&ud, text_section_data, text_section_size);
        ud_set_pc(&ud, text_section_address);
        while(ud_disassemble(&ud)){
            int is_jump_or_call;
            uint32_t address, offset, length, pointer_address, resolver_address, import_address;
            uint8_t buffer[8];
            MEMORY_BASIC_INFORMATION mbi;
            struct exported_symbol *symbol = NULL;

            address = ud_insn_off(&ud);
            if(address < text_section_address || (offset = address - text_section_address) >= text_section_size)
                return sub_error("ud_insn_off");
            length = ud_insn_len(&ud);
            if(length > text_section_size - offset)
                return sub_error("ud_insn_len");
            if(length < 5)
                continue;
            memcpy(&pointer_address, text_section_data+offset+length-4, 4);

            if(length == 5 && (text_section_data[offset] == 0xe8 || text_section_data[offset] == 0xe9)){
                is_jump_or_call = 1;
                resolver_address = pointer_address + address + 5;
            }else{
                is_jump_or_call = (length == 6 && text_section_data[offset] == 0xff &&
                    (text_section_data[offset+1] == 0x15 || text_section_data[offset+1] == 0x25));
                if(!read_process_memory(hProcess, pointer_address, &resolver_address, 4))
                    continue;
            }

            /* verify that the destination is not in the text section,
            ** and that it points to either a recognized resolver function, a direct jump/call function,
            ** or a hooked API function */
            if(resolver_address >= text_section_address && resolver_address - text_section_address < text_section_size)
                continue;
            if(VirtualQueryEx(hProcess, (void*)resolver_address, &mbi, sizeof(mbi)) != sizeof(mbi)
                || mbi.State != MEM_COMMIT || (mbi.Protect & 0xF0) == 0)
                continue;

            symbol = binary_search_address(resolver_address);
            if(symbol){
                if(pass == 0)
                    printf("* Import: %08X\n", address);
                import_address = resolver_address;
                buffer[4] = (text_section_data[offset] == 0xe9 || (text_section_data[offset] == 0xff &&
                    text_section_data[offset+1] == 0x25));
            }else{
                if(!read_process_memory(hProcess, resolver_address, buffer, 8))
                    continue;
                if(
                    /* indirect jump/call resolver */
                    (buffer[0] != 0x68 || buffer[5] != 0x9c || buffer[6] != 0x60 || buffer[7] != 0x54)
                    &&
                    /* direct jump/call resolver */
                    ((text_section_data[offset] != 0xe8 && text_section_data[offset] != 0xe9)
                    || buffer[0] != 0x53 || (buffer[1] != 0xe8 && buffer[1] != 0xe9 && buffer[1] != 0xeb))
                )
                    continue;

                if(pass == 0)
                    printf("* Import: %08X\n", address);

                if(!create_and_wait_for_thread(is_jump_or_call ? address : resolver_address,
                    text_section_address, text_section_address + text_section_size))
                    return sub_error("create_and_wait_for_thread");

                if(!read_process_memory(hProcess, hook_code_address + 0x00, buffer, 5))
                    return sub_error("read_process_memory");

                memcpy(&import_address, buffer+0, 4);
                symbol = binary_search_address(import_address);
                if(!symbol)
                    return sub_error("binary_search_address");
            }

            if(pass == 0){
                /* first pass: mark which exported functions are referenced */
                printf("* Resolves to a %s to %s in %s (%08X)\n", is_jump_or_call ?
                    (buffer[4] ? "jump" : "call") : "reference", symbol->name,
                    symbol->parent_dll->name, import_address);
                if(!symbol->is_referenced){
                    symbol->is_referenced = 1;
                    symbol->parent_dll->referenced_symbol_count++;
                }
            }else{
                /* second pass: patch the instructions to use the new import address tables */
                printf("Finding %s in IAT\n", symbol->name);
                for(i=0; i<iat_region_size-3; i+=4){
                    uint32_t iat_entry;
                    memcpy(&iat_entry, iat_section_data + iat_region_address - iat_section_address + i, 4);
                    if(iat_entry == symbol->address)
                        break;
                }
                if(i >= iat_region_size-3)
                    return sub_error("address not found in import address table; resolving import");

                pointer_address = iat_region_address + i;
                if(is_jump_or_call){
                    if(text_section_size - offset < 6)
                        return sub_error("extra byte for jump/call instruction causes overflow; resolving import");
                    text_section_data[offset+0] = 0xff;
                    text_section_data[offset+1] = (buffer[4]) ? 0x25 : 0x15;
                    memcpy(text_section_data + offset + 2, &pointer_address, 4);

                    /* if this was originally a 5-byte instruction, skip over the extra byte in the disassembly */
                    ud_set_input_buffer(&ud, text_section_data + offset + 6, text_section_size - (offset + 6));
                    ud_set_pc(&ud, text_section_address + offset + 6);
                }else
                    memcpy(text_section_data + offset + length - 4, &pointer_address, 4);
            }
        }

        if(pass == 0){
            if(!reconstruct_import_table_and_data())
                return sub_error("reconstruct_import_table_and_data");
            iat_region_address = import_table.iat_region_address;
            iat_region_size = import_table.iat_region_size;
            ordinal_name_rva_region_address = import_table.ordinal_name_rva_region_address;
        }
    }

    /* restore the unlinked version of the import address table by copying from the ordinal-name RVA table */
    memcpy(iat_section_data + iat_region_address - iat_section_address,
        import_section_data + ordinal_name_rva_region_address - import_section_address,
        iat_region_size);

    return 1;
}

static int write_to_file(uint32_t position, const void *data, uint32_t size)
{
    LARGE_INTEGER int1, int2;
    DWORD bytes_transferred;
    int1.QuadPart = position;
    if(SetFilePointerEx(hOutFile, int1, &int2, FILE_BEGIN) == FALSE || int2.QuadPart != int1.QuadPart)
        return sub_error("SetFilePointerEx");
    if(WriteFile(hOutFile, data, size, &bytes_transferred, NULL) == FALSE || bytes_transferred != size)
        return sub_error("WriteFile");
    return 1;
}

static int write_exe()
{
    uint32_t image_base, section_alignment, file_alignment, section_count, section_table_offset;
    uint32_t size_of_exe_file, size_of_image = 0, size_of_headers, checksum = 0;
    uint32_t base_of_code = 0, base_of_data = 0;
    uint32_t size_of_code = 0, size_of_initialized_data = 0, size_of_uninitialized_data = 0;
    uint32_t prev_memory_address = 0, offset, padding, i;
    uint8_t buffer[1024] = {0};

    /* remove the sections added by SafeDisc */
    i=0;
    while(i<game_ctx.number_of_sections){
        if(!memcmp(game_ctx.section_table[i], "stxt", 4)){
            if(game_ctx.section_data[i]){
                free(game_ctx.section_data[i]);
                game_ctx.section_data[i] = NULL;
            }
            memcpy(game_ctx.section_table[i], game_ctx.section_table[i+1],
                (game_ctx.number_of_sections - i - 1) * sizeof(*game_ctx.section_table));
            memcpy(game_ctx.section_data+i, game_ctx.section_data+i+1,
                (game_ctx.number_of_sections - i - 1) * sizeof(*game_ctx.section_data));
            memcpy(game_ctx.section_address+i, game_ctx.section_address+i+1,
                (game_ctx.number_of_sections - i - 1) * sizeof(*game_ctx.section_address));
            memcpy(game_ctx.section_size+i, game_ctx.section_size+i+1,
                (game_ctx.number_of_sections - i - 1) * sizeof(*game_ctx.section_size));
            game_ctx.number_of_sections--;
            continue;
        }
        i++;
    }

    section_count = game_ctx.number_of_sections;
    if(section_count == 0)
        return sub_error("no sections remaining; updating section table");

    memcpy(&section_alignment, game_ctx.pe_header + 0x38, 4);
    if(section_alignment == 0)
        section_alignment = 512;
    memcpy(&file_alignment, game_ctx.pe_header + 0x3c, 4);
    if(file_alignment == 0)
        file_alignment = 512;
    image_base = game_ctx.image_base;
    section_table_offset = game_ctx.pe_header_offset + game_ctx.pe_header_size;

    /* make the memory for all sections contiguous */
    for(i=0; i<section_count; i++){
        uint32_t memory_address, memory_size, prev_memory_size;

        memcpy(&memory_size, game_ctx.section_table[i] + 8, 4);
        memcpy(&memory_address, game_ctx.section_table[i] + 12, 4);
        if(memory_address % section_alignment != 0)
            return sub_error("section address is not aligned to section_alignment; updating section table");
        if(memory_size > 0xFFFFFFFF - memory_address)
            return sub_error("section size causes overflow for process; updating section table");

        if(i != 0){
            if(memory_address <= prev_memory_address)
                return sub_error("section addresses are not monotonically increasing; updating section table");

            prev_memory_size = memory_address - prev_memory_address;
            write_uint32(game_ctx.section_table[i-1] + 8, prev_memory_size);
        }
        prev_memory_address = memory_address;
    }

    /* set the offset to the section data with padding to file_alignment */
    offset = section_table_offset + 40*section_count;
    padding = file_alignment - (offset % file_alignment);
    if(padding != file_alignment){
        if(offset > 0xFFFFFFFF - padding)
            return sub_error("padding causes overflow for exe file; updating section table");
        offset += padding;
    }
    size_of_headers = offset;

    /* calculate physical offsets and sizes for the sections
    ** and obtain the base/size statistics for the exe header */
    for(i=0; i<section_count; i++){
        uint32_t memory_size, memory_address, physical_size, physical_offset, flags;

        memcpy(&memory_size, game_ctx.section_table[i] + 8, 4);
        memcpy(&memory_address, game_ctx.section_table[i] + 12, 4);
        memcpy(&physical_size, game_ctx.section_table[i] + 16, 4);
        memcpy(&physical_offset, game_ctx.section_table[i] + 20, 4);
        memcpy(&flags, game_ctx.section_table[i] + 36, 4);

        printf("section %u: memory size %08X, memory address %08X, physical size %08X, physical offset %08X, flags %08X\n",
            i, memory_size, memory_address, physical_size, physical_offset, flags);

        if(i == section_count-1){
            /* add padding for the last section; this is necessary because the last section does
            ** not need to lead into another section on aligned memory */
            padding = file_alignment - (memory_size % file_alignment);
            if(padding != file_alignment){
                if(memory_size > 0xFFFFFFFF - padding)
                    return sub_error("last section padding to file_alignment is out of range; updating section table");
                memory_size += padding;
            }
            if(memory_size > 0xFFFFFFFF - memory_address)
                return sub_error("last section size is out of range; updating section table");

            /* update the memory image size field for the exe header */
            size_of_image = memory_address + memory_size;
            padding = section_alignment - (size_of_image % section_alignment);
            if(padding != section_alignment){
                if(size_of_image > 0xFFFFFFFF - padding)
                    return sub_error("last section padding to section_alignment is out of range; updating section table");
                size_of_image += padding;
            }
        }

        /* update the base and size fields for the exe header */
        if(flags & 0x00000020){ /* code */
            if(!base_of_code)
                base_of_code = memory_address;
            size_of_code += memory_size;
        }else if(flags & 0x00000040){ /* initialized data */
            if(!base_of_data)
                base_of_data = memory_address;
            size_of_initialized_data += memory_size;
        }else if(flags & 0x00000080){ /* uninitialized data */
            if(!base_of_data)
                base_of_data = memory_address;
            size_of_uninitialized_data += memory_size;
        }

        /* if the section uses initialized data, specify its new physical offset
        ** in the exe file, padded to file_alignment */
        if(physical_size != 0 && !(flags & 0x00000080)){
            padding = file_alignment - (offset % file_alignment);
            if(padding != file_alignment){
                if(offset > 0xFFFFFFFF - padding)
                    return sub_error("section padding causes overflow for exe file; updating section table");
                offset += padding;
            }

            write_uint32(game_ctx.section_table[i] + 20, offset);

            if(offset > 0xFFFFFFFF - physical_size)
                return sub_error("section data causes overflow for exe file; updating section table");
            offset += physical_size;
        }else{
            /* uninitialized data: set the physical size and offset fields to 0 */
            write_uint32(game_ctx.section_table[i] + 16, 0);
            write_uint32(game_ctx.section_table[i] + 20, 0);
        }
    }

    /* pad the remainder of the file */
    padding = file_alignment - (offset % file_alignment);
    if(padding != file_alignment){
        if(offset > 0xFFFFFFFF - padding)
            return sub_error("end-of-file padding causes overflow for exe file; updating section table");
        offset += padding;
    }
    size_of_exe_file = offset;

    /* write the updated values to the exe header */
    game_ctx.original_entry_point -= image_base;
    import_table.import_table_region_size = import_table.ordinal_name_region_address
        + import_table.ordinal_name_region_size - import_table.import_table_region_address;
    import_table.import_table_region_address -= image_base;
    import_table.iat_region_address -= image_base;
    memcpy(game_ctx.dos_header + 0x12, &checksum, 2);
    memcpy(game_ctx.pe_header + 0x06, &section_count, 2);
    memcpy(game_ctx.pe_header + 0x1c, &size_of_code, 4);
    memcpy(game_ctx.pe_header + 0x20, &size_of_initialized_data, 4);
    memcpy(game_ctx.pe_header + 0x24, &size_of_uninitialized_data, 4);
    memcpy(game_ctx.pe_header + 0x28, &game_ctx.original_entry_point, 4);
    memcpy(game_ctx.pe_header + 0x2c, &base_of_code, 4);
    memcpy(game_ctx.pe_header + 0x30, &base_of_data, 4);
    memcpy(game_ctx.pe_header + 0x50, &size_of_image, 4);
    memcpy(game_ctx.pe_header + 0x54, &size_of_headers, 4);
    memcpy(game_ctx.pe_header + 0x58, &checksum, 4);
    memcpy(game_ctx.pe_header + 0x80, &import_table.import_table_region_address, 4);
    memcpy(game_ctx.pe_header + 0x84, &import_table.import_table_region_size, 4);
    memcpy(game_ctx.pe_header + 0xd8, &import_table.iat_region_address, 4);
    memcpy(game_ctx.pe_header + 0xdc, &import_table.iat_region_size, 4);

    /* write the data to the file */
    for(offset=0; offset<size_of_exe_file-1024; offset+=1024)
        if(!write_to_file(offset, buffer, 1024))
            return sub_error("write_to_file for zero data");
    if(!write_to_file(offset, buffer, size_of_exe_file-offset))
        return sub_error("write_to_file for end of zero data");
    if(!write_to_file(0, game_ctx.dos_header, game_ctx.pe_header_offset))
        return sub_error("write_to_file for dos header");
    if(!write_to_file(game_ctx.pe_header_offset, game_ctx.pe_header, game_ctx.pe_header_size))
        return sub_error("write_to_file for pe header");
    if(!write_to_file(section_table_offset, game_ctx.section_table, 40*section_count))
        return sub_error("write_to_file for section table");
    for(i=0; i<section_count; i++){
        uint32_t physical_size, physical_offset;

        memcpy(&physical_size, game_ctx.section_table[i] + 16, 4);
        memcpy(&physical_offset, game_ctx.section_table[i] + 20, 4);
        if(physical_size){
            if(physical_size > game_ctx.section_size[i])
                physical_size = game_ctx.section_size[i];
            printf("section %u: writing %08X bytes to offset %08X\n", i, physical_size, physical_offset);
            if(!write_to_file(physical_offset, game_ctx.section_data[i], physical_size))
                return sub_error("write_to_file for section data");
        }
    }

    return 1;
}

int main(int argc, char *argv[])
{
    char executable_name[268] = "", command[268] = "", directory[268] = "",
        *directory_file_part = NULL, *outfile_file_part = NULL;
    SECURITY_ATTRIBUTES sa;
    unsigned i;
    DWORD event_value;
    uint32_t pi_address = 0;
    int patched;

    /* make sure the arguments are correctly formatted */
    if(argc != 3 || argv[1][0] == '-' || strlen(argv[1]) > 260 || strlen(argv[2]) > 260
        || GetFullPathName(argv[1], 268, directory, &directory_file_part) >= 268
        || directory_file_part == NULL || directory_file_part - directory < 1
        || directory[0] == '\0'
        || GetFullPathName(argv[2], 268, outfile, &outfile_file_part) >= 268
        || outfile_file_part == NULL
        || outfile[0] == '\0'
        || sprintf(command, "\"%.260s\" -w", argv[1]) < 0 /* append "-w" for windowed mode, if the game supports it */
        || command[0] == '\0'){
        printf("Usage: unpack INFILE OUTFILE\n");
        return EXIT_SUCCESS;
    }

    directory_file_part[-1] = '\0'; /* remove the filename and trailing backslash to leave just the directory */
    outfile[266] = '\0';
    memset(&game_ctx, 0, sizeof(game_ctx));
    memset(&debugger_ctx, 0, sizeof(debugger_ctx));
    current_thread_handle = (uint32_t)GetCurrentThread(); /* a pseudo-handle, 0xFFFFFFFE on NT-based Windows */

    ud_init(&ud);
    ud_set_mode(&ud, 32);

    SetConsoleCtrlHandler(HandlerRoutine, TRUE); /* register the Ctrl+C and console close events */

    /* open the output file for writing */
    hOutFile = CreateFile(argv[2], GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hOutFile == INVALID_HANDLE_VALUE)
        return Shutdown("CreateFile on the output file");

    /* create the event objects for signaling in the game and debugger processes */
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    for(i=0; i<event_count; i++)
        if((events[i] = CreateEvent(&sa, FALSE, FALSE, NULL)) == NULL)
            return Shutdown("CreateEvent");

    /* we are assuming that the image base of kernel32.dll never changes between processes;
    ** Toolhelp32 and PSAPI do not yet work on the child process at this point because the child process
    ** has not completely initialized its process environment block. */
    kernel32_base = (uint32_t)GetModuleHandle("kernel32.dll");
    if(!kernel32_base)
        return Shutdown("GetModuleHandle");
    printf("kernel32 image base: %08X\n", kernel32_base);
    ntdll_base = (uint32_t)GetModuleHandle("ntdll.dll");
    if(!ntdll_base)
        return Shutdown("GetModuleHandle");
    printf("ntdll image base: %08X\n", ntdll_base);

    for(i=0; i<api_count; i++){
        api_address[i] = (uint32_t)GetProcAddress((HMODULE)kernel32_base, api_string[i]);
        if(!api_address[i])
            return Shutdown("GetProcAddress");
        printf("%s address: %08X\n", api_string[i], api_address[i]);
    }

    /* create, hook, and start the game process */
    printf("Game process:\n");
    if(!create_process_and_inject_hook_code(&game_ctx, argv[1], command, directory, SW_SHOWNORMAL,
        events[game_entry_point_event], events[game_entry_point_response]))
        return Shutdown("create_process_and_inject_hook_code for the game process");
    if(!find_game_oep())
        return Shutdown("find_game_oep");
    if(!install_game_hooks())
        return Shutdown("install_game_hooks");
    printf("\n");

    /* resume the thread and wait for our hooked CreateProcessA to be called */
    if(SetEvent(events[game_entry_point_response]) == FALSE)
        return Shutdown("SetEvent");
    event_value = WaitForMultipleObjects(3, events, FALSE, INFINITE) - WAIT_OBJECT_0;
    if((unsigned)event_value > 3)
        return Shutdown("WaitForMultipleObjects");
    if(event_value == game_entry_point_event)
        return Shutdown("Received game_entry_point_event but expected CreateProcessA_event; WaitForMultipleObjects");
    if(event_value == WaitForSingleObject_event)
        return Shutdown("Received WaitForSingleObject_event but expected CreateProcessA_event; WaitForMultipleObjects");

    /* create, hook, and start the debugger process, and pass the result to the game thread */
    if(!get_debugger_process_args(executable_name, command, directory, &pi_address))
        return Shutdown("get_debugger_process_args");
    if(!create_process_and_inject_hook_code(&debugger_ctx, executable_name, command, directory, SW_HIDE,
        events[debugger_entry_point_event], events[debugger_entry_point_response]))
        return Shutdown("create_process_and_inject_hook_code for the debugger process");
    if(!install_debugger_hooks())
        return Shutdown("install_debugger_hooks");
    if(SetEvent(events[debugger_entry_point_response]) == FALSE)
        return Shutdown("SetEvent");
    if(!continue_game_thread(pi_address))
        return Shutdown("continue_game_thread");

    /* wait for the hooked WaitForSingleObject call */
    event_value = WaitForMultipleObjects(3, events, FALSE, INFINITE) - WAIT_OBJECT_0;
    if((unsigned)event_value > 3)
        return Shutdown("WaitForMultipleObjects");
    if(event_value == game_entry_point_event)
        return Shutdown("Received game_entry_point_event but expected WaitForSingleObject_event; WaitForMultipleObjects");
    if(event_value == CreateProcessA_event)
        return Shutdown("Received CreateProcessA_event but expected WaitForSingleObject_event; WaitForMultipleObjects");

    /* suspend the game process's threads, and dump and fix up all of the game's sections */
    if(!suspend_game_threads())
        return Shutdown("suspend_game_threads");
    if(!dump_game_sections())
        return Shutdown("dump_game_sections");
    if(!enumerate_imported_dlls())
        return Shutdown("enumerate_imported_dlls");
    do {
        patched = 0;
        if(!fix_nanomites(&patched))
            return Shutdown("fix_nanomites");
        if(!fix_stolen_bytes(&patched))
            return Shutdown("fix_stolen_bytes");
    } while(patched);
    if(!hook_all_imported_functions())
        return Shutdown("hook_all_imported_functions");
    if(!fix_imports())
        return Shutdown("fix_imports");

    /* write out the exe to the output file */
    if(!write_exe())
        return Shutdown("write_exe");

    return Shutdown(NULL);
}