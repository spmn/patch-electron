#include <Windows.h>
#include <psapi.h>
#include <vector>

// #define SLACK
#define ATOM

#if defined(SLACK)
// Supports Electron 12.0.2 (Slack 4.15.0)

#   define ELECTRON_PROCESS_NAME            L"Slack.exe"
#   define ALLOW_ALL_INLINE_OFFSET          0x215420
#   define ALLOW_EVAL_OFFSET                0x6FAFB0
#   define EXPECTED_ALLOW_ALL_INLINE_INSTR  "\x44\x8D\x41\xEB\x41\x83"
#   define EXPECTED_ALLOW_EVAL_INSTR        "\x41\x56\x56\x57\x53\x48"

#elif defined(ATOM)
// Supports Electron 9.4.4 (Atom 1.58.0)

#   define ELECTRON_PROCESS_NAME            L"atom.exe"
#   define ALLOW_ALL_INLINE_OFFSET          0x480A760
#   define ALLOW_EVAL_OFFSET                0x4211820
#   define EXPECTED_ALLOW_ALL_INLINE_INSTR  "\x56\x48\x83\xEC\x20\x48"
#   define EXPECTED_ALLOW_EVAL_INSTR        "\x41\x56\x56\x57\x53\x48"

#endif

#define RETURN_TRUE_INSTR                   "\xB8\x01\x00\x00\x00\xC3"


void Patch(HANDLE hProcess, uintptr_t patchAddress, LPCVOID expectedOldInstructions, LPCVOID newInstructions, SIZE_T size)
{
    SIZE_T bytesRead = 0, bytesWritten = 0;
    BOOL retVal;

    std::vector<BYTE> oldInstructions;
    oldInstructions.resize(size);

    retVal = ReadProcessMemory(hProcess, (void *)patchAddress, &oldInstructions[0], size, &bytesRead);
    if (retVal && bytesRead == size && 0 == memcmp(&oldInstructions[0], expectedOldInstructions, size))
    {
        retVal = WriteProcessMemory(hProcess, (void *)patchAddress, newInstructions, size, &bytesWritten);
        if (retVal && bytesWritten == size)
        {
            wprintf_s(L"    Patched address: %llx\n", patchAddress);
        }
        else
        {
            wprintf_s(L"    Failed to patch address: %llx, error: %d [can't write]\n", patchAddress, GetLastError());
        }
    }
    else
    {
        // Invalid electron version.
        wprintf_s(L"    Failed to patch address: %llx, error: %d [instructions don't match]\n", patchAddress, GetLastError());
    }
}

void PatchIfNeeded(DWORD processID)
{
    const WCHAR kszExpectedProcessName[] = ELECTRON_PROCESS_NAME;
    WCHAR szProcessName[MAX_PATH] = L"<unknown>";

    // Get a handle to the process.

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE, processID);

    // Get the process name.

    if (NULL != hProcess)
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModulesEx(hProcess, &hMod, sizeof(hMod),
            &cbNeeded, LIST_MODULES_ALL))
        {
            GetModuleBaseNameW(hProcess, hMod, szProcessName, _countof(szProcessName));

            if (_wcsicmp(szProcessName, kszExpectedProcessName) == 0)
            {
                uintptr_t baseAddress = (uintptr_t)hMod;
                uintptr_t patchAddress;

                // hMod = base address of slack.exe inside slack proc virtual memory

                wprintf_s(L"Patching process %s, ID: %d, base address: %llx\n", szProcessName, processID, baseAddress);

                /*
                * Patch to allow inline scripts
                * eg: script = document.createElement('script'); script.innerText = 'console.log("hello")'; document.body.appendChild(script);
                *
                * Refused to execute inline script because it violates the following Content Security Policy directive:
                * 
                * .text:0000000140215420             ; bool __fastcall blink::CSPSourceListAllowAllInline(network::mojom::CSPDirectiveName, const network::mojom::blink::CSPSourceList *)
                * .text:0000000140215420             ?CSPSourceListAllowAllInline@blink@@YA_NW4CSPDirectiveName@mojom@network@@AEBVCSPSourceList@134@@Z proc near
                * .text:0000000140215420                                                     ; CODE XREF: blink::CSPDirectiveList::AllowInline(blink::ContentSecurityPolicy::InlineType,blink::Element *,WTF::String const &,WTF::String const &,WTF::String const &,WTF::OrdinalNumber const &,blink::ReportingDisposition)
                * .text:0000000140215420                                                     ; blink::CSPDirectiveList::CheckInlineAndReportViolation(blink::CSPOperativeDirective,WTF::String const &,blink::Element *,WTF::String const &,WTF::String const &,WTF::OrdinalNumber const &,bool,WTF::String const &,network::mojom::CSPDirectiveName) ...
                * .text:0000000140215420 44 8D 41 EB                 lea     r8d, [rcx-15h]
                * .text:0000000140215424 41 83 F8 06                 cmp     r8d, 6
                * .text:0000000140215428 73 20                       jnb     short loc_14021544A
                */

                patchAddress = baseAddress + ALLOW_ALL_INLINE_OFFSET;
                wprintf_s(L"  Patching blink::CSPSourceListAllowAllInline, address: %llx\n", patchAddress);
                Patch(hProcess, patchAddress, EXPECTED_ALLOW_ALL_INLINE_INSTR, RETURN_TRUE_INSTR, 6);

                /*
                * Patch to allow eval()
                * eg: eval('console.log("hello")');
                * 
                * Uncaught EvalError: Refused to evaluate a string as JavaScript because 'unsafe-eval' is not an allowed source of script in the following Content Security Policy directive:
                * 
                * .text:00000001406FAFB0             ; __int64 __fastcall blink::CSPDirectiveList::AllowEval(__int64, blink::ContentSecurityPolicy::ExceptionStatus, const WTF::String *)
                * .text:00000001406FAFB0             ?AllowEval@CSPDirectiveList@blink@@QEBA_NW4ReportingDisposition@2@W4ExceptionStatus@ContentSecurityPolicy@2@AEBVString@WTF@@@Z proc near
                * .text:00000001406FAFB0                                                     ; CODE XREF: blink::ContentSecurityPolicy::ApplyPolicySideEffectsToDelegate(void)
                * .text:00000001406FAFB0                                                     ; blink::ContentSecurityPolicy::AllowEval(blink::ReportingDisposition,blink::ContentSecurityPolicy::ExceptionStatus,WTF::String const &) ...
                * .text:00000001406FAFB0 41 56                       push    r14
                * .text:00000001406FAFB2 56                          push    rsi
                * .text:00000001406FAFB3 57                          push    rdi
                * .text:00000001406FAFB4 53                          push    rbx
                * .text:00000001406FAFB5 48 83 EC 38                 sub     rsp, 38h%
                */

                patchAddress = baseAddress + ALLOW_EVAL_OFFSET;
                wprintf_s(L"  Patching blink::CSPDirectiveList::AllowEval, address: %llx\n", patchAddress);
                Patch(hProcess, patchAddress, EXPECTED_ALLOW_EVAL_INSTR, RETURN_TRUE_INSTR, 6);

                wprintf_s(L"\n");
            }
        }

        // Release the handle to the process.
        CloseHandle(hProcess);
    }
}

int main(void)
{
    // Get the list of process identifiers.

    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        return 1;
    }


    // Calculate how many process identifiers were returned.

    cProcesses = cbNeeded / sizeof(DWORD);

    // Print the name and process identifier for each process.

    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            PatchIfNeeded(aProcesses[i]);
        }
    }

    return 0;
}