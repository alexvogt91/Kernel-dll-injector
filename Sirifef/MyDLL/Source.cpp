#include <Windows.h>


BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lParam)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		MessageBox(NULL, L"DLL Injected", L"Kernel Injector", MB_ICONINFORMATION);
		break;
	case DLL_PROCESS_DETACH:
		MessageBox(NULL, L"DLL Detached from process", L"Kernel Injector", MB_ICONINFORMATION);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	default:
		break;
	}

	return TRUE;
}