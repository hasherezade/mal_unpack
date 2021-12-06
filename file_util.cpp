#include "file_util.h"

#include "ntddk.h"

namespace file_util {

	const SIZE_T MAX_NT_PATH = (MAX_PATH * 2);

	NTSTATUS fetch_volume_handle(std::wstring driveLetter, HANDLE& RootHandle)
	{
		RootHandle = NULL;

		UNICODE_STRING RootDirectory = { 0 };
		OBJECT_ATTRIBUTES Attributes = { 0 };
		IO_STATUS_BLOCK Io = { 0 };

		std::wstring volume_path = L"\\??\\" + driveLetter + L":\\";
		RtlInitUnicodeString(&RootDirectory, volume_path.c_str());
		InitializeObjectAttributes(&Attributes, &RootDirectory, OBJ_CASE_INSENSITIVE, NULL, NULL);

		return NtOpenFile(&RootHandle, FILE_READ_DATA, &Attributes, &Io, FILE_SHARE_READ, FILE_OPEN);
	}

	bool set_to_delete(wchar_t file_name[MAX_NT_PATH])
	{
		HANDLE hFile = NULL;
		IO_STATUS_BLOCK ioStatusBlock = { 0 };
		OBJECT_ATTRIBUTES objAttr = { 0 };
		IO_STATUS_BLOCK Io = { 0 };

		UNICODE_STRING filePathU = { 0 };
		RtlInitUnicodeString(&filePathU, file_name);
		InitializeObjectAttributes(&objAttr, &filePathU, OBJ_CASE_INSENSITIVE, NULL, NULL);

		NTSTATUS status = NtCreateFile(&hFile, SYNCHRONIZE | DELETE, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
		if (status != STATUS_SUCCESS) {
			std::cout << "Failed to open the file for deletion:" << std::hex << status << "\n";
			return false;
		}
		FILE_DISPOSITION_INFORMATION disposition = { TRUE };
		status = NtSetInformationFile(hFile, &ioStatusBlock, &disposition, sizeof(FILE_DISPOSITION_INFORMATION), FileDispositionInformation);
		NtClose(hFile);
#ifdef _DEBUG
		std::cout << "Attempted to set delete disposition: " << std::hex << status << "\n";
#endif
		if (status == STATUS_SUCCESS) {
			return true;
		}
		return false;
	}
};


size_t file_util::list_files(std::set<ULONGLONG>& filesIds)
{
	FILE_ID_DESCRIPTOR FileDesc = { 0 };
	FileDesc.dwSize = sizeof(FILE_ID_DESCRIPTOR);
	FileDesc.Type = FileIdType;

	char file_name[MAX_PATH] = { 0 };
	HANDLE volumeHndl = NULL;
	if (fetch_volume_handle(L"C", volumeHndl) != STATUS_SUCCESS) {
		return 0;
	}
	size_t processed = 0;
	std::set<ULONGLONG>::iterator itr = filesIds.begin();

	for (itr = filesIds.begin(); itr != filesIds.end(); ++itr) {
		FileDesc.FileId.QuadPart = *itr;

		HANDLE hFile = OpenFileById(volumeHndl, &FileDesc, FILE_GENERIC_READ, FILE_SHARE_READ, NULL, 0);
		if (!hFile || hFile == INVALID_HANDLE_VALUE) {
			continue;
		}
		BOOL gotName = GetFinalPathNameByHandleA(hFile, file_name, MAX_PATH, VOLUME_NAME_DOS);
		NtClose(hFile);

		if (!gotName) {
			std::cerr << "Failed to retrieve the name of the file with ID: " << std::hex << FileDesc.FileId.QuadPart << "\n";
			continue;
		}
		processed++;
		std::cout << "File: " << file_name << "\n";
	}
	return processed;
}


size_t file_util::delete_dropped_files(std::set<ULONGLONG>& filesIds)
{
	FILE_ID_DESCRIPTOR FileDesc = { 0 };
	FileDesc.dwSize = sizeof(FILE_ID_DESCRIPTOR);
	FileDesc.Type = FileIdType;

	const size_t max_len = MAX_NT_PATH;
	wchar_t file_name[max_len] = { 0 };
	HANDLE volumeHndl = NULL;
	if (fetch_volume_handle(L"C", volumeHndl) != STATUS_SUCCESS) {
		return 0;
	}
	size_t processed = 0;
	std::set<ULONGLONG>::iterator itr = filesIds.begin();

	while (itr != filesIds.end()) {
		FileDesc.FileId.QuadPart = *itr;
		++itr;

		HANDLE hFile = OpenFileById(volumeHndl, &FileDesc, FILE_GENERIC_READ, FILE_SHARE_READ, NULL, 0);
		if (!hFile || hFile == INVALID_HANDLE_VALUE) {
			continue;
		}
		BOOL gotName = GetFinalPathNameByHandleW(hFile, file_name, max_len, VOLUME_NAME_NT);
		NtClose(hFile);

		if (!gotName) {
#ifdef _DEBUG
			std::cerr << "Failed to retrieve the name of the file with ID: " << std::hex << FileDesc.FileId.QuadPart << "\n";
#endif
			continue;
		}
#ifdef _DEBUG
		std::wcout << "File: " << file_name << "\n";
#endif
		// file cannot be deleted by its ID, so reopen it again by name...
		if (set_to_delete(file_name)) {

			filesIds.erase(FileDesc.FileId.QuadPart);
			processed++;
		}
#ifdef _DEBUG
		else {
			const DWORD err = GetLastError();
			std::cout << "Failed to delete dropped file: " << file_name << " Error: " << std::hex << err << "\n";
		}
#endif
	}
	return processed;
}

