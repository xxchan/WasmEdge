// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2019-2022 Second State INC

#include "common/defines.h"
#if WASMEDGE_OS_WINDOWS

#include "common/errcode.h"
#include "host/wasi/environ.h"
#include "host/wasi/inode.h"
#include "host/wasi/vfs.h"
#include "win.h"
#include <algorithm>
#include <boost/align/aligned_allocator.hpp>
#include <new>
#include <vector>

#define NANOSECONDS_PER_TICK 100ULL
#define TICKS_PER_SECOND 10000000ULL
#define SEC_TO_UNIX_EPOCH 11644473600ULL
#define TICKS_TO_UNIX_EPOCH (TICKS_PER_SECOND * SEC_TO_UNIX_EPOCH)

namespace WasmEdge {
namespace Host {
namespace WASI {

// clang-format off
  /*

  ## Implementation Status

  ### Host Functions: Function-wise Summary

  | Function               | Status             | Comment                                                                                                                                                                                                                                                          |
  | ---------------------- | ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | `open`                 | complete           | some flags may not have an equivalent                                                                                                                                                                                                                            |
  | `fdAdvise`             | no equivalent      | have to find an solution                                                                                                                                                                                                                                         |
  | `fdAllocate`           | complete           | None                                                                                                                                                                                                                                                             |
  | `fdDatasync`           | complete           | documentation is not clear on whether metadata is also flushed, refer [here](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers#remarks)                                                                                     |
  | `fdFdstatGet`          | complete           | depends on a partially complete function - `fromFileType` (this function has been implemented partially in linux), find appropriate functions to query the equivalent flags and fill the other fields (the implementation for linux has not filled these fields) |
  | `fdFdstatSetFlags`     | complete           | depends on a partially complete function - `fromFileType` and an equivalent for device ID needs to be found which may be related to the file index                                                                                                               |
  | `fdFilestatSetSize`    | complete           | None                                                                                                                                                                                                                                                             |
  | `fdFilestatSetTimes`   | complete           | None                                                                                                                                                                                                                                                             |
  | `fdPread`              | complete           | there maybe issues due to casting                                                                                                                                                                                                                                |
  | `fdPwrite`             | complete           | there maybe issues due to casting                                                                                                                                                                                                                                |
  | `fdRead`               | complete           | had already been implemented                                                                                                                                                                                                                                     |
  | `fdWrite`              | complete           | had already been implemented                                                                                                                                                                                                                                     |
  | `fdReaddir`            | complete           | Need to optimise the function and it depends on a partially implemented function - `fromFileType`                                                                                                                                                                |
  | `fdSeek`               | complete           | None                                                                                                                                                                                                                                                             |
  | `fdSync`               | complete           | works when the file has been opened with the flags `FILE_FLAG_NO_BUFFERING` and `FILE_FLAG_WRITE_THROUGH` which I suspect is the desired behaviour, refer [here](https://devblogs.microsoft.com/oldnewthing/20210729-00/?p=105494)                               |
  | `fdTell`               | complete           | None                                                                                                                                                                                                                                                             |
  | `getNativeHandler`     | complete           | had already been implemented                                                                                                                                                                                                                                     |
  | `pathCreateDirectory`  | complete           | None                                                                                                                                                                                                                                                             |
  | `pathFilestatGet`      | complete           | similar to `stat` which uses absolute paths                                                                                                                                                                                                                      |
  | `pathFilestatSetTimes` | complete           | None                                                                                                                                                                                                                                                             |
  | `pathLink`             | complete           | None                                                                                                                                                                                                                                                             |
  | `pathOpen`             | complete           | None                                                                                                                                                                                                                                                             |
  | `pathReadlink`         | complete           | None                                                                                                                                                                                                                                                             |
  | `pathRemoveDirectory`  | complete           | had been already implemented                                                                                                                                                                                                                                     |
  | `pathRename`           | complete           | None                                                                                                                                                                                                                                                             |
  | `pathSymlink`          | complete           | None                                                                                                                                                                                                                                                             |
  | `pathUnlinkFile`       | complete           | None                                                                                                                                                                                                                                                             |
  | `pollOneoff`           | incomplete         | could not find a similar concept on windows                                                                                                                                                                                                                      |
  | `sockGetPeerAddr`      | incomplete         | behaviour is unspecified                                                                                                                                                                                                                                         |
  | `unsafeFiletype`       | partially complete | need to find equivalent flags for three file types                                                                                                                                                                                                               |
  | `filetype`             | partially complete | need to find equivalent flags for three file types                                                                                                                                                                                                               |
  | `isDirectory`          | complete           | None                                                                                                                                                                                                                                                             |
  | `isSymlink`            | complete           | None                                                                                                                                                                                                                                                             |
  | `filesize`             | complete           | None                                                                                                                                                                                                                                                             |
  | `canBrowse`            | incomplete         | need to find appropriate functions                                                                                                                                                                                                                               |
  | `Poller::clock`        | incomplete         | could not find a similar concept on windows                                                                                                                                                                                                                      |
  | `Poller::read`         | incomplete         | could not find a similar concept on windows                                                                                                                                                                                                                      |
  | `Poller::write`        | incomplete         | could not find a similar concept on windows                                                                                                                                                                                                                      |
  | `Poller::wait`         | incomplete         | could not find a similar concept on windows                                                                                                                                                                                                                      |

  Resolves #1227 and #1477

  Reference: https://github.com/WasmEdge/WasmEdge/issues/1477

  */
// clang-format on

namespace {

namespace winapi = boost::winapi;

const winapi::LARGE_INTEGER_ ZERO_OFFSET = {.LowPart = 0, .HighPart = 0};

inline constexpr __wasi_size_t
calculateAddrinfoLinkedListSize(struct addrinfo *const Addrinfo) {
  __wasi_size_t Length = 0;
  for (struct addrinfo *TmpPointer = Addrinfo; TmpPointer != nullptr;
       TmpPointer = TmpPointer->ai_next) {
    Length++;
  }
  return Length;
};

static bool isSocket(LPVOID H) {
  if (likely(winapi::GetFileType(H) != winapi::FILE_TYPE_PIPE_)) {
    return false;
  }
  return !winapi::GetNamedPipeInfo(H, nullptr, nullptr, nullptr, nullptr);
}

static winapi::SOCKET_ toSocket(winapi::HANDLE_ H) {
  return reinterpret_cast<winapi::SOCKET_>(H);
}

std::pair<const char *, std::unique_ptr<char[]>>
createNullTerminatedString(std::string_view View) noexcept {
  const char *CStr = nullptr;
  std::unique_ptr<char[]> Buffer;
  if (!View.empty()) {
    if (const auto Pos = View.find_first_of('\0');
        Pos != std::string_view::npos) {
      CStr = View.data();
    } else {
      Buffer = std::make_unique<char[]>(View.size() + 1);
      std::copy(View.begin(), View.end(), Buffer.get());
      CStr = Buffer.get();
    }
  }
  return {CStr, std::move(Buffer)};
}

inline winapi::LARGE_INTEGER_
toLargeIntegerFromUnsigned(unsigned long long Value) {
  winapi::LARGE_INTEGER_ Result;

  // Does the compiler natively support 64-bit integers?
#ifdef INT64_MAX
  Result.QuadPart = static_cast<int64_t>(Value);
#else
  Result.high_part = (value & 0xFFFFFFFF00000000) >> 32;
  Result.low_part = value & 0xFFFFFFFF;
#endif
  return Result;
}

inline winapi::LARGE_INTEGER_ toLargeIntegerFromSigned(long long Value) {
  winapi::LARGE_INTEGER_ Result;

#ifdef INT64_MAX
  Result.QuadPart = static_cast<int>(Value);
#else
  Result.high_part = (value & 0xFFFFFFFF00000000) >> 32;
  Result.low_part = value & 0xFFFFFFFF;
#endif
  return Result;
}

inline constexpr __wasi_errno_t fromWinError(winapi::DWORD_ Winerr) {
  __wasi_errno_t Error = __WASI_ERRNO_NOSYS;
  switch (Winerr) {
  case winapi::ERROR_ACCESS_DENIED_:
  case winapi::ERROR_ACCOUNT_DISABLED_:
  case winapi::ERROR_ACCOUNT_RESTRICTION_:
  case winapi::ERROR_CANNOT_MAKE_:
  case winapi::ERROR_CURRENT_DIRECTORY_:
  case winapi::ERROR_INVALID_ACCESS_:
  case winapi::ERROR_INVALID_LOGON_HOURS_:
  case winapi::ERROR_INVALID_WORKSTATION_:
  case winapi::ERROR_LOGON_FAILURE_:
  case winapi::ERROR_NO_SUCH_PRIVILEGE_:
  case winapi::ERROR_PASSWORD_EXPIRED_:
  case winapi::ERROR_CANT_ACCESS_FILE_:
  case winapi::ERROR_NOACCESS_:
  case winapi::WSAEACCES_:
  case winapi::ERROR_ELEVATION_REQUIRED_:
    Error = __WASI_ERRNO_ACCES;
    break;
  case winapi::ERROR_ALREADY_ASSIGNED_:
  case winapi::ERROR_BUSY_DRIVE_:
  case winapi::ERROR_DEVICE_IN_USE_:
  case winapi::ERROR_DRIVE_LOCKED_:
  case winapi::ERROR_LOCKED_:
  case winapi::ERROR_OPEN_FILES_:
  case winapi::ERROR_PATH_BUSY_:
  case winapi::ERROR_PIPE_BUSY_:
  case winapi::ERROR_BUSY_:
  case winapi::ERROR_LOCK_VIOLATION_:
  case winapi::ERROR_SHARING_VIOLATION_:
    Error = __WASI_ERRNO_BUSY;
    break;
  case winapi::ERROR_ALREADY_EXISTS_:
  case winapi::ERROR_FILE_EXISTS_:
    Error = __WASI_ERRNO_EXIST;
    break;
  case winapi::ERROR_ARITHMETIC_OVERFLOW_:
    Error = __WASI_ERRNO_RANGE;
    break;
  case winapi::ERROR_BAD_COMMAND_:
  case winapi::ERROR_CANTOPEN_:
  case winapi::ERROR_CANTREAD_:
  case winapi::ERROR_CANTWRITE_:
  case winapi::ERROR_CRC_:
  case winapi::ERROR_DISK_CHANGE_:
  case winapi::ERROR_GEN_FAILURE_:
  case winapi::ERROR_INVALID_TARGET_HANDLE_:
  case winapi::ERROR_IO_DEVICE_:
  case winapi::ERROR_NO_MORE_SEARCH_HANDLES_:
  case winapi::ERROR_OPEN_FAILED_:
  case winapi::ERROR_READ_FAULT_:
  case winapi::ERROR_SEEK_:
  case winapi::ERROR_WRITE_FAULT_:
  case winapi::ERROR_BEGINNING_OF_MEDIA_:
  case winapi::ERROR_BUS_RESET_:
  case winapi::ERROR_DEVICE_DOOR_OPEN_:
  case winapi::ERROR_DEVICE_REQUIRES_CLEANING_:
  case winapi::ERROR_DISK_CORRUPT_:
  case winapi::ERROR_EOM_OVERFLOW_:
  case winapi::ERROR_INVALID_BLOCK_LENGTH_:
  case winapi::ERROR_NO_DATA_DETECTED_:
  case winapi::ERROR_NO_SIGNAL_SENT_:
  case winapi::ERROR_SETMARK_DETECTED_:
  case winapi::ERROR_SIGNAL_REFUSED_:
  case winapi::ERROR_FILEMARK_DETECTED_:
    Error = __WASI_ERRNO_IO;
    break;
  case winapi::ERROR_BAD_UNIT_:
  case winapi::ERROR_BAD_DEVICE_:
  case winapi::ERROR_DEV_NOT_EXIST_:
  case winapi::ERROR_FILE_INVALID_:
  case winapi::ERROR_INVALID_DRIVE_:
  case winapi::ERROR_UNRECOGNIZED_VOLUME_:
    Error = __WASI_ERRNO_NODEV;
    break;
  case winapi::ERROR_BAD_DRIVER_LEVEL_:
  case winapi::ERROR_UNRECOGNIZED_MEDIA_:
    Error = __WASI_ERRNO_NXIO;
    break;
  case winapi::ERROR_BAD_EXE_FORMAT_:
  case winapi::ERROR_BAD_FORMAT_:
  case winapi::ERROR_EXE_MARKED_INVALID_:
  case winapi::ERROR_INVALID_EXE_SIGNATURE_:
    Error = __WASI_ERRNO_NOEXEC;
    break;
  case winapi::ERROR_BAD_USERNAME_:
  case winapi::ERROR_BAD_LENGTH_:
  case winapi::ERROR_ENVVAR_NOT_FOUND_:
  case winapi::ERROR_INVALID_DATA_:
  case winapi::ERROR_INVALID_FLAGS_:
  case winapi::ERROR_INVALID_NAME_:
  case winapi::ERROR_INVALID_OWNER_:
  case winapi::ERROR_INVALID_PARAMETER_:
  case winapi::ERROR_INVALID_PRIMARY_GROUP_:
  case winapi::ERROR_INVALID_SIGNAL_NUMBER_:
  case winapi::ERROR_MAPPED_ALIGNMENT_:
  case winapi::ERROR_NONE_MAPPED_:
  case winapi::ERROR_SYMLINK_NOT_SUPPORTED_:
    Error = __WASI_ERRNO_INVAL;
    break;
  case winapi::ERROR_BAD_PATHNAME_:
  case winapi::ERROR_FILE_NOT_FOUND_:
  case winapi::ERROR_PATH_NOT_FOUND_:
  case winapi::ERROR_SWAPERROR_:
  case winapi::ERROR_DIRECTORY_:
  case winapi::ERROR_INVALID_REPARSE_DATA_:
  case winapi::ERROR_MOD_NOT_FOUND_:
    Error = __WASI_ERRNO_NOENT;
    break;
  case winapi::ERROR_BROKEN_PIPE_:
  case winapi::ERROR_BAD_PIPE_:
  case winapi::ERROR_MORE_DATA_:
  case winapi::ERROR_NO_DATA_:
  case winapi::ERROR_PIPE_CONNECTED_:
  case winapi::ERROR_PIPE_LISTENING_:
  case winapi::ERROR_PIPE_NOT_CONNECTED:
    Error = __WASI_ERRNO_PIPE;
    break;
  case winapi::ERROR_BUFFER_OVERFLOW_:
  case winapi::ERROR_FILENAME_EXCED_RANGE_:
    Error = __WASI_ERRNO_NAMETOOLONG;
    break;
  case winapi::ERROR_CALL_NOT_IMPLEMENTED_:
  case winapi::ERROR_INVALID_FUNCTION_:
    Error = __WASI_ERRNO_NOSYS;
    break;
  case winapi::ERROR_DIR_NOT_EMPTY_:
    Error = __WASI_ERRNO_NOTEMPTY;
    break;
  case winapi::ERROR_DISK_FULL_:
  case winapi::ERROR_HANDLE_DISK_FULL_:
  case winapi::ERROR_EA_TABLE_FULL_:
  case winapi::ERROR_END_OF_MEDIA_:
    Error = __WASI_ERRNO_NOSPC;
    break;
  case winapi::ERROR_INSUFFICIENT_BUFFER_:
  case winapi::ERROR_NOT_ENOUGH_MEMORY_:
  case winapi::ERROR_OUTOFMEMORY_:
  case winapi::ERROR_STACK_OVERFLOW_:
    Error = __WASI_ERRNO_NOMEM;
    break;
  case winapi::ERROR_INVALID_ADDRESS_:
  case winapi::ERROR_INVALID_BLOCK_:
    Error = __WASI_ERRNO_FAULT;
    break;
  case winapi::ERROR_NOT_READY_:
  case winapi::ERROR_NO_PROC_SLOTS_:
  case winapi::ERROR_ADDRESS_ALREADY_ASSOCIATED_:
    Error = __WASI_ERRNO_ADDRINUSE;
    break;
  case winapi::ERROR_INVALID_PASSWORD_:
  case winapi::ERROR_PRIVILEGE_NOT_HELD_:
    Error = __WASI_ERRNO_PERM;
    break;
  case winapi::ERROR_IO_INCOMPLETE_:
  case winapi::ERROR_OPERATION_ABORTED_:
    Error = __WASI_ERRNO_INTR;
    break;
  case winapi::ERROR_META_EXPANSION_TOO_LONG_:
    Error = __WASI_ERRNO_2BIG;
    break;
  case winapi::ERROR_NEGATIVE_SEEK_:
  case winapi::ERROR_SEEK_ON_DEVICE_:
    Error = __WASI_ERRNO_SPIPE;
    break;
  case winapi::ERROR_NOT_SAME_DEVICE_:
    Error = __WASI_ERRNO_XDEV;
    break;
  case winapi::ERROR_SHARING_BUFFER_EXCEEDED_:
    Error = __WASI_ERRNO_NFILE;
    break;
  case winapi::ERROR_TOO_MANY_MODULES_:
  case winapi::ERROR_TOO_MANY_OPEN_FILES_:
    Error = __WASI_ERRNO_MFILE;
    break;
  case winapi::ERROR_WAIT_NO_CHILDREN_:
    Error = __WASI_ERRNO_CHILD;
    break;
  case winapi::ERROR_WRITE_PROTECT_:
    Error = __WASI_ERRNO_ROFS;
    break;
  case winapi::ERROR_CANT_RESOLVE_FILENAME_:
    Error = __WASI_ERRNO_LOOP;
    break;
  case winapi::ERROR_CONNECTION_ABORTED_:
    Error = __WASI_ERRNO_CONNABORTED;
    break;
  case winapi::ERROR_CONNECTION_REFUSED_:
    Error = __WASI_ERRNO_CONNREFUSED;
    break;
  case winapi::ERROR_HOST_UNREACHABLE_:
    Error = __WASI_ERRNO_HOSTUNREACH;
    break;
  case winapi::ERROR_INVALID_HANDLE_:
    Error = __WASI_ERRNO_BADF;
    break;
  case winapi::ERROR_NETNAME_DELETED_:
    Error = __WASI_ERRNO_CONNRESET;
    break;
  case winapi::ERROR_NETWORK_UNREACHABLE_:
    Error = __WASI_ERRNO_NETUNREACH;
    break;
  case winapi::ERROR_NOT_CONNECTED_:
    Error = __WASI_ERRNO_NOTCONN;
    break;
  case winapi::ERROR_NOT_SUPPORTED_:
    Error = __WASI_ERRNO_NOTSUP;
    break;
  case winapi::ERROR_SEM_TIMEOUT_:
    Error = __WASI_ERRNO_TIMEDOUT;
    break;
  case winapi::ERROR_TOO_MANY_LINKS_:
    Error = __WASI_ERRNO_MLINK;
    break;
  default:
    assumingUnreachable();
  }
  return Error;
}

constexpr winapi::DWORD_ attributeFlags(__wasi_oflags_t OpenFlags,
                                        __wasi_fdflags_t FdFlags) noexcept {
  winapi::DWORD_ Flags = winapi::FILE_ATTRIBUTE_NORMAL_;
  if ((FdFlags & __WASI_FDFLAGS_NONBLOCK) != 0) {
    Flags |= FILE_FLAG_OVERLAPPED;
  }

  // Source: https://devblogs.microsoft.com/oldnewthing/20210729-00/?p=105494
  if ((FdFlags & __WASI_FDFLAGS_SYNC) || (FdFlags & __WASI_FDFLAGS_RSYNC)) {
    // Linux does not implement O_RSYNC and glibc defines O_RSYNC as O_SYNC
    Flags |= winapi::FILE_FLAG_WRITE_THROUGH_ | winapi::FILE_FLAG_NO_BUFFERING_;
  }
  if (FdFlags & __WASI_FDFLAGS_DSYNC) {
    Flags |= winapi::FILE_FLAG_WRITE_THROUGH_;
  }
  if (OpenFlags & __WASI_OFLAGS_DIRECTORY) {
    Flags |= winapi::FILE_ATTRIBUTE_DIRECTORY_;
  }

  return Flags;
}

constexpr winapi::DWORD_ accessFlags(__wasi_fdflags_t FdFlags,
                                     uint8_t VFSFlags) noexcept {
  winapi::DWORD_ Flags = 0;

  if (VFSFlags & VFS::Read) {
    if (VFSFlags & VFS::Write) {
      Flags |= winapi::GENERIC_READ_ | GENERIC_WRITE;
    } else {
      Flags |= winapi::GENERIC_READ_;
    }
  } else if (VFSFlags & VFS::Write) {
    Flags |= GENERIC_WRITE;
  }

  if ((FdFlags & __WASI_FDFLAGS_APPEND) != 0) {
    Flags |= FILE_APPEND_DATA;
  }

  return Flags;
}

constexpr winapi::DWORD_ creationDisposition(__wasi_oflags_t OpenFlags) {
  winapi::DWORD_ Flags = winapi::OPEN_EXISTING_;
  if (OpenFlags & __WASI_OFLAGS_CREAT) {
    Flags = OPEN_ALWAYS;
  }
  if (OpenFlags & __WASI_OFLAGS_TRUNC) {
    Flags = TRUNCATE_EXISTING;
  }
  if (OpenFlags & __WASI_OFLAGS_EXCL) {
    Flags = CREATE_NEW;
  }
  return Flags;
}

inline constexpr __wasi_filetype_t
fromFileType(winapi::DWORD_ Attribute, winapi::DWORD_ FileType) noexcept {
  switch (Attribute) {
  case winapi::FILE_ATTRIBUTE_DIRECTORY_:
    return __WASI_FILETYPE_DIRECTORY;
  case winapi::FILE_ATTRIBUTE_NORMAL_:
    return __WASI_FILETYPE_REGULAR_FILE;
  case winapi::FILE_ATTRIBUTE_REPARSE_POINT_:
    return __WASI_FILETYPE_SYMBOLIC_LINK;
  }
  switch (FileType) {
  case FILE_TYPE_CHAR:
    return __WASI_FILETYPE_CHARACTER_DEVICE;
  }
  return __WASI_FILETYPE_UNKNOWN;
}

constexpr inline winapi::DWORD_ fromWhence(__wasi_whence_t Whence) {
  switch (Whence) {
  case __WASI_WHENCE_SET:
    return FILE_BEGIN;
  case __WASI_WHENCE_END:
    return FILE_END;
  case __WASI_WHENCE_CUR:
    return FILE_CURRENT;
  }
}

} // namespace

void HandleHolder::reset() noexcept {
  if (likely(ok())) {
    if (likely(!isSocket(&Handle))) {
      winapi::CloseHandle(Handle);
    } else {
      ::closesocket(reinterpret_cast<winapi::SOCKET_>(Handle));
    }
    Handle = nullptr;
  }
}

INode INode::stdIn() noexcept {
  return INode(winapi::GetStdHandle(winapi::STD_INPUT_HANDLE_));
}

INode INode::stdOut() noexcept {
  return INode(winapi::GetStdHandle(winapi::STD_OUTPUT_HANDLE_));
}

INode INode::stdErr() noexcept {
  return INode(winapi::GetStdHandle(winapi::STD_ERROR_HANDLE_));
}

WasiExpect<INode> INode::open(std::string Path, __wasi_oflags_t OpenFlags,
                              __wasi_fdflags_t FdFlags,
                              uint8_t VFSFlags) noexcept {

  winapi::DWORD_ AttributeFlags = attributeFlags(OpenFlags, FdFlags);
  winapi::DWORD_ AccessFlags = accessFlags(FdFlags, VFSFlags);
  winapi::DWORD_ CreationDisposition = creationDisposition(OpenFlags);

  winapi::HANDLE_ FileHandle = CreateFileA(
      Path.c_str(), AccessFlags,
      FILE_SHARE_DELETE | winapi::FILE_SHARE_READ_ | winapi::FILE_SHARE_WRITE_,
      nullptr, CreationDisposition, AttributeFlags, nullptr);

  if (unlikely(FileHandle == winapi::INVALID_HANDLE_VALUE_)) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  } else {
    INode New(FileHandle);
    return New;
  }
}

WasiExpect<void> INode::fdAdvise(__wasi_filesize_t, __wasi_filesize_t,
                                 __wasi_advice_t) const noexcept {
  // FIXME: No equivalent function was found for this purpose in the Win32 API
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<void> INode::fdAllocate(__wasi_filesize_t Offset,
                                   __wasi_filesize_t Len) const noexcept {

  winapi::LARGE_INTEGER_ FileSize;
  if (unlikely(GetFileSizeEx(Handle, &FileSize) == 0)) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }

  // We need to check if the request size (Offset + Len) is lesser than the
  // current the size and if it is lesser then we don't truncate the file

  if (static_cast<int64_t>((Offset + Len) & 0x7FFFFFFFFFFFFFFF) >
      FileSize.QuadPart) {

    FILE_STANDARD_INFO StandardInfo;
    FILE_ALLOCATION_INFO AllocationInfo;

    if (unlikely(GetFileInformationByHandleEx(Handle, FileStandardInfo,
                                              &StandardInfo,
                                              sizeof(StandardInfo))) == 0) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }

    // TODO: Since the unsigned integer is cast into a signed integer the range
    // of the values will be twice as small as the parameter - for very large
    // unsigned integers the cast to a signed integer may overflow the range of
    // the signed integer. Is this fine?
    AllocationInfo.AllocationSize.QuadPart =
        static_cast<int64_t>((Offset + Len) & 0x7FFFFFFFFFFFFFFF);

    if (SetFileInformationByHandle(Handle, FileAllocationInfo, &AllocationInfo,
                                   sizeof(AllocationInfo)) == 0) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }
  }
  return {};
}

WasiExpect<void> INode::fdDatasync() const noexcept {
  if (unlikely(FlushFileBuffers(Handle) == 0)) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }
  return {};
}

WasiExpect<void> INode::fdFdstatGet(__wasi_fdstat_t &FdStat) const noexcept {
  // TODO: Complete this partially implemented function after finding equivalent
  // flags/attributes for fs_filetype, fs_flags and fs_rights_base and
  // fs_rights_inheriting. The linux implementation has not implemented this
  // function completely.

  // Update the file information
  FileInfo.emplace();
  if (unlikely(GetFileInformationByHandle(Handle, &(*FileInfo)) == 0)) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }

  FdStat.fs_filetype =
      fromFileType((*FileInfo).dwFileAttributes, GetFileType(Handle));

  // We don't have a function to retrieve the equivalent Fd Flags used to
  // open the file in the win32 API hence it will be better to retrieve the
  // saved flags used during the file open
  // FIXME: Find a better way
  FdStat.fs_flags = (*SavedFdFlags);

  return {};
}

WasiExpect<void>
INode::fdFdstatSetFlags(__wasi_fdflags_t FdFlags) const noexcept {
  // The __WASI_FDFLAGS_APPEND flag is ignored as it cannot be changed for an
  // open file

  winapi::DWORD_ Attributes = winapi::FILE_ATTRIBUTE_NORMAL_;

  winapi::FILE_BASIC_INFO_ BasicInfo;

  // Source: https://devblogs.microsoft.com/oldnewthing/20210729-00/?p=105494
  if ((FdFlags & __WASI_FDFLAGS_SYNC) || (FdFlags & __WASI_FDFLAGS_RSYNC)) {
    // Linux does not implement RSYNC and glibc defines O_RSYNC as O_SYNC
    Attributes |=
        winapi::FILE_FLAG_WRITE_THROUGH_ | winapi::FILE_FLAG_NO_BUFFERING_;
  }
  if (FdFlags & __WASI_FDFLAGS_DSYNC) {
    Attributes |= winapi::FILE_FLAG_NO_BUFFERING_;
  }
  if (FdFlags & __WASI_FDFLAGS_NONBLOCK) {
    Attributes |= FILE_FLAG_OVERLAPPED;
  }

  if (unlikely(GetFileInformationByHandleEx(Handle, FileBasicInfo, &BasicInfo,
                                            sizeof(BasicInfo))) == 0) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }

  // Update the attributes
  BasicInfo.FileAttributes = Attributes;

  if (unlikely(SetFileInformationByHandle(Handle, FileBasicInfo, &BasicInfo,
                                          sizeof(BasicInfo))) == 0) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }

  return {};
}

WasiExpect<void>
INode::fdFilestatGet(__wasi_filestat_t &FileStat) const noexcept {
  // TODO: Complete this partially implemented function after finding equivalent
  // flags/attributes for __wasi_filetype_t.

  // Update the File information
  FileInfo.emplace();
  if (unlikely(GetFileInformationByHandle(Handle, &*FileInfo) == 0)) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }

  FileStat.filetype =
      fromFileType((*FileInfo).dwFileAttributes, GetFileType(Handle));

  // Windows does not have an equivalent for the INode number.
  // A possible equivalent could be the File Index
  // Source:
  // https://stackoverflow.com/questions/28252850/open-windows-file-using-unique-id/28253123#28253123
  // this
  // https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-openfilebyid?redirectedfrom=MSDN
  // and this
  // https://docs.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info
  FileStat.ino = 0;
  // TODO: Find an equivalent for device ID in windows
  FileStat.dev = 0;
  FileStat.nlink = (*FileInfo).nNumberOfLinks;
  FileStat.size = static_cast<uint64_t>((*FileInfo).nFileSizeLow) +
                  (static_cast<uint64_t>((*FileInfo).nFileSizeHigh) << 32);
  FileStat.atim =
      (static_cast<uint64_t>((*FileInfo).ftLastAccessTime.dwHighDateTime)
       << 32) +
      (static_cast<uint64_t>((*FileInfo).ftLastAccessTime.dwLowDateTime)) -
      TICKS_TO_UNIX_EPOCH;
  FileStat.mtim =
      (static_cast<uint64_t>((*FileInfo).ftLastWriteTime.dwHighDateTime)
       << 32) +
      (static_cast<uint64_t>((*FileInfo).ftLastWriteTime.dwLowDateTime)) -
      TICKS_TO_UNIX_EPOCH;
  FileStat.ctim =
      (static_cast<uint64_t>((*FileInfo).ftCreationTime.dwHighDateTime) << 32) +
      (static_cast<uint64_t>((*FileInfo).ftCreationTime.dwLowDateTime)) -
      TICKS_TO_UNIX_EPOCH;

  return {};
}

WasiExpect<void>
INode::fdFilestatSetSize(__wasi_filesize_t Size) const noexcept {

  FILE_STANDARD_INFO StandardInfo;
  FILE_ALLOCATION_INFO AllocationInfo;

  if (unlikely(GetFileInformationByHandleEx(Handle, FileStandardInfo,
                                            &StandardInfo,
                                            sizeof(StandardInfo))) == 0) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }

  uint64_t PreviousSize =
      (static_cast<uint64_t>(StandardInfo.AllocationSize.HighPart) << 32) +
      static_cast<uint64_t>(StandardInfo.AllocationSize.LowPart);

  // Update the size attribute
  AllocationInfo.AllocationSize = toLargeIntegerFromUnsigned(Size);

  if (SetFileInformationByHandle(Handle, FileAllocationInfo, &AllocationInfo,
                                 sizeof(AllocationInfo)) == 0) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }

  if (Size > PreviousSize) {
    OVERLAPPED FileOffsetProvider;
    FileOffsetProvider.Offset =
        static_cast<winapi::DWORD_>(StandardInfo.AllocationSize.LowPart);
    FileOffsetProvider.OffsetHigh =
        static_cast<winapi::DWORD_>(StandardInfo.AllocationSize.HighPart);

    // Write null byte by byte
    uint64_t Count = static_cast<uint64_t>(Size - PreviousSize);
    while (Count > 0) {
      winapi::DWORD_ BytesWritten;
      winapi::BOOL_ WriteResult =
          WriteFile(Handle, "\0", 1, nullptr, &FileOffsetProvider);

      if (winapi::GetLastError() == ERROR_IO_PENDING) {
        // Wait for the Write to complete
        if (unlikely(GetOverlappedResult(Handle, &FileOffsetProvider,
                                         &BytesWritten, TRUE)) == 0) {
          return WasiUnexpect(fromWinError(winapi::GetLastError()));
        }
      } else if (unlikely(WriteResult == 0)) {
        return WasiUnexpect(fromWinError(winapi::GetLastError()));
      }
      Count++;
    }

    // Restore pointer
    winapi::LARGE_INTEGER_ FileOffset;
    FileOffset.QuadPart = static_cast<int64_t>(PreviousSize - Size);
    if (unlikely(SetFilePointerEx(Handle, FileOffset, nullptr, FILE_CURRENT) ==
                 0)) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }
  }

  return {};
}

WasiExpect<void>
INode::fdFilestatSetTimes(__wasi_timestamp_t ATim, __wasi_timestamp_t MTim,
                          __wasi_fstflags_t FstFlags) const noexcept {

  // Let FileTime be initialized to zero if the times need not be changed
  FILETIME AFileTime = {0, 0};
  FILETIME MFileTime = {0, 0};

  // For setting access time
  if (FstFlags & __WASI_FSTFLAGS_ATIM) {
    uint64_t Aticks = ATim / NANOSECONDS_PER_TICK + TICKS_TO_UNIX_EPOCH;
    AFileTime.dwLowDateTime = static_cast<winapi::DWORD_>(Aticks & 0xFFFFFFFF);
    AFileTime.dwHighDateTime =
        static_cast<winapi::DWORD_>((Aticks & 0xFFFFFFFF00000000) >> 32);
  } else if (FstFlags & __WASI_FSTFLAGS_ATIM_NOW) {
    GetSystemTimeAsFileTime(&AFileTime);
  }

  // For setting modification time
  if (FstFlags & __WASI_FSTFLAGS_MTIM) {
    uint64_t Mticks = MTim / NANOSECONDS_PER_TICK + TICKS_TO_UNIX_EPOCH;
    MFileTime.dwLowDateTime = static_cast<winapi::DWORD_>(Mticks & 0xFFFFFFFF);
    MFileTime.dwHighDateTime =
        static_cast<winapi::DWORD_>((Mticks & 0xFFFFFFFF00000000) >> 32);
  } else if (FstFlags & __WASI_FSTFLAGS_MTIM_NOW) {
    GetSystemTimeAsFileTime(&MFileTime);
  }

  if (unlikely(SetFileTime(Handle, nullptr, &AFileTime, &MFileTime)) == 0) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }

  return {};
}

WasiExpect<void> INode::fdPread(Span<Span<uint8_t>> IOVs,
                                __wasi_filesize_t Offset,
                                __wasi_size_t &NRead) const noexcept {
  NRead = 0;
  uint64_t LocalOffset = Offset;

  for (auto IOV : IOVs) {
    winapi::DWORD_ NumberOfBytesRead = 0;
    OVERLAPPED Result;

    Result.Offset = static_cast<uint32_t>(LocalOffset);
    Result.OffsetHigh = static_cast<uint32_t>(LocalOffset >> 32);

    // Casting the 64 bit `IOV.size()` integer may overflow the range
    // of the 32 bit integer it is cast into
    winapi::BOOL_ ReadResult =
        ReadFile(Handle, IOV.data(), static_cast<uint32_t>(IOV.size()),
                 &NumberOfBytesRead, &Result);
    if (winapi::GetLastError() == ERROR_IO_PENDING) {
      // Wait for the Write to complete
      if (unlikely(GetOverlappedResult(Handle, &Result, &NumberOfBytesRead,
                                       TRUE)) == 0) {
        return WasiUnexpect(fromWinError(winapi::GetLastError()));
      }
    } else if (unlikely(ReadResult == 0)) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }
    LocalOffset += NumberOfBytesRead;
    NRead += NumberOfBytesRead;
  }

  return {};
}

WasiExpect<void> INode::fdPwrite(Span<Span<const uint8_t>> IOVs,
                                 __wasi_filesize_t Offset,
                                 __wasi_size_t &NWritten) const noexcept {
  NWritten = 0;
  uint64_t LocalOffset = Offset;

  for (auto IOV : IOVs) {
    winapi::DWORD_ NumberOfBytesWritten = 0;
    OVERLAPPED Result;

    Result.Offset = static_cast<uint32_t>(LocalOffset);
    Result.OffsetHigh = static_cast<uint32_t>(LocalOffset >> 32);

    // There maybe issues due to casting IOV.size() to unit32_t
    winapi::BOOL_ WriteResult = WriteFile(
        Handle, static_cast<const uint8_t *>(IOV.data()),
        static_cast<uint32_t>(IOV.size()), &NumberOfBytesWritten, &Result);

    if (winapi::GetLastError() == ERROR_IO_PENDING) {
      // Wait for the Write to complete
      if (unlikely(GetOverlappedResult(Handle, &Result, &NumberOfBytesWritten,
                                       TRUE)) == 0) {
        return WasiUnexpect(fromWinError(winapi::GetLastError()));
      }
    } else if (unlikely(WriteResult == 0)) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }

    LocalOffset += NumberOfBytesWritten;
    NWritten += NumberOfBytesWritten;
  }

  return {};
}

WasiExpect<void> INode::fdRead(Span<Span<uint8_t>> IOVs,
                               __wasi_size_t &NRead) const noexcept {
  NRead = 0;
  for (auto IOV : IOVs) {
    winapi::DWORD_ NumberOfBytesRead = 0;
    if (!winapi::ReadFile(Handle, IOV.data(), static_cast<uint32_t>(IOV.size()),
                          &NumberOfBytesRead, nullptr)) {
      return WasiUnexpect(fromLastError(winapi::GetLastError()));
    }
    NRead += NumberOfBytesRead;
  }
  return {};
}

WasiExpect<void> INode::fdReaddir(Span<uint8_t> Buffer,
                                  __wasi_dircookie_t Cookie,
                                  __wasi_size_t &Size) noexcept {

  WIN32_FIND_DATAW FindData;
  uint64_t Seek = 0;
  wchar_t HandleFullPathW[MAX_PATH];
  wchar_t FullPathW[MAX_PATH];

  std::vector<uint8_t, boost::alignment::aligned_allocator<
                           uint8_t, alignof(__wasi_dirent_t)>>
      LocalBuffer;

  // First get the path of the handle
  if (unlikely(winapi::GetFinalPathNameByHandleW(
          Handle, HandleFullPathW, MAX_PATH, winapi::FILE_NAME_NORMALIZED_)) ==
      0) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }

  // Check if the path is a directory or not
  if (!winapi::PathIsDirectoryW(HandleFullPathW)) {
    return WasiUnexpect(__WASI_ERRNO_NOTDIR);
  }

  // WildCard to match every file/directory present in the directory
  const wchar_t WildCard[]{L"\\*"};
  HRESULT CombineResult =
      PathCchCombine(FullPathW, MAX_PATH, HandleFullPathW, WildCard);

  switch (CombineResult) {
  case S_OK:
    break;
  case E_INVALIDARG:
    return WasiUnexpect(__WASI_ERRNO_INVAL);
  case E_OUTOFMEMORY:
    return WasiUnexpect(__WASI_ERRNO_OVERFLOW);
  default:
    return WasiUnexpect(__WASI_ERRNO_NAMETOOLONG);
  }

  // Begin the search for files
  winapi::HANDLE_ LocalFindHandle = FindFirstFileW(FullPathW, &FindData);
  if (unlikely(LocalFindHandle == winapi::INVALID_HANDLE_VALUE_)) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }

  // seekdir() emulation - go to the Cookie'th file/directory
  while (Seek < Cookie) {
    if (unlikely(FindNextFileW(LocalFindHandle, &FindData) == 0)) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }
    Seek++;
  }

  uint32_t NumberOfBytesRead = 0;
  winapi::BOOL_ FindNextResult = 0;

  do {
    if (!LocalBuffer.empty()) {
      const auto NewDataSize =
          std::min<uint32_t>(static_cast<uint32_t>(Buffer.size()),
                             static_cast<uint32_t>(LocalBuffer.size()));
      std::copy(LocalBuffer.begin(), LocalBuffer.begin() + NewDataSize,
                Buffer.begin());
      Buffer = Buffer.subspan(NewDataSize);
      Size += NewDataSize;
      LocalBuffer.erase(LocalBuffer.begin(), LocalBuffer.begin() + NewDataSize);
      if (unlikely(Buffer.empty())) {
        break;
      }
    }

    std::wstring_view FileName = FindData.cFileName;

    __wasi_dirent_t DirentObject = {.d_next = 0,
                                    .d_ino = 0,
                                    .d_namlen = 0,
                                    .d_type = __WASI_FILETYPE_UNKNOWN};

    LocalBuffer.resize(sizeof(__wasi_dirent_t) + (FileName.size() * 2));

    NumberOfBytesRead += sizeof(__wasi_dirent_t) + (FileName.size() * 2);

    __wasi_dirent_t *const Dirent =
        reinterpret_cast<__wasi_dirent_t *>(LocalBuffer.data());

    // The opening and closing of the handles may have a negative
    // impact on the performance

    winapi::HANDLE_ LocalFileHandle;

    CombineResult = PathCchCombine(FullPathW, MAX_PATH, HandleFullPathW,
                                   FindData.cFileName);

    switch (CombineResult) {
    case S_OK:
      break;
    case E_INVALIDARG:
      return WasiUnexpect(__WASI_ERRNO_INVAL);
    case E_OUTOFMEMORY:
      return WasiUnexpect(__WASI_ERRNO_OVERFLOW);
    default:
      return WasiUnexpect(__WASI_ERRNO_NAMETOOLONG);
    }

    LocalFileHandle =
        CreateFileW(FullPathW, winapi::GENERIC_READ_, winapi::FILE_SHARE_READ_,
                    nullptr, winapi::OPEN_EXISTING_, 0, nullptr);

    if (LocalFileHandle == winapi::INVALID_HANDLE_VALUE_) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }

    winapi::DWORD_ FileType = GetFileType(LocalFileHandle);

    if (winapi::GetLastError() != NO_ERROR) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }

    CloseHandle(LocalFileHandle);

    DirentObject.d_type = fromFileType(FindData.dwFileAttributes, FileType);

    // Since windows does not have any equivalent to the INode number,
    // we set this to 0
    // Possible equivalent could be the File Index
    // Source:
    // https://stackoverflow.com/questions/28252850/open-windows-file-using-unique-id/28253123#28253123
    // this
    // https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-openfilebyid?redirectedfrom=MSDN
    // and this
    // https://docs.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info
    Dirent->d_ino = 0;

    // The filed size may not be sufficient to hold the complete length
    Dirent->d_namlen = static_cast<uint32_t>(sizeof(FindData.cFileName));
    Dirent->d_next = sizeof(__wasi_dirent_t) + Dirent->d_namlen;
    Dirent->d_ino = 0;

    std::copy(FileName.cbegin(), FileName.cend(),
              LocalBuffer.begin() + sizeof(__wasi_dirent_t));
    // Check if there no more files left or if an error has been encountered
    FindNextResult = FindNextFileW(LocalFindHandle, &FindData);
  } while (FindNextResult != ERROR_NO_MORE_FILES || FindNextResult != 0);

  FindClose(LocalFindHandle);

  if (winapi::GetLastError() != ERROR_NO_MORE_FILES) {
    // The FindNextFileW() function has failed
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }

  Size = NumberOfBytesRead;

  return {};
}

WasiExpect<void> INode::fdSeek(__wasi_filedelta_t Offset,
                               __wasi_whence_t Whence,
                               __wasi_filesize_t &Size) const noexcept {

  winapi::DWORD_ MoveMethod = fromWhence(Whence);
  winapi::LARGE_INTEGER_ DistanceToMove = toLargeIntegerFromSigned(Offset);
  winapi::LARGE_INTEGER_ Pointer;
  if (unlikely(SetFilePointerEx(Handle, DistanceToMove, &Pointer,
                                MoveMethod)) == 0) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  } else {
    Size = static_cast<uint64_t>(Pointer.QuadPart);
  }
  return {};
}

WasiExpect<void> INode::fdSync() const noexcept {
  if (unlikely(FlushFileBuffers(Handle) == 0)) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }
  return {};
}

WasiExpect<void> INode::fdTell(__wasi_filesize_t &Size) const noexcept {
  winapi::LARGE_INTEGER_ Pointer;

  if (unlikely(SetFilePointerEx(Handle, ZERO_OFFSET, &Pointer, FILE_CURRENT) ==
               0)) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  } else {
    Size = static_cast<uint64_t>(Pointer.QuadPart);
  }
  return {};
}

WasiExpect<void> INode::fdWrite(Span<Span<const uint8_t>> IOVs,
                                __wasi_size_t &NWritten) const noexcept {
  NWritten = 0;
  for (auto IOV : IOVs) {
    winapi::DWORD_ NumberOfBytesWritten = 0;
    if (!winapi::WriteFile(Handle, IOV.data(),
                           static_cast<uint32_t>(IOV.size()),
                           &NumberOfBytesWritten, nullptr)) {
      return WasiUnexpect(fromLastError(winapi::GetLastError()));
    }
    NWritten += NumberOfBytesWritten;
  }
  return {};
}

WasiExpect<uint64_t> INode::getNativeHandler() const noexcept {
  return reinterpret_cast<uint64_t>(Handle);
}

WasiExpect<void> INode::pathCreateDirectory(std::string Path) const noexcept {
  wchar_t FullPathW[MAX_PATH];

  if (winapi::PathIsRelativeA(Path.c_str())) {
    wchar_t HandleFullPathW[MAX_PATH];

    // First get the paths of the handles
    if (unlikely(winapi::GetFinalPathNameByHandleW(
            Handle, HandleFullPathW, MAX_PATH,
            winapi::FILE_NAME_NORMALIZED_)) == 0) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }

    if (!winapi::PathIsDirectoryW(HandleFullPathW)) {
      return WasiUnexpect(__WASI_ERRNO_NOTDIR);
    }

    wchar_t OldPathW[MAX_PATH];

    // Convert the path from char_t to wchar_t
    mbstowcs(OldPathW, Path.c_str(), MAX_PATH);

    // Append the paths together
    HRESULT CombineResult =
        PathCchCombine(FullPathW, MAX_PATH, HandleFullPathW, OldPathW);

    switch (CombineResult) {
    case S_OK:
      break;
    case E_INVALIDARG:
      return WasiUnexpect(__WASI_ERRNO_INVAL);
    case E_OUTOFMEMORY:
      return WasiUnexpect(__WASI_ERRNO_OVERFLOW);
    default:
      return WasiUnexpect(__WASI_ERRNO_NAMETOOLONG);
    }
  }

  else {
    mbstowcs(FullPathW, Path.c_str(), MAX_PATH);
  }

  if (unlikely(CreateDirectoryW(FullPathW, nullptr) == 0)) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }
  return {};
}

WasiExpect<void>
INode::pathFilestatGet(std::string Path,
                       __wasi_filestat_t &FileStat) const noexcept {
  // Since there is no way to get the stat of a file without a HANDLE to it,
  // we open a handle to the requested file, call GetFileInformationByHandle
  // on it and then update our WASI FileStat

  // Since the required function is similar to `stat` we assume Path is an
  // absolute path

  winapi::HANDLE_ LocalFileHandle;
  if (LocalFileHandle = CreateFileA(Path.c_str(), winapi::GENERIC_READ_,
                                    winapi::FILE_SHARE_READ_, nullptr,
                                    winapi::OPEN_EXISTING_, 0, nullptr);
      likely(LocalFileHandle != winapi::INVALID_HANDLE_VALUE_)) {
    BY_HANDLE_FILE_INFORMATION LocalFileInfo;
    if (likely(winapi::GetFileInformationByHandle(LocalFileHandle,
                                                  &LocalFileInfo) != 0)) {
      FileStat.filetype = fromFileType(LocalFileInfo.dwFileAttributes,
                                       GetFileType(LocalFileHandle));

      // Windows does not have an equivalent for the INode number
      // Possible equivalent could be the File Index
      // Source:
      // https://stackoverflow.com/questions/28252850/open-windows-file-using-unique-id/28253123#28253123
      // this
      // https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-openfilebyid?redirectedfrom=MSDN
      // and this
      // https://docs.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info
      FileStat.ino = 0;
      // TODO: Find an equivalent for device ID in windows
      FileStat.dev = 0;
      FileStat.nlink = (LocalFileInfo).nNumberOfLinks;
      FileStat.size =
          static_cast<uint64_t>((LocalFileInfo).nFileSizeLow) +
          (static_cast<uint64_t>((LocalFileInfo).nFileSizeHigh) << 32);
      FileStat.atim = (static_cast<uint64_t>(
                           (LocalFileInfo).ftLastAccessTime.dwHighDateTime)
                       << 32) +
                      (static_cast<uint64_t>(
                          (LocalFileInfo).ftLastAccessTime.dwLowDateTime)) -
                      TICKS_TO_UNIX_EPOCH;
      FileStat.mtim =
          (static_cast<uint64_t>((LocalFileInfo).ftLastWriteTime.dwHighDateTime)
           << 32) +
          (static_cast<uint64_t>(
              (LocalFileInfo).ftLastWriteTime.dwLowDateTime)) -
          TICKS_TO_UNIX_EPOCH;
      FileStat.ctim =
          (static_cast<uint64_t>((LocalFileInfo).ftCreationTime.dwHighDateTime)
           << 32) +
          (static_cast<uint64_t>(
              (LocalFileInfo).ftCreationTime.dwLowDateTime)) -
          TICKS_TO_UNIX_EPOCH;

      return {};
    }
    CloseHandle(LocalFileHandle);
  }

  return WasiUnexpect(fromWinError(winapi::GetLastError()));
}

WasiExpect<void>
INode::pathFilestatSetTimes(std::string Path, __wasi_timestamp_t ATim,
                            __wasi_timestamp_t MTim,
                            __wasi_fstflags_t FstFlags) const noexcept {

  wchar_t FullPathW[MAX_PATH];

  if (winapi::PathIsRelativeA(Path.c_str())) {
    wchar_t HandleFullPathW[MAX_PATH];

    // First get the path of the handle
    if (unlikely(winapi::GetFinalPathNameByHandleW(
            Handle, HandleFullPathW, MAX_PATH,
            winapi::FILE_NAME_NORMALIZED_)) == 0) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }

    if (!winapi::PathIsDirectoryW(HandleFullPathW)) {
      return WasiUnexpect(__WASI_ERRNO_NOTDIR);
    }

    wchar_t OldPathW[MAX_PATH];

    // Convert the path from char_t to wchar_t
    mbstowcs(OldPathW, Path.c_str(), MAX_PATH);

    // Append the paths together
    HRESULT CombineResult =
        PathCchCombine(FullPathW, MAX_PATH, HandleFullPathW, OldPathW);

    switch (CombineResult) {
    case S_OK:
      break;
    case E_INVALIDARG:
      return WasiUnexpect(__WASI_ERRNO_INVAL);
    case E_OUTOFMEMORY:
      return WasiUnexpect(__WASI_ERRNO_OVERFLOW);
    default:
      return WasiUnexpect(__WASI_ERRNO_NAMETOOLONG);
    }
  } else {
    mbstowcs(FullPathW, Path.c_str(), MAX_PATH);
  }

  winapi::HANDLE_ LocalFileHandle;
  if (LocalFileHandle = CreateFileW(FullPathW, winapi::GENERIC_READ_,
                                    winapi::FILE_SHARE_READ_, nullptr,
                                    winapi::OPEN_EXISTING_, 0, nullptr);
      likely(LocalFileHandle != winapi::INVALID_HANDLE_VALUE_)) {
    // Let FileTime be initialized to zero if the times need not be changed
    FILETIME AFileTime = {0, 0};
    FILETIME MFileTime = {0, 0};

    // For setting access time
    if (FstFlags & __WASI_FSTFLAGS_ATIM) {
      uint64_t Aticks = ATim / NANOSECONDS_PER_TICK + TICKS_TO_UNIX_EPOCH;
      AFileTime.dwLowDateTime =
          static_cast<winapi::DWORD_>(Aticks % 0x100000000ULL);
      AFileTime.dwHighDateTime =
          static_cast<winapi::DWORD_>(Aticks / 0x100000000ULL);
    } else if (FstFlags & __WASI_FSTFLAGS_ATIM_NOW) {
      GetSystemTimeAsFileTime(&AFileTime);
    }

    // For setting modification time
    if (FstFlags & __WASI_FSTFLAGS_MTIM) {
      uint64_t Mticks = MTim / NANOSECONDS_PER_TICK + TICKS_TO_UNIX_EPOCH;
      MFileTime.dwLowDateTime =
          static_cast<winapi::DWORD_>(Mticks % 0x100000000ULL);
      MFileTime.dwHighDateTime =
          static_cast<winapi::DWORD_>(Mticks / 0x100000000ULL);
    } else if (FstFlags & __WASI_FSTFLAGS_MTIM_NOW) {
      GetSystemTimeAsFileTime(&MFileTime);
    }

    if (unlikely(SetFileTime(LocalFileHandle, nullptr, &AFileTime,
                             &MFileTime) == 0)) {
      CloseHandle(LocalFileHandle);
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }
    CloseHandle(LocalFileHandle);
    return {};
  }
  return WasiUnexpect(fromWinError(winapi::GetLastError()));
}

WasiExpect<void> INode::pathLink(const INode &Old, std::string OldPath,
                                 const INode &New,
                                 std::string NewPath) noexcept {

  wchar_t OldFullPathW[MAX_PATH];
  wchar_t NewFullPathW[MAX_PATH];

  if (winapi::PathIsRelativeA(OldPath.c_str())) {
    wchar_t HandleFullPathW[MAX_PATH];

    // First get the paths of the handle
    if (unlikely(winapi::GetFinalPathNameByHandleW(
            Old.Handle, HandleFullPathW, MAX_PATH,
            winapi::FILE_NAME_NORMALIZED)) == 0) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }

    if (!winapi::PathIsDirectoryW(HandleFullPathW)) {
      return WasiUnexpect(__WASI_ERRNO_NOTDIR);
    }

    wchar_t OldPathW[MAX_PATH];

    // Convert the path from char_t to wchar_t
    mbstowcs(OldPathW, OldPath.c_str(), MAX_PATH);

    // Append the paths together
    HRESULT CombineResult =
        PathCchCombine(OldFullPathW, MAX_PATH, HandleFullPathW, OldPathW);

    switch (CombineResult) {
    case S_OK:
      break;
    case E_INVALIDARG:
      return WasiUnexpect(__WASI_ERRNO_INVAL);
    case E_OUTOFMEMORY:
      return WasiUnexpect(__WASI_ERRNO_OVERFLOW);
    default:
      return WasiUnexpect(__WASI_ERRNO_NAMETOOLONG);
    }

  } else {
    mbstowcs(OldFullPathW, OldPath.c_str(), MAX_PATH);
  }

  if (winapi::PathIsRelativeA(NewPath.c_str())) {
    wchar_t HandleFullPathW[MAX_PATH];

    // First get the paths of the handle
    if (unlikely(winapi::GetFinalPathNameByHandleW(
            New.Handle, HandleFullPathW, MAX_PATH,
            winapi::FILE_NAME_NORMALIZED)) == 0) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }

    if (!winapi::PathIsDirectoryW(HandleFullPathW)) {
      return WasiUnexpect(__WASI_ERRNO_NOTDIR);
    }

    wchar_t NewPathW[MAX_PATH];

    // Convert the path from char_t to wchar_t
    mbstowcs(NewPathW, OldPath.c_str(), MAX_PATH);

    // Append the paths together
    HRESULT CombineResult =
        PathCchCombine(NewFullPathW, MAX_PATH, HandleFullPathW, NewPathW);
    switch (CombineResult) {
    case S_OK:
      break;
    case E_INVALIDARG:
      return WasiUnexpect(__WASI_ERRNO_INVAL);
    case E_OUTOFMEMORY:
      return WasiUnexpect(__WASI_ERRNO_OVERFLOW);
    default:
      return WasiUnexpect(__WASI_ERRNO_NAMETOOLONG);
    }

  } else {
    mbstowcs(NewFullPathW, NewPath.c_str(), MAX_PATH);
  }

  // Create the hard link from the paths
  if (unlikely(CreateHardLinkW(NewFullPathW, OldFullPathW, nullptr) == 0)) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }

  return {};
}

WasiExpect<INode> INode::pathOpen(std::string Path, __wasi_oflags_t OpenFlags,
                                  __wasi_fdflags_t FdFlags,
                                  uint8_t VFSFlags) const noexcept {
  wchar_t FullPathW[MAX_PATH];

  if (winapi::PathIsRelativeA(Path.c_str())) {
    wchar_t HandleFullPathW[MAX_PATH];

    // First get the paths of the handles
    if (unlikely(winapi::GetFinalPathNameByHandleW(
            Handle, HandleFullPathW, MAX_PATH,
            winapi::FILE_NAME_NORMALIZED_)) == 0) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }

    if (!winapi::PathIsDirectoryW(HandleFullPathW)) {
      return WasiUnexpect(__WASI_ERRNO_NOTDIR);
    }

    wchar_t PathW[MAX_PATH];

    // Convert the path from char_t to wchar_t
    mbstowcs(PathW, Path.c_str(), MAX_PATH);

    // Append the paths together
    HRESULT CombineResult =
        PathCchCombine(FullPathW, MAX_PATH, HandleFullPathW, PathW);

    switch (CombineResult) {
    case S_OK:
      break;
    case E_INVALIDARG:
      return WasiUnexpect(__WASI_ERRNO_INVAL);
    case E_OUTOFMEMORY:
      return WasiUnexpect(__WASI_ERRNO_OVERFLOW);
    default:
      return WasiUnexpect(__WASI_ERRNO_NAMETOOLONG);
    }

  } else {
    mbstowcs(FullPathW, Path.c_str(), MAX_PATH);
  }

  winapi::DWORD_ AttributeFlags = attributeFlags(OpenFlags, FdFlags);
  winapi::DWORD_ AccessFlags = accessFlags(FdFlags, VFSFlags);
  winapi::DWORD_ CreationDisposition = creationDisposition(OpenFlags);

  winapi::HANDLE_ FileHandle = CreateFileW(
      FullPathW, AccessFlags,
      FILE_SHARE_DELETE | winapi::FILE_SHARE_READ_ | winapi::FILE_SHARE_WRITE_,
      nullptr, CreationDisposition, AttributeFlags, nullptr);
  if (unlikely(FileHandle == winapi::INVALID_HANDLE_VALUE_)) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  } else {
    INode New(FileHandle);
    return New;
  }
}

WasiExpect<void> INode::pathReadlink(std::string Path, Span<char> Buffer,
                                     __wasi_size_t &NRead) const noexcept {

  wchar_t FullPathW[MAX_PATH];

  if (PathIsRelativeA(Path.c_str())) {
    wchar_t HandleFullPathW[MAX_PATH];
    // First get the paths of the handles
    if (unlikely(winapi::GetFinalPathNameByHandleW(
            Handle, HandleFullPathW, MAX_PATH,
            winapi::FILE_NAME_NORMALIZED_)) == 0) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }

    if (!PathIsDirectoryW(HandleFullPathW)) {
      return WasiUnexpect(__WASI_ERRNO_NOTDIR);
    }

    wchar_t PathSuffixW[MAX_PATH];

    // Convert the paths from char_t to wchar_t
    mbstowcs(PathSuffixW, Path.c_str(), MAX_PATH);

    // Append the paths together
    HRESULT CombineResult =
        PathCchCombine(FullPathW, MAX_PATH, HandleFullPathW, PathSuffixW);
    switch (CombineResult) {
    case S_OK:
      break;
    case E_INVALIDARG:
      return WasiUnexpect(__WASI_ERRNO_INVAL);
    case E_OUTOFMEMORY:
      return WasiUnexpect(__WASI_ERRNO_OVERFLOW);
    default:
      return WasiUnexpect(__WASI_ERRNO_NAMETOOLONG);
    }

  } else {
    mbstowcs(FullPathW, Path.c_str(), MAX_PATH);
  }

  // Fill the Buffer with the contents of the link
  winapi::HANDLE_ LocalFileHandle;

  LocalFileHandle =
      CreateFileW(FullPathW, winapi::GENERIC_READ_, winapi::FILE_SHARE_READ_,
                  nullptr, winapi::OPEN_EXISTING_, 0, nullptr);

  if (likely(LocalFileHandle != winapi::INVALID_HANDLE_VALUE_)) {
    if (unlikely(GetFinalPathNameByHandleA(LocalFileHandle, Buffer.data(),
                                           static_cast<uint32_t>(Buffer.size()),
                                           FILE_NAME_NORMALIZED) != 0)) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }
    NRead = static_cast<uint32_t>(Buffer.size());
    CloseHandle(LocalFileHandle);
    return {};
  }

  return WasiUnexpect(fromWinError(winapi::GetLastError()));
}

WasiExpect<void> INode::pathRemoveDirectory(std::string Path) const noexcept {
  if (RemoveDirectoryA(Path.c_str()) == 0) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }
  return {};
}

WasiExpect<void> INode::pathRename(const INode &Old, std::string OldPath,
                                   const INode &New,
                                   std::string NewPath) noexcept {

  wchar_t OldFullPathW[MAX_PATH];
  wchar_t NewFullPathW[MAX_PATH];

  if (PathIsRelativeA(OldPath.c_str())) {
    wchar_t HandleFullPath[MAX_PATH];

    // First get the paths of the handles
    if (unlikely(winapi::GetFinalPathNameByHandleW(
            Old.Handle, HandleFullPath, MAX_PATH,
            winapi::FILE_NAME_NORMALIZED)) == 0) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }

    if (!PathIsDirectoryW(HandleFullPath) && !OldPath.empty()) {
      return WasiUnexpect(__WASI_ERRNO_NOTDIR);
    }

    wchar_t OldPathW[MAX_PATH];

    // Convert the paths from char_t to wchar_t
    mbstowcs(OldPathW, OldPath.c_str(), MAX_PATH);

    // Append the paths together
    HRESULT CombineResult =
        PathCchCombine(OldFullPathW, MAX_PATH, OldFullPathW, OldPathW);

    switch (CombineResult) {
    case S_OK:
      break;
    case E_INVALIDARG:
      return WasiUnexpect(__WASI_ERRNO_INVAL);
    case E_OUTOFMEMORY:
      return WasiUnexpect(__WASI_ERRNO_OVERFLOW);
    default:
      return WasiUnexpect(__WASI_ERRNO_NAMETOOLONG);
    }

  } else {
    mbstowcs(OldFullPathW, OldPath.c_str(), MAX_PATH);
  }

  if (PathIsRelativeA(NewPath.c_str())) {
    wchar_t HandleFullPathW[MAX_PATH];

    // First get the paths of the handles
    if (unlikely(winapi::GetFinalPathNameByHandleW(
            New.Handle, HandleFullPathW, MAX_PATH,
            winapi::FILE_NAME_NORMALIZED_)) == 0) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }

    if (!PathIsDirectoryW(HandleFullPathW) && !NewPath.empty()) {
      return WasiUnexpect(__WASI_ERRNO_NOTDIR);
    }

    wchar_t NewPathW[MAX_PATH];

    // Convert the paths from char_t to wchar_t
    mbstowcs(NewPathW, NewPath.c_str(), MAX_PATH);

    // Append the paths together
    HRESULT CombineResult =
        PathCchCombine(NewFullPathW, MAX_PATH, HandleFullPathW, NewPathW);

    switch (CombineResult) {
    case S_OK:
      break;
    case E_INVALIDARG:
      return WasiUnexpect(__WASI_ERRNO_INVAL);
    case E_OUTOFMEMORY:
      return WasiUnexpect(__WASI_ERRNO_OVERFLOW);
    default:
      return WasiUnexpect(__WASI_ERRNO_NAMETOOLONG);
    }

  } else {
    mbstowcs(NewFullPathW, NewPath.c_str(), MAX_PATH);
  }

  // Rename the file from the paths
  if (unlikely(MoveFileW(OldFullPathW, NewFullPathW) == 0)) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }

  return {};
}

WasiExpect<void> INode::pathSymlink(std::string OldPath,
                                    std::string NewPath) const noexcept {

  wchar_t OldFullPathW[MAX_PATH];
  wchar_t NewFullPathW[MAX_PATH];

  if (PathIsRelativeA(OldPath.c_str())) {
    wchar_t OldPathW[MAX_PATH];
    wchar_t HandleFullPath[MAX_PATH];

    // Convert the paths from char_t to wchar_t
    mbstowcs(OldPathW, OldPath.c_str(), MAX_PATH);

    // First get the paths of the handle
    if (unlikely(winapi::GetFinalPathNameByHandleW(
            Handle, HandleFullPath, MAX_PATH, winapi::FILE_NAME_NORMALIZED_)) ==
        0) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }
    // If check it is a directory or not
    if (!PathIsDirectoryW(HandleFullPath) && !OldPath.empty()) {
      return WasiUnexpect(__WASI_ERRNO_NOTDIR);
    }
    HRESULT CombineResult =
        PathCchCombine(OldFullPathW, MAX_PATH, HandleFullPath, OldPathW);

    switch (CombineResult) {
    case S_OK:
      break;
    case E_INVALIDARG:
      return WasiUnexpect(__WASI_ERRNO_INVAL);
    case E_OUTOFMEMORY:
      return WasiUnexpect(__WASI_ERRNO_OVERFLOW);
    default:
      return WasiUnexpect(__WASI_ERRNO_NAMETOOLONG);
    }
  }
  if (PathIsRelativeA(NewPath.c_str())) {
    wchar_t NewPathW[MAX_PATH];
    wchar_t HandleFullPath[MAX_PATH];

    // Convert the path from char_t to wchar_t
    mbstowcs(NewPathW, NewPath.c_str(), MAX_PATH);

    // First get the path of the handle
    if (unlikely(winapi::GetFinalPathNameByHandleW(
            Handle, HandleFullPath, MAX_PATH, winapi::FILE_NAME_NORMALIZED_)) ==
        0) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }
    __wasi_fdstat_t HandleStat;
    fdFdstatGet(HandleStat);

    // Remove file names if the handle refers to a file
    if (!PathIsDirectoryW(HandleFullPath) && !OldPath.empty()) {
      PathCchRemoveFileSpec(HandleFullPath, MAX_PATH);
    }
    HRESULT CombineResult =
        PathCchCombine(NewFullPathW, MAX_PATH, HandleFullPath, NewPathW);
    switch (CombineResult) {
    case S_OK:
      break;
    case E_INVALIDARG:
      return WasiUnexpect(__WASI_ERRNO_INVAL);
    case E_OUTOFMEMORY:
      return WasiUnexpect(__WASI_ERRNO_OVERFLOW);
    default:
      return WasiUnexpect(__WASI_ERRNO_NAMETOOLONG);
    }
  }
  winapi::DWORD_ TargetType = 0;
  if (PathIsDirectoryW(OldFullPathW)) {
    TargetType = SYMBOLIC_LINK_FLAG_DIRECTORY;
  }

  if (unlikely(CreateSymbolicLinkW(NewFullPathW, OldFullPathW, TargetType))) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }

  return {};
}

WasiExpect<void> INode::pathUnlinkFile(std::string Path) const noexcept {

  wchar_t PathFullW[MAX_PATH];

  if (PathIsRelativeA(Path.c_str())) {
    wchar_t PathW[MAX_PATH];
    wchar_t HandleFullPath[MAX_PATH];

    // Convert the paths from char_t to wchar_t
    mbstowcs(PathW, Path.c_str(), MAX_PATH);

    // First get the paths of the handle
    if (unlikely(winapi::GetFinalPathNameByHandleW(
            Handle, HandleFullPath, MAX_PATH, winapi::FILE_NAME_NORMALIZED_)) ==
        0) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }
    if (!PathIsDirectoryW(HandleFullPath)) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }
    HRESULT CombineResult =
        PathCchCombine(PathFullW, MAX_PATH, HandleFullPath, PathW);

    switch (CombineResult) {
    case S_OK:
      break;
    case E_INVALIDARG:
      return WasiUnexpect(__WASI_ERRNO_INVAL);
    case E_OUTOFMEMORY:
      return WasiUnexpect(__WASI_ERRNO_OVERFLOW);
    default:
      return WasiUnexpect(__WASI_ERRNO_NAMETOOLONG);
    }
  }

  if (PathIsDirectoryW(PathFullW)) {
    if (unlikely(RemoveDirectoryW(PathFullW) == 0)) {
      return WasiUnexpect(fromWinError(winapi::GetLastError()));
    }
    return {};
  }

  if (unlikely(DeleteFileW(PathFullW) == 0)) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }

  return {};
}

WasiExpect<Poller> INode::pollOneoff(__wasi_size_t) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<Epoller> INode::epollOneoff(__wasi_size_t, int) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

static bool EnsureWSAStartup() {
  static bool WSALoad = false;
  static WSADATA WSAData;

  if (!WSALoad) {
    int Err = WSAStartup(MAKEWORD(2, 2), &WSAData);
    if (Err == 0) {
      WSALoad = true;
    }
  }

  return WSALoad;
}

WasiExpect<void> INode::getAddrinfo(std::string_view Node,
                                    std::string_view Service,
                                    const __wasi_addrinfo_t &Hint,
                                    uint32_t MaxResLength,
                                    Span<__wasi_addrinfo_t *> WasiAddrinfoArray,
                                    Span<__wasi_sockaddr_t *> WasiSockaddrArray,
                                    Span<char *> AiAddrSaDataArray,
                                    Span<char *> AiCanonnameArray,
                                    /*Out*/ __wasi_size_t &ResLength) noexcept {
  const auto [NodeCStr, NodeBuf] = createNullTerminatedString(Node);
  const auto [ServiceCStr, ServiceBuf] = createNullTerminatedString(Service);

  struct addrinfo SysHint;
  SysHint.ai_flags = toAIFlags(Hint.ai_flags);
  SysHint.ai_family = toAddressFamily(Hint.ai_family);
  SysHint.ai_socktype = toSockType(Hint.ai_socktype);
  SysHint.ai_protocol = toProtocal(Hint.ai_protocol);
  SysHint.ai_addrlen = Hint.ai_addrlen;
  SysHint.ai_addr = nullptr;
  SysHint.ai_canonname = nullptr;
  SysHint.ai_next = nullptr;

  struct addrinfo *SysResPtr = nullptr;
  if (auto Res = ::getaddrinfo(NodeCStr, ServiceCStr, &SysHint, &SysResPtr);
      unlikely(Res != 0)) {
    // By MSDN, on failure, getaddrinfo returns a nonzero Windows Sockets error
    // code.
    return WasiUnexpect(fromWSAToEAIError(Res));
  }
  // calculate ResLength
  if (ResLength = calculateAddrinfoLinkedListSize(SysResPtr);
      ResLength > MaxResLength) {
    ResLength = MaxResLength;
  }

  struct addrinfo *SysResItem = SysResPtr;
  for (uint32_t Idx = 0; Idx < ResLength; Idx++) {
    auto &CurAddrinfo = WasiAddrinfoArray[Idx];
    CurAddrinfo->ai_flags = fromAIFlags(SysResItem->ai_flags);
    CurAddrinfo->ai_socktype = fromSockType(SysResItem->ai_socktype);
    CurAddrinfo->ai_protocol = fromProtocal(SysResItem->ai_protocol);
    CurAddrinfo->ai_family = fromAddressFamily(SysResItem->ai_family);
    CurAddrinfo->ai_addrlen = static_cast<uint32_t>(SysResItem->ai_addrlen);

    // process ai_canonname in addrinfo
    if (SysResItem->ai_canonname != nullptr) {
      CurAddrinfo->ai_canonname_len =
          static_cast<uint32_t>(std::strlen(SysResItem->ai_canonname));
      auto &CurAiCanonname = AiCanonnameArray[Idx];
      std::memcpy(CurAiCanonname, SysResItem->ai_canonname,
                  CurAddrinfo->ai_canonname_len + 1);
    } else {
      CurAddrinfo->ai_canonname_len = 0;
    }

    // process socket address
    if (SysResItem->ai_addrlen > 0) {
      auto &CurSockaddr = WasiSockaddrArray[Idx];
      CurSockaddr->sa_family =
          fromAddressFamily(SysResItem->ai_addr->sa_family);

      // process sa_data in socket address
      size_t SaSize = 0;
      switch (CurSockaddr->sa_family) {
      case __wasi_address_family_t::__WASI_ADDRESS_FAMILY_INET4:
        SaSize = sizeof(sockaddr_in) - sizeof(sockaddr_in::sin_family);
        break;
      case __wasi_address_family_t::__WASI_ADDRESS_FAMILY_INET6:
        SaSize = sizeof(sockaddr_in6) - sizeof(sockaddr_in6::sin6_family);
        break;
      default:
        assumingUnreachable();
      }
      std::memcpy(AiAddrSaDataArray[Idx], SysResItem->ai_addr->sa_data, SaSize);
      CurSockaddr->sa_data_len = __wasi_size_t(SaSize);
    }
    // process ai_next in addrinfo
    SysResItem = SysResItem->ai_next;
  }
  ::freeaddrinfo(SysResPtr);

  return {};
}

WasiExpect<INode> INode::sockOpen(__wasi_address_family_t AddressFamily,
                                  __wasi_sock_type_t SockType) noexcept {
  EnsureWSAStartup();

  int SysProtocol = IPPROTO_IP;

  int SysDomain = 0;
  int SysType = 0;

  switch (AddressFamily) {
  case __WASI_ADDRESS_FAMILY_INET4:
    SysDomain = AF_INET;
    break;
  case __WASI_ADDRESS_FAMILY_INET6:
    SysDomain = AF_INET6;
    break;
  default:
    return WasiUnexpect(__WASI_ERRNO_INVAL);
  }

  switch (SockType) {
  case __WASI_SOCK_TYPE_SOCK_DGRAM:
    SysType = SOCK_DGRAM;
    break;
  case __WASI_SOCK_TYPE_SOCK_STREAM:
    SysType = SOCK_STREAM;
    break;
  default:
    return WasiUnexpect(__WASI_ERRNO_INVAL);
  }

  if (auto NewSock = ::socket(SysDomain, SysType, SysProtocol);
      unlikely(NewSock == INVALID_SOCKET)) {
    return WasiUnexpect(fromWSALastError(WSAGetLastError()));
  } else {
    INode New(reinterpret_cast<winapi::HANDLE_>(NewSock));
    return New;
  }
}

WasiExpect<void> INode::sockBind(uint8_t *Address, uint8_t AddressLength,
                                 uint16_t Port) noexcept {
  EnsureWSAStartup();

  if (AddressLength == 4) {
    struct sockaddr_in ServerAddr;
    ServerAddr.sin_family = AF_INET;
    ServerAddr.sin_port = htons(Port);
    std::memcpy(&ServerAddr.sin_addr.s_addr, Address, AddressLength);

    if (auto Res = ::bind(toSocket(Handle),
                          reinterpret_cast<struct sockaddr *>(&ServerAddr),
                          sizeof(ServerAddr));
        unlikely(Res == SOCKET_ERROR)) {
      return WasiUnexpect(fromWSALastError(WSAGetLastError()));
    }
  } else if (AddressLength == 16) {
    struct sockaddr_in6 ServerAddr;
    std::memset(&ServerAddr, 0, sizeof(ServerAddr));

    ServerAddr.sin6_family = AF_INET6;
    ServerAddr.sin6_port = htons(Port);
    std::memcpy(ServerAddr.sin6_addr.s6_addr, Address, AddressLength);
    if (auto Res = ::bind(toSocket(Handle),
                          reinterpret_cast<struct sockaddr *>(&ServerAddr),
                          sizeof(ServerAddr));
        unlikely(Res == SOCKET_ERROR)) {
      return WasiUnexpect(fromWSALastError(WSAGetLastError()));
    }
  }
  return {};
}

WasiExpect<void> INode::sockListen(int32_t Backlog) noexcept {
  EnsureWSAStartup();
  if (auto Res = ::listen(toSocket(Handle), Backlog);
      unlikely(Res == SOCKET_ERROR)) {
    return WasiUnexpect(fromWSALastError(WSAGetLastError()));
  }
  return {};
}

WasiExpect<INode> INode::sockAccept() noexcept {
  EnsureWSAStartup();
  struct sockaddr_in ServerSocketAddr;
  ServerSocketAddr.sin_family = AF_INET;
  ServerSocketAddr.sin_addr.s_addr = INADDR_ANY;
  socklen_t AddressLen = sizeof(ServerSocketAddr);

  if (auto NewSock = ::accept(
          toSocket(Handle),
          reinterpret_cast<struct sockaddr *>(&ServerSocketAddr), &AddressLen);
      unlikely(NewSock == INVALID_SOCKET)) {
    return WasiUnexpect(fromWSALastError(WSAGetLastError()));
  } else {
    INode New(reinterpret_cast<winapi::HANDLE_>(NewSock));
    return New;
  }
}

WasiExpect<void> INode::sockConnect(uint8_t *Address, uint8_t AddressLength,
                                    uint16_t Port) noexcept {
  EnsureWSAStartup();
  if (AddressLength == 4) {
    struct sockaddr_in ClientSocketAddr;
    ClientSocketAddr.sin_family = AF_INET;
    ClientSocketAddr.sin_port = htons(Port);
    std::memcpy(&ClientSocketAddr.sin_addr.s_addr, Address, AddressLength);

    if (auto Res =
            ::connect(toSocket(Handle),
                      reinterpret_cast<struct sockaddr *>(&ClientSocketAddr),
                      sizeof(ClientSocketAddr));
        unlikely(Res == SOCKET_ERROR)) {
      return WasiUnexpect(fromWSALastError(WSAGetLastError()));
    }
  } else if (AddressLength == 16) {
    struct sockaddr_in6 ClientSocketAddr;

    ClientSocketAddr.sin6_family = AF_INET6;
    ClientSocketAddr.sin6_port = htons(Port);
    std::memcpy(ClientSocketAddr.sin6_addr.s6_addr, Address, AddressLength);
    if (auto Res =
            ::connect(toSocket(Handle),
                      reinterpret_cast<struct sockaddr *>(&ClientSocketAddr),
                      sizeof(ClientSocketAddr));
        unlikely(Res == SOCKET_ERROR)) {
      return WasiUnexpect(fromWSALastError(WSAGetLastError()));
    }
  }
  return {};
}

WasiExpect<void> INode::sockRecv(Span<Span<uint8_t>> RiData,
                                 __wasi_riflags_t RiFlags, __wasi_size_t &NRead,
                                 __wasi_roflags_t &RoFlags) const noexcept {
  return sockRecvFrom(RiData, RiFlags, nullptr, 0, NRead, RoFlags);
}

WasiExpect<void> INode::sockRecvFrom(Span<Span<uint8_t>> RiData,
                                     __wasi_riflags_t RiFlags, uint8_t *Address,
                                     uint8_t AddressLength,
                                     __wasi_size_t &NRead,
                                     __wasi_roflags_t &RoFlags) const noexcept {
  EnsureWSAStartup();
  // recvmsg is not available on WINDOWS. fall back to call recvfrom
  int SysRiFlags = 0;
  if (RiFlags & __WASI_RIFLAGS_RECV_PEEK) {
    SysRiFlags |= MSG_PEEK;
  }
  if (RiFlags & __WASI_RIFLAGS_RECV_WAITALL) {
    SysRiFlags |= MSG_WAITALL;
  }

  std::size_t TmpBufSize = 0;
  for (auto &IOV : RiData) {
    TmpBufSize += IOV.size();
  }

  std::vector<uint8_t> TmpBuf(TmpBufSize, 0);

  sockaddr_storage SockAddrStorage;
  int MaxAllowLength = 0;
  if (AddressLength == 4) {
    MaxAllowLength = sizeof(sockaddr_in);
  } else if (AddressLength == 16) {
    MaxAllowLength = sizeof(sockaddr_in6);
  }

  if (auto Res = ::recvfrom(
          toSocket(Handle), reinterpret_cast<char *>(TmpBuf.data()),
          static_cast<int>(TmpBufSize), SysRiFlags,
          reinterpret_cast<sockaddr *>(&SockAddrStorage), &MaxAllowLength);
      unlikely(Res == SOCKET_ERROR)) {
    return WasiUnexpect(fromWSALastError(WSAGetLastError()));
  } else {
    NRead = static_cast<__wasi_size_t>(Res);
  }

  if (AddressLength == 4) {
    std::memcpy(Address,
                &reinterpret_cast<sockaddr_in *>(&SockAddrStorage)->sin_addr,
                AddressLength);
  } else if (AddressLength == 16) {
    std::memcpy(Address,
                &reinterpret_cast<sockaddr_in6 *>(&SockAddrStorage)->sin6_addr,
                AddressLength);
  }

  RoFlags = static_cast<__wasi_roflags_t>(0);
  // TODO : check MSG_TRUNC

  size_t BeginIdx = 0;
  for (auto &IOV : RiData) {
    std::copy(TmpBuf.data() + BeginIdx, TmpBuf.data() + BeginIdx + IOV.size(),
              IOV.begin());
    BeginIdx += IOV.size();
  }

  return {};
}

WasiExpect<void> INode::sockSend(Span<Span<const uint8_t>> SiData,
                                 __wasi_siflags_t SiFlags,
                                 __wasi_size_t &NWritten) const noexcept {
  return sockSendTo(SiData, SiFlags, nullptr, 0, 0, NWritten);
}
WasiExpect<void> INode::sockSendTo(Span<Span<const uint8_t>> SiData,
                                   __wasi_siflags_t, uint8_t *Address,
                                   uint8_t AddressLength, int32_t Port,
                                   __wasi_size_t &NWritten) const noexcept {
  EnsureWSAStartup();
  // sendmsg is not available on WINDOWS. fall back to call sendto
  int SysSiFlags = 0;

  std::vector<uint8_t> TmpBuf;
  for (auto &IOV : SiData) {
    copy(IOV.begin(), IOV.end(), std::back_inserter(TmpBuf));
  }
  std::size_t TmpBufSize = TmpBuf.size();

  struct sockaddr_in ClientSocketAddr;
  struct sockaddr_in6 ClientSocketAddr6;
  void *Addr = nullptr;
  socklen_t AddrLen = 0;

  if (Address) {
    if (AddressLength == 4) {
      ClientSocketAddr.sin_family = AF_INET;
      ClientSocketAddr.sin_port = htons(static_cast<u_short>(Port));
      std::memcpy(&ClientSocketAddr.sin_addr.s_addr, Address, AddressLength);

      Addr = &ClientSocketAddr;
      AddrLen = sizeof(ClientSocketAddr);
    } else if (AddressLength == 16) {
      std::memset(&ClientSocketAddr6, 0x00, sizeof(ClientSocketAddr6));
      ClientSocketAddr6.sin6_family = AF_INET6;
      ClientSocketAddr6.sin6_port = htons(static_cast<u_short>(Port));
      std::memcpy(&ClientSocketAddr6.sin6_addr.s6_addr, Address, AddressLength);

      Addr = &ClientSocketAddr6;
      AddrLen = sizeof(ClientSocketAddr6);
    }
  }

  if (auto Res =
          ::sendto(toSocket(Handle), reinterpret_cast<char *>(TmpBuf.data()),
                   static_cast<int>(TmpBufSize), SysSiFlags,
                   reinterpret_cast<sockaddr *>(Addr), AddrLen);
      unlikely(Res == SOCKET_ERROR)) {
    return WasiUnexpect(fromWSALastError(WSAGetLastError()));
  } else {
    NWritten = static_cast<__wasi_size_t>(Res);
  }

  return {};
}

WasiExpect<void> INode::sockShutdown(__wasi_sdflags_t SdFlags) const noexcept {
  EnsureWSAStartup();
  int SysFlags = 0;
  if (SdFlags == __WASI_SDFLAGS_RD) {
    SysFlags = SD_RECEIVE;
  } else if (SdFlags == __WASI_SDFLAGS_WR) {
    SysFlags = SD_SEND;
  } else if (SdFlags == (__WASI_SDFLAGS_RD | __WASI_SDFLAGS_WR)) {
    SysFlags = SD_BOTH;
  }

  if (auto Res = ::shutdown(toSocket(Handle), SysFlags);
      unlikely(Res == SOCKET_ERROR)) {
    return WasiUnexpect(fromWSALastError(WSAGetLastError()));
  }

  return {};
}

WasiExpect<void> INode::sockGetOpt(__wasi_sock_opt_level_t SockOptLevel,
                                   __wasi_sock_opt_so_t SockOptName,
                                   void *FlagPtr,
                                   uint32_t *FlagSizePtr) const noexcept {
  EnsureWSAStartup();
  auto SysSockOptLevel = toSockOptLevel(SockOptLevel);
  auto SysSockOptName = toSockOptSoName(SockOptName);
  auto UnsafeFlagSizePtr = reinterpret_cast<int *>(FlagSizePtr);
  if (SockOptName == __WASI_SOCK_OPT_SO_ERROR) {
    char ErrorCode = 0;
    int *WasiErrorPtr = static_cast<int *>(FlagPtr);
    if (auto Res = ::getsockopt(toSocket(Handle), SysSockOptLevel,
                                SysSockOptName, &ErrorCode, UnsafeFlagSizePtr);
        unlikely(Res == SOCKET_ERROR)) {
      return WasiUnexpect(fromWSALastError(WSAGetLastError()));
    }
    *WasiErrorPtr = fromErrNo(ErrorCode);
  } else {
    char *CFlagPtr = static_cast<char *>(FlagPtr);
    if (auto Res = ::getsockopt(toSocket(Handle), SysSockOptLevel,
                                SysSockOptName, CFlagPtr, UnsafeFlagSizePtr);
        unlikely(Res == SOCKET_ERROR)) {
      return WasiUnexpect(fromWSALastError(WSAGetLastError()));
    }
  }

  return {};
}

WasiExpect<void> INode::sockSetOpt(__wasi_sock_opt_level_t SockOptLevel,
                                   __wasi_sock_opt_so_t SockOptName,
                                   void *FlagPtr,
                                   uint32_t FlagSize) const noexcept {
  EnsureWSAStartup();
  auto SysSockOptLevel = toSockOptLevel(SockOptLevel);
  auto SysSockOptName = toSockOptSoName(SockOptName);
  char *CFlagPtr = static_cast<char *>(FlagPtr);
  auto UnsafeFlagSize = static_cast<int>(FlagSize);

  if (auto Res = ::setsockopt(toSocket(Handle), SysSockOptLevel, SysSockOptName,
                              CFlagPtr, UnsafeFlagSize);
      unlikely(Res == SOCKET_ERROR)) {
    return WasiUnexpect(fromWSALastError(WSAGetLastError()));
  }

  return {};
}

WasiExpect<void> INode::sockGetLoaclAddr(uint8_t *AddressPtr,
                                         uint32_t *AddrTypePtr,
                                         uint32_t *PortPtr) const noexcept {
  EnsureWSAStartup();
  struct sockaddr_storage SocketAddr;
  socklen_t Slen = sizeof(SocketAddr);
  std::memset(&SocketAddr, 0, sizeof(SocketAddr));

  if (auto Res = ::getsockname(
          toSocket(Handle), reinterpret_cast<sockaddr *>(&SocketAddr), &Slen);
      unlikely(Res == SOCKET_ERROR)) {
    return WasiUnexpect(fromWSALastError(WSAGetLastError()));
  }

  size_t AddrLen = 4;
  if (Slen != 16) {
    AddrLen = 16;
  }

  if (SocketAddr.ss_family == AF_INET) {
    *AddrTypePtr = 4;
    auto SocketAddrv4 = reinterpret_cast<struct sockaddr_in *>(&SocketAddr);
    *PortPtr = ntohs(SocketAddrv4->sin_port);
    std::memcpy(AddressPtr, &(SocketAddrv4->sin_addr.s_addr), AddrLen);
  } else if (SocketAddr.ss_family == AF_INET6) {
    *AddrTypePtr = 6;
    auto SocketAddrv6 = reinterpret_cast<struct sockaddr_in6 *>(&SocketAddr);
    *PortPtr = ntohs(SocketAddrv6->sin6_port);
    std::memcpy(AddressPtr, SocketAddrv6->sin6_addr.s6_addr, AddrLen);
  } else {
    return WasiUnexpect(__WASI_ERRNO_NOSYS);
  }

  return {};
}

WasiExpect<void> INode::sockGetPeerAddr(uint8_t *, uint32_t *,
                                        uint32_t *) const noexcept {
  EnsureWSAStartup();
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

__wasi_filetype_t INode::unsafeFiletype() const noexcept {

  // TODO: Find equivalents to the other file types
  // To be completed along with other similar functions

  if (unlikely(GetFileInformationByHandle(Handle, &(*FileInfo)) == 0)) {
    return __WASI_FILETYPE_UNKNOWN;
  }
  return fromFileType((*FileInfo).dwFileAttributes, GetFileType(Handle));
}

WasiExpect<__wasi_filetype_t> INode::filetype() const noexcept {

  // TODO: Find equivalents to the other file types
  // To be completed along with other similar functions

  return unsafeFiletype();
}

WasiExpect<void> INode::updateFileInfo() const noexcept {
  FileInfo.emplace();
  if (unlikely(GetFileInformationByHandle(Handle, &(*FileInfo)) == 0)) {
    return WasiUnexpect(fromWinError(winapi::GetLastError()));
  }
  return {};
}

bool INode::isDirectory() const noexcept {
  updateFileInfo();
  return FileInfo->dwFileAttributes == winapi::FILE_ATTRIBUTE_DIRECTORY_;
}

bool INode::isSymlink() const noexcept {
  updateFileInfo();
  return FileInfo->dwFileAttributes == winapi::FILE_ATTRIBUTE_REPARSE_POINT_;
}

WasiExpect<__wasi_filesize_t> INode::filesize() const noexcept {
  updateFileInfo();
  return static_cast<uint64_t>((*FileInfo).nFileSizeLow) +
         (static_cast<uint64_t>((*FileInfo).nFileSizeHigh) << 32);
}

bool INode::canBrowse() const noexcept { return false; }

Poller::Poller(__wasi_size_t Count) { Events.reserve(Count); }

WasiExpect<void> Poller::clock(__wasi_clockid_t, __wasi_timestamp_t,
                               __wasi_timestamp_t, __wasi_subclockflags_t,
                               __wasi_userdata_t) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<void> Poller::read(const INode &, __wasi_userdata_t) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<void> Poller::write(const INode &, __wasi_userdata_t) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<void> Poller::wait(CallbackType) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

Epoller::Epoller(__wasi_size_t Count, int) { Events.reserve(Count); }

WasiExpect<void> Epoller::clock(__wasi_clockid_t, __wasi_timestamp_t,
                                __wasi_timestamp_t, __wasi_subclockflags_t,
                                __wasi_userdata_t) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<void> Epoller::read(const INode &, __wasi_userdata_t,
                               std::unordered_map<int, uint32_t> &) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<void> Epoller::write(const INode &, __wasi_userdata_t,
                                std::unordered_map<int, uint32_t> &) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

WasiExpect<void> Epoller::wait(CallbackType,
                               std::unordered_map<int, uint32_t> &) noexcept {
  return WasiUnexpect(__WASI_ERRNO_NOSYS);
}

} // namespace WASI
} // namespace Host
} // namespace WasmEdge

#endif
