// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Utils/IntervalList.h>
#include <thread>
#include <shared_mutex>


namespace FEX::Windows {
/**
 * @brief Emulates memory overcommit of reserved regions with exceptions
 */
class OvercommitTracker {
private:
  bool IsWine;
  FEXCore::IntervalList<uint64_t> OvercommitIntervals;
  FEXCore::IntervalList<uint64_t> OvercommitExecIntervals;
  std::shared_mutex OvercommitIntervalsMutex;

  static void Commit(void* Address, size_t Size, bool Exec) {
    VirtualAlloc(Address, Size, MEM_COMMIT, Exec ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE);
  }

public:
  OvercommitTracker(bool IsWine)
    : IsWine {IsWine} {}

  void MarkRange(uint64_t Start, uint64_t Length, bool Exec = false) {
    std::unique_lock Lock {OvercommitIntervalsMutex};
    (Exec ? OvercommitExecIntervals : OvercommitIntervals).Insert({Start, Start + Length});
  }

  void UnmarkRange(uint64_t Start, uint64_t Length) {
    std::unique_lock Lock {OvercommitIntervalsMutex};
    OvercommitIntervals.Remove({Start, Start + Length});
    OvercommitExecIntervals.Remove({Start, Start + Length});
  }

  bool HandleAccessViolation(uint64_t FaultAddress) {
    std::shared_lock Lock {OvercommitIntervalsMutex};
    bool Exec = false;
    auto Query = OvercommitIntervals.Query(FaultAddress);
    if (!Query.Enclosed) {
      Query = OvercommitExecIntervals.Query(FaultAddress);
      Exec = true;
    }

    if (Query.Enclosed) {
      if (IsWine) {
        MEMORY_BASIC_INFORMATION Info;
        NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(FaultAddress), MemoryBasicInformation, &Info, sizeof(Info), nullptr);
        const auto CommitSize = reinterpret_cast<SIZE_T>(Info.BaseAddress) + Info.RegionSize - reinterpret_cast<SIZE_T>(Info.AllocationBase);
        Commit(reinterpret_cast<void*>(Info.AllocationBase), CommitSize, Exec);
      } else {
        static constexpr size_t MaxFaultCommitSize = 1024 * 64;
        const auto AlignedFaultAddress = reinterpret_cast<void*>(FaultAddress & FEXCore::Utils::FEX_PAGE_MASK);
        Commit(AlignedFaultAddress, std::min(Query.Size, MaxFaultCommitSize), Exec);
      }
      return true;
    }
    return false;
  }
};
} // namespace FEX::Windows
