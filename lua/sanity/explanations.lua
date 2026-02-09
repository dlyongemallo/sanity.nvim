-- Static explanations for common error kinds from valgrind and sanitizers.
local M = {
    Race = {
        title = "Data Race",
        description = "Two or more threads accessed the same memory location concurrently, " ..
            "and at least one access was a write, without proper synchronisation.",
        common_fixes = {
            "Add mutex/lock protection around the shared variable.",
            "Use higher-level concurrency primitives where applicable.",
            "Redesign to avoid shared mutable state between threads.",
            "Use thread-local storage if the data does not need to be shared.",
        },
    },
    Leak_DefinitelyLost = {
        title = "Definitely Lost Memory",
        description = "Memory was allocated but no pointer to it exists anymore. " ..
            "This memory can never be freed and is definitely leaked.",
        common_fixes = {
            "Ensure every malloc/new has a corresponding free/delete.",
            "Use RAII patterns or smart pointers in C++.",
            "Check all early return paths for proper cleanup.",
            "Consider using a memory pool or arena allocator.",
        },
    },
    Leak_IndirectlyLost = {
        title = "Indirectly Lost Memory",
        description = "Memory is lost because the pointer to it was in another block " ..
            "that was itself lost. Fixing the 'definitely lost' block will also fix this.",
        common_fixes = {
            "Find and fix the 'definitely lost' block that contains the pointer to this memory.",
            "Ensure proper cleanup of nested data structures.",
        },
    },
    Leak_PossiblyLost = {
        title = "Possibly Lost Memory",
        description = "A pointer to the interior of this block exists, but no pointer " ..
            "to the start. This might be a leak or might be intentional pointer arithmetic.",
        common_fixes = {
            "Check if interior pointers are intentional (e.g., for aligned allocation).",
            "Ensure the base pointer is preserved if the memory needs to be freed.",
        },
    },
    Leak_StillReachable = {
        title = "Still Reachable Memory",
        description = "Memory is still reachable at program exit but was never freed. " ..
            "While not technically a leak, it indicates missing cleanup.",
        common_fixes = {
            "Add cleanup code before program exit.",
            "This is often acceptable for global/singleton objects.",
        },
    },
    InvalidRead = {
        title = "Invalid Read",
        description = "Reading from memory that is not valid — freed, unallocated, or out of bounds.",
        common_fixes = {
            "Check array bounds before accessing.",
            "Ensure pointers are not used after free.",
            "Initialise pointers to NULL and check before use.",
        },
    },
    InvalidWrite = {
        title = "Invalid Write",
        description = "Writing to memory that is not valid — freed, unallocated, or out of bounds.",
        common_fixes = {
            "Check array bounds before writing.",
            "Ensure pointers are not used after free.",
            "Verify buffer sizes before string operations.",
        },
    },
    InvalidFree = {
        title = "Invalid Free",
        description = "Attempting to free memory that was not allocated or was already freed.",
        common_fixes = {
            "Set pointers to NULL after freeing.",
            "Track ownership clearly to avoid double-free.",
            "Do not free stack-allocated or static memory.",
        },
    },
    UninitCondition = {
        title = "Conditional Jump on Uninitialised Value",
        description = "A conditional branch depends on an uninitialised value.",
        common_fixes = {
            "Initialise all variables before use.",
            "Check all code paths initialise the variable.",
            "Use compiler warnings (-Wuninitialized).",
        },
    },
    UninitValue = {
        title = "Use of Uninitialised Value",
        description = "An uninitialised value is being used in a computation.",
        common_fixes = {
            "Initialise variables at declaration.",
            "Ensure all struct/array members are initialised.",
        },
    },
    Overlap = {
        title = "Memory Overlap",
        description = "Source and destination of a memory copy operation overlap incorrectly.",
        common_fixes = {
            "Use memmove() instead of memcpy() for overlapping regions.",
            "Ensure buffers do not overlap in strcpy/strcat operations.",
        },
    },
    UnlockUnlocked = {
        title = "Unlock of Unlocked Mutex",
        description = "Attempting to unlock a mutex that is not currently locked.",
        common_fixes = {
            "Ensure lock/unlock calls are balanced.",
            "Check ownership before unlocking.",
            "Use RAII lock guards in C++.",
        },
    },
    LockOrder = {
        title = "Lock Order Violation",
        description = "Locks are being acquired in an inconsistent order across threads, " ..
            "which can lead to deadlock.",
        common_fixes = {
            "Establish and document a global lock ordering.",
            "Always acquire locks in the same order.",
            "Consider using a single coarser lock if ordering is difficult.",
        },
    },
    ["heap-use-after-free"] = {
        title = "Heap Use After Free",
        description = "Accessing heap memory that has already been freed.",
        common_fixes = {
            "Set pointers to NULL after freeing.",
            "Use smart pointers or RAII in C++.",
            "Review object lifetimes and ownership.",
        },
    },
    ["heap-buffer-overflow"] = {
        title = "Heap Buffer Overflow",
        description = "Accessing memory beyond the bounds of a heap-allocated buffer.",
        common_fixes = {
            "Check array indices against allocated size.",
            "Use bounds-checked container types.",
            "Verify sizes passed to memcpy/strcpy.",
        },
    },
    ["stack-buffer-overflow"] = {
        title = "Stack Buffer Overflow",
        description = "Accessing memory beyond the bounds of a stack-allocated buffer.",
        common_fixes = {
            "Check array indices against buffer size.",
            "Avoid unbounded string operations on stack buffers.",
            "Use snprintf instead of sprintf.",
        },
    },
    ["signal-unsafe-call"] = {
        title = "Signal-Unsafe Call in Signal Handler",
        description = "A function that is not async-signal-safe was called from a signal handler.",
        common_fixes = {
            "Only call async-signal-safe functions in signal handlers.",
            "Set a flag in the handler and act on it in the main loop.",
            "Use sigaction with SA_RESTART where appropriate.",
        },
    },
}

-- Sanitizer "data-race" is the same explanation as Helgrind "Race".
M["data-race"] = M.Race

return M
