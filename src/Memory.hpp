#pragma once

#include <cstdint>
#include <cstring>
#include <type_traits>

struct MemorySectionType
{
    enum Enum
    {
        Text,
        Data,
        RData,
        EnumCount
    };
};

struct MemorySection
{
    uintptr_t offset = -1;
    uintptr_t size = -1;
};

struct MemoryData
{
    uintptr_t base_addr;
    MemorySection sections[3];
};

struct Hook
{
    const char* name;
    void* from;
    void* to;
    void* orig;

    Hook(const char* name_, void* from_, void* to_);
    ~Hook();
 
    Hook() = delete;
    Hook(const Hook& rhs) = delete;
    Hook(Hook&& rhs) = default;

    template <typename Ret, typename... Args>
    Ret call_original(Args ... args)
    {
        using FuncPtr = Ret(*)(Args...);
        FuncPtr fn = (FuncPtr)orig;
        return fn(args...);
    }
};

MemoryData mem_init();

bool mem_hook(const char* name, void* address, void* new_address, void** call_original_addr);
void mem_hook_free(const char* name, void* address);

uintptr_t mem_scan(const MemoryData* mem, const char* signature, const MemorySectionType::Enum section);
uintptr_t mem_ida_addr(const MemoryData* mem, const uintptr_t addr);
uintptr_t mem_resolve(const uintptr_t instruction);

template <typename T = uint32_t>
uintptr_t mem_rel_operand(const MemoryData* mem, const uintptr_t text_addr)
{
    const MemorySection& data = mem->sections[MemorySectionType::Data];
    const MemorySection& rdata = mem->sections[MemorySectionType::RData];

    static constexpr uintptr_t MAX_INST_LEN = 4;
    for (uintptr_t i = 0; i < MAX_INST_LEN; ++i)
    {
        // This is the value of the assembly...
        const uintptr_t operand = mem_read<T>(text_addr + i);

        // The resolved address is the full address, plus the number of bytes we have skipped, plus the size of the operand, plus the offset
        const uintptr_t resolved_addr = text_addr + i + sizeof(T) + operand;

        // Now check if the offset (resolved address minus base address) falls in either data or rdata.
        // To find this offset in IDA, it's the base address + the offset_addr; the base is usually 0x140000000
        if (const uintptr_t offset_addr = resolved_addr - mem->base_addr;
            (offset_addr >= data.offset && offset_addr < data.offset + data.size) ||
            (offset_addr >= rdata.offset && offset_addr < rdata.offset + rdata.size))
        {
            return resolved_addr;
        }
    }

    return 0;
}

template <typename T>
T mem_read(uintptr_t address, uintptr_t offset = 0)
{
    static_assert(std::is_trivially_copyable<T>::value);
    T data;
    memcpy(&data, (void*)(address + offset), sizeof(T));
    return data;
}

inline void* mem_step(void* addr, const uintptr_t offset)
{
    return (void*)((uintptr_t)addr + offset);
}
