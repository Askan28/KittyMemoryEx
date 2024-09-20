#pragma once

#include "KittyUtils.hpp"
#include "KittyIOFile.hpp"

enum EKittyMemOP
{
    EK_MEM_OP_NONE = 0,
    EK_MEM_OP_SYSCALL,
    EK_MEM_OP_IO,
    EK_MEM_OP_KERNEL
};

class IKittyMemOp
{
protected:
    pid_t _pid;

public:
    IKittyMemOp() : _pid(0) {}
    virtual ~IKittyMemOp() = default;

    virtual bool init(pid_t pid) = 0;

    inline pid_t processID() const { return _pid; }

    virtual size_t Read(uintptr_t address, void *buffer, size_t len) const = 0;
    virtual size_t Write(uintptr_t address, void *buffer, size_t len) const = 0;

    std::string ReadStr(uintptr_t address, size_t maxLen);
    bool WriteStr(uintptr_t address, std::string str);
};

class KittyMemSys : public IKittyMemOp
{
public:
    bool init(pid_t pid);

    size_t Read(uintptr_t address, void *buffer, size_t len) const;
    size_t Write(uintptr_t address, void *buffer, size_t len) const;
};

class KittyMemIO : public IKittyMemOp
{
private:
    std::unique_ptr<KittyIOFile> _pMem;

public:
    bool init(pid_t pid);

    size_t Read(uintptr_t address, void *buffer, size_t len) const;
    size_t Write(uintptr_t address, void *buffer, size_t len) const;
};

class KittyMemKernel : public IKittyMemOp
{
public:
    enum OPERATIONS {
		OP_INIT_KEY = 0x800,
		OP_READ_MEM = 0x801,
		OP_WRITE_MEM = 0x802,
		OP_MODULE_BASE = 0x803,
	};

    typedef struct _COPY_MEMORY {
		pid_t pid;
		uintptr_t addr;
		void* buffer;
		size_t size;
	} COPY_MEMORY, *PCOPY_MEMORY;

	typedef struct _MODULE_BASE {
		pid_t pid;
		char* name;
		uintptr_t base;
	} MODULE_BASE, *PMODULE_BASE;
private:
    int has_upper = 0;
	int has_lower = 0;
	int has_symbol = 0;
	int has_digit = 0;
	int fd;
    pid_t driver_pid;
    bool show_log;
    std::string kdriver_path;

    int symbol_file(const char *filename);
    bool symbol_file_ql(const char *filename);
    char *driver_path();
    char *driver_qx10();
    void driver_path_plus();
    void driver_ql();

public:
    bool init(pid_t pid);

    bool internal_read(uintptr_t addr, void *buffer, size_t size) const;
    bool internal_write(uintptr_t addr, void *buffer, size_t size) const;

    size_t Read(uintptr_t address, void *buffer, size_t len) const;
    size_t Write(uintptr_t address, void *buffer, size_t len) const;
};