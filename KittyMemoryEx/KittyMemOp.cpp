#include "KittyMemOp.hpp"
#include <cerrno>
#include <filesystem>
#include <regex>
#include <fstream>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

// process_vm_readv & process_vm_writev
#if defined(__aarch64__)
#define syscall_rpmv_n 270
#define syscall_wpmv_n 271
#elif defined(__arm__)
#define syscall_rpmv_n 376
#define syscall_wpmv_n 377
#elif defined(__i386__)
#define syscall_rpmv_n 347
#define syscall_wpmv_n 348
#elif defined(__x86_64__)
#define syscall_rpmv_n 310
#define syscall_wpmv_n 311
#else
#error "Unsupported ABI"
#endif

static ssize_t call_process_vm_readv(pid_t pid,
                                     const iovec *lvec, unsigned long liovcnt,
                                     const iovec *rvec, unsigned long riovcnt,
                                     unsigned long flags)
{
    return syscall(syscall_rpmv_n, pid, lvec, liovcnt, rvec, riovcnt, flags);
}

static ssize_t call_process_vm_writev(pid_t pid,
                                      const iovec *lvec, unsigned long liovcnt,
                                      const iovec *rvec, unsigned long riovcnt,
                                      unsigned long flags)
{
    return syscall(syscall_wpmv_n, pid, lvec, liovcnt, rvec, riovcnt, flags);
}

/* =================== IKittyMemOp =================== */

std::string IKittyMemOp::ReadStr(uintptr_t address, size_t maxLen)
{
    std::vector<char> chars(maxLen);

    if (!Read(address, &chars[0], maxLen))
        return "";

    std::string str = "";
    for (size_t i = 0; i < chars.size(); i++)
    {
        if (chars[i] == '\0')
            break;

        str.push_back(chars[i]);
    }

    if ((int)str[0] == 0 && str.size() == 1)
        return "";

    return str;
}

bool IKittyMemOp::WriteStr(uintptr_t address, std::string str)
{
    size_t len = str.length() + 1; // extra for \0;
    return Write(address, &str[0], len) == len;
}

/* =================== KittyMemSys =================== */

bool KittyMemSys::init(pid_t pid)
{
    if (pid < 1)
    {
        KITTY_LOGE("KittyMemSys: Invalid PID.");
        return false;
    }

    errno = 0;
    ssize_t rt = syscall(syscall_rpmv_n, 0, 0, 0, 0, 0, 0);
    if (rt == -1 && errno == ENOSYS)
    {
        KITTY_LOGE("KittyMemSys: syscall not supported.");
        return false;
    }

    _pid = pid;
    return true;
}

size_t KittyMemSys::Read(uintptr_t address, void *buffer, size_t len) const
{
    if (_pid < 1 || !address || !buffer || !len)
        return 0;

    struct iovec lvec { .iov_base = buffer, .iov_len = 0 };
    struct iovec rvec { .iov_base = reinterpret_cast<void*>(address), .iov_len = 0 };

    ssize_t n = 0;
    size_t bytes_read = 0, remaining = len;
    bool read_one_page = false;
    do {
        size_t remaining_or_pglen = remaining;
        if (read_one_page)
            remaining_or_pglen = std::min(KT_PAGE_LEN(rvec.iov_base), remaining);

        lvec.iov_len = remaining_or_pglen;
        rvec.iov_len = remaining_or_pglen;

        errno = 0;
        n = KT_EINTR_RETRY(call_process_vm_readv(_pid, &lvec, 1, &rvec, 1, 0));
        if (n > 0)
        {
            remaining -= n;
            bytes_read += n;
            lvec.iov_base = reinterpret_cast<char*>(lvec.iov_base) + n;
            rvec.iov_base = reinterpret_cast<char*>(rvec.iov_base) + n;
        }
        else
        {
            if (n == -1)
            {
                int err = errno;
                switch (err)
                {
                case EPERM:
                    KITTY_LOGE("Failed vm_readv(%p + %p, %p) | Can't access the address space of process ID (%d).",
                        (void*)address, (void*)(uintptr_t(rvec.iov_base) - address), (void*)rvec.iov_len, _pid);
                    break;
                case ESRCH:
                    KITTY_LOGE("Failed vm_readv(%p + %p, %p) | No process with ID (%d) exists.",
                        (void*)address, (void*)(uintptr_t(rvec.iov_base) - address), (void*)rvec.iov_len, _pid);
                    break;
                case ENOMEM:
                    KITTY_LOGE("Failed vm_readv(%p + %p, %p) | Could not allocate memory for internal copies of the iovec structures.",
                        (void*)address, (void*)(uintptr_t(rvec.iov_base) - address), (void*)rvec.iov_len);
                    break;
                default:
                    KITTY_LOGD("Failed vm_readv(%p + %p, %p) | error(%d): %s.",
                        (void*)address, (void*)(uintptr_t(rvec.iov_base) - address), (void*)rvec.iov_len, err, strerror(err));
                }
            }
            if (read_one_page)
            {
                remaining -= remaining_or_pglen;
                lvec.iov_base = reinterpret_cast<char*>(lvec.iov_base) + remaining_or_pglen;
                rvec.iov_base = reinterpret_cast<char*>(rvec.iov_base) + remaining_or_pglen;
            }
        }
        read_one_page = n == -1 || size_t(n) != remaining_or_pglen;
    } while (remaining > 0);
    return bytes_read;
}

size_t KittyMemSys::Write(uintptr_t address, void *buffer, size_t len) const
{
    if (_pid < 1 || !address || !buffer || !len)
        return 0;

    struct iovec lvec { .iov_base = buffer, .iov_len = 0 };
    struct iovec rvec { .iov_base = reinterpret_cast<void*>(address), .iov_len = 0 };

    ssize_t n = 0;
    size_t bytes_written = 0, remaining = len;
    bool write_one_page = false;
    do {
        size_t remaining_or_pglen = remaining;
        if (write_one_page)
            remaining_or_pglen = std::min(KT_PAGE_LEN(rvec.iov_base), remaining);

        lvec.iov_len = remaining_or_pglen;
        rvec.iov_len = remaining_or_pglen;

        errno = 0;
        n = KT_EINTR_RETRY(call_process_vm_writev(_pid, &lvec, 1, &rvec, 1, 0));
        if (n > 0)
        {
            remaining -= n;
            bytes_written += n;
            lvec.iov_base = reinterpret_cast<char*>(lvec.iov_base) + n;
            rvec.iov_base = reinterpret_cast<char*>(rvec.iov_base) + n;
        }
        else
        {
            if (n == -1)
            {
                int err = errno;
                switch (err)
                {
                case EPERM:
                    KITTY_LOGE("Failed vm_writev(%p + %p, %p) | Can't access the address space of process ID (%d).",
                        (void*)address, (void*)(uintptr_t(rvec.iov_base) - address), (void*)rvec.iov_len, _pid);
                    break;
                case ESRCH:
                    KITTY_LOGE("Failed vm_writev(%p + %p, %p) | No process with ID (%d) exists.",
                        (void*)address, (void*)(uintptr_t(rvec.iov_base) - address), (void*)rvec.iov_len, _pid);
                    break;
                case ENOMEM:
                    KITTY_LOGE("Failed vm_writev(%p + %p, %p) | Could not allocate memory for internal copies of the iovec structures.",
                        (void*)address, (void*)(uintptr_t(rvec.iov_base) - address), (void*)rvec.iov_len);
                    break;
                default:
                    KITTY_LOGD("Failed vm_writev(%p + %p, %p) | error(%d): %s.",
                        (void*)address, (void*)(uintptr_t(rvec.iov_base) - address), (void*)rvec.iov_len, err, strerror(err));
                }
            }
            if (write_one_page)
            {
                remaining -= remaining_or_pglen;
                lvec.iov_base = reinterpret_cast<char*>(lvec.iov_base) + remaining_or_pglen;
                rvec.iov_base = reinterpret_cast<char*>(rvec.iov_base) + remaining_or_pglen;
            }
        }
        write_one_page = n == -1 || size_t(n) != remaining_or_pglen;
    } while (remaining > 0);
    return bytes_written;
}

/* =================== KittyMemIO =================== */

bool KittyMemIO::init(pid_t pid)
{
    if (pid < 1)
    {
        KITTY_LOGE("KittyMemIO: Invalid PID.");
        return false;
    }

    _pid = pid;

    char memPath[256] = {0};
    snprintf(memPath, sizeof(memPath), "/proc/%d/mem", _pid);
    _pMem = std::make_unique<KittyIOFile>(memPath, O_RDWR);
    if (!_pMem->Open())
    {
        KITTY_LOGE("Couldn't open mem file %s, error=%s", _pMem->Path().c_str(), _pMem->lastStrError().c_str());
        return false;
    }

    return _pid > 0 && _pMem.get();
}

size_t KittyMemIO::Read(uintptr_t address, void *buffer, size_t len) const
{
    if (_pid < 1 || !address || !buffer || !len || !_pMem.get())
        return 0;

    ssize_t bytes = _pMem->Read(address, buffer, len);
    return bytes > 0 ? bytes : 0;
}

size_t KittyMemIO::Write(uintptr_t address, void *buffer, size_t len) const
{
    if (_pid < 1 || !address || !buffer || !len || !_pMem.get())
        return 0;

    ssize_t bytes = _pMem->Write(address, buffer, len);
    return bytes > 0 ? bytes : 0;
}

/* =================== KittyMemKernel =================== */

int KittyMemKernel::symbol_file(const char *filename)
{
    //Determine whether the file name contains lowercase and does not contain uppercase letters, numbers, or symbols.
    int length = strlen(filename);
    for (int i = 1; i < length; i++) {
        if (islower(filename[i])) {
            has_lower = 1;
        } else if (isupper(filename[i])) {
            has_upper = 1;
        } else if (ispunct(filename[i])) {
            has_symbol = 1;
        } else if (isdigit(filename[i])) {
            has_digit = 1;
        }
    }
    return has_lower && !has_upper && !has_symbol && !has_digit;
}

bool KittyMemKernel::symbol_file_ql(const char *filename)
{
    //Determine whether the file name contains lowercase and does not contain uppercase letters, numbers, or symbols.
    int length = strlen(filename);
    for (int i = 0; i < length; i++) {
        if (islower(filename[i])) {
            has_lower = 1;
        } else if (isupper(filename[i])) {
            has_upper = 1;
        } else if (ispunct(filename[i])) {
            has_symbol = 1;
        } else if (isdigit(filename[i])) {
            has_digit = 1;
        }
    }
    if (has_symbol) return false;
    return has_lower || has_upper || has_digit;
}

bool isLowercaseOnly(const std::string& str) {
    return std::all_of(str.begin(), str.end(), [](char c) { return std::islower(c); });
}

bool isUppercaseOnly(const std::string& str) {
    return std::all_of(str.begin(), str.end(), [](char c) { return std::isupper(c); });
}

const char *execlude[] = {"stdin","stdout", "stderr", "fscklogs", "input", "ptmx", "socket", "ttyHS0", "console",
        "camlog", "mbraink", "snapshot", "userfaultfd", "ashmem", "vsock", "binder", "nanohub", "SUB2AF",
        "ipaIpv6CTTable", "fs15xx", "connfem"
};

char *KittyMemKernel::driver_path()
{
    const char *dev_path = "/dev";
	DIR *dir = opendir(dev_path);
	if (dir == NULL){
		printf("Unable to open /dev directory\n");
	    return NULL;
	}
    
   const char *files[] = { "wanbai", "CheckMe", "Ckanri", "lanran","video188"};
    int files_length = (sizeof files / sizeof files[0]);
    struct dirent *entry;
    char *file_path = NULL;
    
    while ((entry = readdir(dir)) != NULL)
    {
        //printf("- %s\n", entry->d_name);
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0
        || strcmp(entry->d_name, "tty") == 0 || strcmp(entry->d_name, "video188") == 0
        || strcmp(entry->d_name, "watchdog") == 0 || strcmp(entry->d_name, "zero") == 0)
        {
            //printf("a %s\n", entry->d_name);
            continue;
        }
        bool fail = false;
        for (auto ss : execlude) {
            if (strcmp(entry->d_name, ss) == 0) {
                fail = true;
                break;
            }
        }
        if (fail) {
           // printf("b %s\n", entry->d_name);
            continue;
        } 
        
        int lowercase_only = 1;
		int uppercase_only = 1;
        int length = strlen(entry->d_name);
        for (int i = 1; i < length; i++) {
            if (isupper(entry->d_name[i])) {
                //Determine whether the file name contains uppercase letters
                lowercase_only = 0;
            }
            if (islower(entry->d_name[i])) {
                //Determine whether the file name contains lowercase letters
                uppercase_only = 0;
            }
        }
        if (!lowercase_only || uppercase_only)
        {
            //printf("c %s\n", entry->d_name);
            continue;
        } 
        
        size_t path_length = strlen(dev_path) + strlen(entry->d_name) + 2;
        file_path = (char *)malloc(path_length);
        snprintf(file_path, path_length, "%s/%s", dev_path, entry->d_name);
        
        for (int i = 0; i < files_length; i++) {
            if (strcmp(entry->d_name, files[i]) == 0) {
                closedir(dir);
                return file_path;
            }
        }
        
        // Get file stat structure
        struct stat file_info;
        if (stat(file_path, &file_info) < 0) {
            free(file_path);
            file_path = NULL;
            //printf("d %s\n", entry->d_name);
            continue;
        } 
        
        // skip gpio interface
        if (strstr(entry->d_name, "watchdog") != NULL || strstr(entry->d_name, "video") != NULL
        || strstr(entry->d_name, "gpiochip") != NULL || strstr(entry->d_name, "wlan") != NULL
        || strstr(entry->d_name, "wl2868") != NULL || strstr(entry->d_name, "remoteproc") != NULL
        || strstr(entry->d_name, "binder") != NULL || strstr(entry->d_name, "tty") != NULL
        || strstr(entry->d_name, "ptyp") != NULL || strstr(entry->d_name, "mmcblk") != NULL
        || strstr(entry->d_name, "rpmb") != NULL || strstr(entry->d_name, "ionfd") != NULL
        || strstr(entry->d_name, "ipaIpv") != NULL || strstr(entry->d_name, "stpgp") != NULL
        )
        {
            free(file_path);
            file_path = NULL;
           // printf("e %s\n", entry->d_name);
            continue;
        } 
        
        // Check if it is a driver file
        if ((S_ISCHR(file_info.st_mode) || S_ISBLK(file_info.st_mode))
            && strchr(entry->d_name, '_') == NULL && strchr(entry->d_name, '-') == NULL && strchr(entry->d_name, ':') == NULL)
        {
            // Filter standard input and output
            if (strcmp(entry->d_name, "stdin") == 0 || strcmp(entry->d_name, "stdout") == 0 || strcmp(entry->d_name, "stderr") == 0) {
                free(file_path);
                file_path = NULL;
               // printf("f %s\n", entry->d_name);
                continue;
            } 
			
            size_t file_name_length = strlen(entry->d_name);
            
            time_t current_time;
            time(&current_time);
            auto current_year = localtime(&current_time)->tm_year + 1900;
            auto file_year = localtime(&file_info.st_ctime)->tm_year + 1900;
            if (file_year < current_year || file_year == 1970) {
                free(file_path);
                file_path = NULL;
               // printf("g %s\n", entry->d_name);
                continue;
            }
            
            time_t atime = file_info.st_atime;
            time_t ctime = file_info.st_ctime;
            // Check whether the last access time and modification time are consistent and whether the file name is a symbol file
            if (atime == ctime && isLowercaseOnly({entry->d_name+1})) {
                //Check whether the mode permission type is S_IFREG (ordinary file) and the size, gid and uid are 0 (root) and the file name length is 7 characters or less.
                if ((file_info.st_mode & S_IFMT) == 8192 && file_info.st_size == 0
                  && file_info.st_gid == 0 && file_info.st_uid == 0 && file_name_length <= 7) {
                    closedir(dir);
                    return file_path;
                }
            }
        }
        free(file_path);
        file_path = NULL;
    }
    closedir(dir);
    return NULL; 
}

char *KittyMemKernel::driver_qx10()
{
    const char* command = "dir=$(ls -l /proc/*/exe 2>/dev/null | grep -E '/data/[^/]* \\(deleted\\)' | sed 's/ /\\n/g' | grep '/proc' | sed 's/\\/[^/]*$//g');if [[ \"$dir\" ]]; then sbwj=$(head -n 1 \"$dir/comm\");open_file=\"\";for file in \"$dir\"/fd/*; do link=$(readlink \"$file\");if [[ \"$link\" == \"/dev/$sbwj (deleted)\" ]]; then open_file=\"$file\";break;fi;done;if [[ -n \"$open_file\" ]]; then nhjd=$(echo \"$open_file\");sbid=$(ls -L -l \"$nhjd\" | sed 's/\\([^,]*\\).*/\\1/' | sed 's/.*root //');echo \"/dev/$sbwj\";rm -rf \"/dev/$sbwj\";mknod \"/dev/$sbwj\" c \"$sbid\" 0;fi;fi;";
    FILE* file = popen(command, "r");
    if (file == NULL) {
       	return NULL;
    }
    static char result[512];
    if (fgets(result, sizeof(result), file) == NULL) {
		return NULL;
	}
    pclose(file);
    result[strlen(result)-1] = '\0';
	return result;
}

void KittyMemKernel::driver_ql()
{
    const char *dev_path = "/dev";
	DIR *dir = opendir(dev_path);
	if (dir == NULL){
		printf("Unable to open /dev directory\n");
	    return;
	}
    
    struct dirent *entry;
    char *file_path = NULL;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0
        || strcmp(entry->d_name, "tty") == 0 || strcmp(entry->d_name, "video188") == 0
        || strcmp(entry->d_name, "watchdog") == 0 || strcmp(entry->d_name, "zero") == 0)
            continue;
            
        if (strstr(entry->d_name, "watchdog") != NULL || strstr(entry->d_name, "video") != NULL
        || strstr(entry->d_name, "gpiochip") != NULL || strstr(entry->d_name, "wlan") != NULL
        || strstr(entry->d_name, "wl2868") != NULL || strstr(entry->d_name, "remoteproc") != NULL
        || strstr(entry->d_name, "binder") != NULL || strstr(entry->d_name, "tty") != NULL
        || strstr(entry->d_name, "ptyp") != NULL || strstr(entry->d_name, "mmcblk") != NULL
        || strstr(entry->d_name, "rpmb") != NULL || strstr(entry->d_name, "ionfd") != NULL
        || strstr(entry->d_name, "ipaIpv") != NULL || strstr(entry->d_name, "stpgp") != NULL
        )
            continue;
            
        bool fail = false;
        for (auto ss : execlude) {
            if (strcmp(entry->d_name, ss) == 0) {
                fail = true;
                break;
            }
        }
        if (fail) continue;
        
        std::string path = "/dev/";
        path += entry->d_name;
        
        if (path.length() < 10) continue;
        
        if (isLowercaseOnly({entry->d_name}))
            continue;
        if (isUppercaseOnly({entry->d_name}))
            continue;
        
        struct stat file_stat;
        if (stat(path.c_str(), &file_stat) == -1) {
            perror("lstat");
            continue;
        }
        
        if (!S_ISCHR(file_stat.st_mode) ||
             file_stat.st_atime != file_stat.st_ctime ||
             strchr(entry->d_name, '_') != NULL ||
             strchr(entry->d_name, '-') != NULL ||
             strchr(entry->d_name, ':') != NULL)
         continue;
        
        time_t current_time;
        time(&current_time);
        auto current_year = localtime(&current_time)->tm_year + 1900;
        auto file_year = localtime(&file_stat.st_ctime)->tm_year + 1900;
        if (file_year < current_year || file_year == 1970)
            continue;
            
        if (!symbol_file_ql(entry->d_name) ||
            (file_stat.st_mode & S_IFMT) != 8192 ||
            file_stat.st_size != 0 || file_stat.st_gid != 0 ||
            file_stat.st_uid != 0)
            continue;
        
        if (isLowercaseOnly(path))
            continue;
        
        this->kdriver_path = path;
        if (show_log) printf("%s\n",path.c_str());
        //break;
    }
    
    if (!this->kdriver_path.empty()) {
        this->fd = open(this->kdriver_path.c_str(), O_RDWR);
        if (fd <= 0) {
            if (this->show_log) printf("[-] Driver link startup fail\n");
        }
    }
    
    closedir(dir);
}

namespace fs = std::filesystem;
std::string read_symlink(const fs::path& p) {
    try {
        return fs::read_symlink(p).string();
    } catch (const fs::filesystem_error& e) {
        return "";
    }
}

std::string Exec(const char *cmd, bool logs = true) {
   std::string res;
   FILE *pipe = popen(cmd, "r");
   if (pipe == nullptr) {
       if (logs) printf("ERROR: %s\n", cmd);
       return res;
   }
   char line[512];
   while (fgets(line,sizeof line, pipe))
       res += std::string(line);
   pclose(pipe);
   return res;
}

void create_driver_node(const char *path, int major_number, int minor_number)
{
    char cmd[512]{0};
    sprintf(cmd, "mknod %s c %d %d", path, major_number, minor_number);
    Exec(cmd);
    //printf("[-] Create %s\n", path, major_number, minor_number);
}

void remove_driver_node(const char *path)
{
    if (unlink(path) == 0) {
        printf("[-] Driver security guard is activated\n");
    } else {
        printf("[-] Driver security guard execution error\n");
    }
}


void KittyMemKernel::driver_path_plus() {
    std::regex deleted_regex("/data/[a-z]{6} \\(deleted\\)");
    std::string filePath = "/dev/";
    std::string nodename;
    pid_t pid = -1;
    bool found = false;

    for (const auto& entry : fs::directory_iterator("/proc")) {
        if (entry.is_directory()) {
            std::string proc_path = entry.path().string();
            std::string exe_path = proc_path + "/exe";
            
            std::string symlink_target = read_symlink(exe_path);
            if (symlink_target.empty()) continue;
            
            std::smatch match;
            if (std::regex_search(symlink_target, match, deleted_regex)) {
                std::string pid_str = entry.path().filename().string();
                
                pid = (pid_t)std::stoi(pid_str);
                
                size_t start_pos = symlink_target.rfind('/') + 1;
                if (start_pos == std::string::npos)
                    break;
                
                size_t end_pos = symlink_target.find(' ', start_pos);
                if (end_pos == std::string::npos)
                    break;
                    
                filePath += symlink_target.substr(start_pos, end_pos - start_pos);
                nodename = symlink_target.substr(start_pos, end_pos - start_pos);
                found = true;
                break;
            }
        }
    }

    if (found) {
        this->driver_pid = pid;
        
        char sfd[128]{0};
        sprintf(sfd, "/proc/%d/fd/3", pid);
        if (access(sfd, F_OK) == 0)
        {
            char cmd[256]{0};
            sprintf(cmd, "ls -al -L %s", sfd);
            auto fdInfo = Exec(cmd);
            int major_number, minor_number;
            sscanf(fdInfo.c_str(), "%*s %*d %*s %*s %d, %d", &major_number, &minor_number);
            if (filePath[0] != 0) {
                create_driver_node(filePath.c_str(), major_number, minor_number);
                sleep(1);
                this->fd = open(filePath.c_str(), O_RDWR);
                if (fd <= -1) {
                    printf("[-] Driver link startup fail\n");
                }
                this->kdriver_path = filePath;
                if (this->show_log) printf("[-] Driver loaded successfully：%s\n", filePath.c_str());
                remove_driver_node(filePath.c_str());
            }
        }
        else
        {
            std::string dp = "/proc/" + nodename;
            this->fd = open(dp.c_str(), O_RDWR);
            this->kdriver_path = dp;
        }   
    }
}

static KittyMemKernel::COPY_MEMORY cm;

bool KittyMemKernel::init(pid_t pid)
{
    this->_pid = pid;
    this->fd = -1;
    this->show_log = true;
    bool gt=false;
    driver_ql();
    if (fd <= 0) {
        gt = false;
        char *device_name = driver_path();
        if (device_name != NULL)
        {
            fd = open(device_name, O_RDWR);
            free(device_name);
            if (fd <= 0) {
                printf("[-] Failed to open driver %s QX\n", device_name);
                return false;
            } else {
                this->kdriver_path = device_name;
            }
        }
    } else {
        gt = true;
    }
    if (fd <= 0) {
        driver_path_plus();
        if (fd <= 0) {
            printf("[-] Failed to find driver %s *\n", this->kdriver_path.c_str());
            return false;
        } else
           gt = false;
    }
    if (show_log) printf("Driver file: %s %s\n", this->kdriver_path.c_str(), gt?"GT":"QX");
    return this->fd > 0 && this->_pid > 0;
}

bool KittyMemKernel::internal_read(uintptr_t addr, void *buffer, size_t size) const {
    auto oadr = addr;
    if ((addr & 0xFF00000000000000) > 0x0) {
        addr = addr & 0xFFFFFFFFFF;
    }
    memset((void*)&cm, 0, sizeof(COPY_MEMORY));
    cm.pid = this->_pid;
    cm.addr = addr;
    cm.buffer = buffer;
    cm.size = size;
    if (ioctl(fd, OP_READ_MEM, &cm) != 0) {
        printf("kernel fail read %p\n", (void*)addr);
        return false;
    }
	return true;
}

bool KittyMemKernel::internal_write(uintptr_t addr, void *buffer, size_t size) const {
    if ((addr & 0xFF00000000000000) > 0x0) {
        addr = addr & 0xFFFFFFFFFF;
    }
	memset((void*)&cm, 0, sizeof(COPY_MEMORY));
	cm.pid = this->_pid;
	cm.addr = addr;
	cm.buffer = buffer;
	cm.size = size;
	if (ioctl(fd, OP_WRITE_MEM, &cm) != 0) {
        printf("kernel fail write %p\n", (void*)addr);
		return false;
	}
    return true;
}

size_t KittyMemKernel::Read(uintptr_t address, void *buffer, size_t len) const
{
    if (_pid < 1 || !address || !buffer || !len)
        return 0;

    bool ok = internal_read(address, buffer, len);
    return ok ? len : 0;
}

size_t KittyMemKernel::Write(uintptr_t address, void *buffer, size_t len) const
{
    if (_pid < 1 || !address || !buffer || !len)
        return 0;

    bool ok = internal_write(address, buffer, len);
    return ok ? len : 0;
}
