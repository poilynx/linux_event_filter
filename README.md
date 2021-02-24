# ptrace #

`ptrace(2)` 用于Linux进程调试机制，它可以通过fork或者进程绑定追踪一个进程的所有系统调用。

```c
#include <sys/ptrace.h>

long ptrace(enum __ptrace_request request, pid_t pid,
		void *addr, void *data);
```

Tracer 通过调用`ptrace(2)`并传递`PTRACE_SYSCALL`，可以使Tracee在每个系统调用开始和结束处中断执行，并向Tracer发送SIGTRAP信号，所以对于每个系统调用，Tracer需要使用如下方式接收远程进程信息并控制其继续执行：

```c
/* regs 用于保存系统调用寄存器状态 */
struct user_regs_struct regs;

/* 通知被调试进程在下一个SYSCALL开始处中断，并等待SIGTRAP */
ptrace(PTRACE_SYSCALL, pid, 0, 0);
waitpid(pid, 0, 0);

/* 读取寄存器 */
ptrace(PTRACE_GETREGS, pid, 0, &regs);
long syscall = regs.orig_rax;

fprintf(stderr, "%ld(%ld, %ld, %ld, %ld, %ld, %ld)", syscall,
		(long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
		(long)regs.r10, (long)regs.r8,  (long)regs.r9);

/* 通知被调试进程在下一个SYSCALL结束处中断，并等待SIGTRAP */
ptrace(PTRACE_SYSCALL, pid, 0, 0);
waitpid(pid, 0, 0);

/* 读取寄存器 */
ptrace(PTRACE_GETREGS, pid, 0, &regs);

/* rax 为系统调用的返回值 */
fprintf(stderr, " = %ld\n", (long)regs.rax);

```

**优点**

1. ptrace可以对一个进程做到指令级别的精细控制
2. 追踪的覆盖范围广，能拦截所有系统调用
3. 可以任意读写进程虚拟内存空间
4. 可以对进程注入动态链接库

**缺点**

1. 只针对单个进程，不适用于全局挂钩
2. 只能追踪全部系统调用，不能针对性的追踪
3. 对单个系统调用进行追踪，追踪进程需要多次陷入内核，性能不佳
2. 进程被ptrace后，无法使用GDB对其进行调试

# Audit #

Audit 是 Linux 的操作系统审计机制，它使用LSM实现，通过内核开启 `CONFIG_AUDIT` 配置宏来支持审计功能，并通过 `NETLINK_AUDIT` 来支持与用户空间的通信

Audit 包含一组命令行工具和守护进程

```
auditd	 守护进程，用于读取NetLink，并写入/var/log/audit/audit.log
auditctl 添加和删除过滤规则
autrace  类似于strace，通过添加所有系统调用和指定pid过滤规则，监视系统调用并写入log
libaudit 对NetLink通信的lib封装，用于对规则的增删查操作以及系统审计日志的接受
```

Audit 理论上支持所有系统调用的监控，支持逻辑上的三种规则
1. 系统调用监控，可以获取系统调用的四个输入参数和返回值
2. 文件监控(基于1)，把文件相关的系调用加入规则，包括文件和文件夹的打开、关闭、读写、权限访问等
3. 任务监控(基于1)，把进程控制相关的系调用加入规则，包括进程启动、信号传递、管道通信等

案例

监控execve系统调用，在`/tmp`目录执行`whoami(1)`可以获取7条审计记录

```
event: Type=SYSCALL Message=audit(1614135765.782:3290812): arch=c000003e syscall=59 success=yes exit=0 a0=555be04fdc50 a1=555be04fda70 a2=555be0557780 a3=fffffffffffff878 items=2 ppid=3390 pid=8847 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts2 ses=77 comm="whoami" exe="/usr/bin/whoami" subj==unconfined key=(null)

event: Type=EXECVE Message=audit(1614135765.782:3290812): argc=1 a0="whoami"

event: Type=CWD Message=audit(1614135765.782:3290812): cwd="/tmp"

event: Type=PATH Message=audit(1614135765.782:3290812): item=0 name="/usr/bin/whoami" inode=263283 dev=08:05 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0

event: Type=PATH Message=audit(1614135765.782:3290812): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=790725 dev=08:05 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0

event: Type=PROCTITLE Message=audit(1614135765.782:3290812): proctitle="whoami"

event: Type=EOE Message=audit(1614135765.782:3290812): 
```

监控mkdir系统调用，在`/tmp`目录执行`cat foo`可以获取6条审计日志

```
event: Type=SYSCALL Message=audit(1614135991.614:3290850): arch=c000003e syscall=83 success=yes exit=0 a0=7ffdcd3c545f a1=1ff a2=0 a3=fffffffffffff35a items=2 ppid=3390 pid=8907 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts2 ses=77 comm="mkdir" exe="/usr/bin/mkdir" subj==unconfined key=(null)

event: Type=CWD Message=audit(1614135991.614:3290850): cwd="/tmp"

event: Type=PATH Message=audit(1614135991.614:3290850): item=0 name="/tmp" inode=786433 dev=08:05 mode=041777 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0

event: Type=PATH Message=audit(1614135991.614:3290850): item=1 name="foo" inode=924807 dev=08:05 mode=040755 ouid=1000 ogid=1000 rdev=00:00 nametype=CREATE cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0

event: Type=PROCTITLE Message=audit(1614135991.614:3290850): proctitle=6D6B64697200666F6F

event: Type=EOE Message=audit(1614135991.614:3290850): 
```

**优点**

1. 支持对系统调用的监控，监控点类型覆盖范围广
2. 支持系统全局范围监控，监控面覆盖范围广

**缺点**

1. 不支持拦截
2. 只支持单个进程读取审计记录，默认是auditd，如果由第三方接管，则auditd服务则不能工作
3. 审计记录数据量过大处理不及时可能会导致记录丢失（NETLINK限制）
4. 任意进程都可以通过 `NETLINK` 查询和修改 审计规则

# FANOTIFY #

fanotify 用于替换 inotify，它专门设计用于防病毒软件

fanotify 支持文件系统和进程加载的事件通知和**拦截**，它的监控范围包括挂在点全局监控、文件夹己其直接子监控、单个文件监控

监控能力：

```
FAN_ACCESS 文件读取

FAN_MODIFY 文件写入

FAN_CLOSE_WRITE 关闭写描述符

FAN_CLOSE_NOWRITE 关闭读描述符

FAN_OPEN 文件打开

FAN_OPEN_EXEC (since Linux 5.0) 文件执行

FAN_ATTRIB (since Linux 5.1) metadata

FAN_CREATE (since Linux 5.1) 新文件添加

FAN_DELETE (since Linux 5.1) 子文件删除

FAN_DELETE_SELF (since Linux 5.1) 标记点的删除

FAN_MOVED_FROM (since Linux 5.1) 从哪里来

FAN_MOVED_TO (since Linux 5.1) 到哪里去

FAN_MOVE_SELF (since Linux 5.1) 标记点的移动

FAN_OPEN_PERM 文件打开拦截

FAN_OPEN_EXEC_PERM (since Linux 5.0) 文件执行拦截

FAN_ACCESS_PERM 文件读取拦截

FAN_ONDIR opendir readdir监控

FAN_EVENT_ON_CHILD 直接子的监控
```

**优点**

1. 全面支持文件监控和进程监控
2. 支持对进程和文件访问的拦截能力
3. 高性能的全局监控能力

**缺点**

1. 进程监控能力 对内核版本要求过高
2. 文件移动和删除的监控能力对内核版本要求过高
