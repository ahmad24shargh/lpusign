#ifndef LPUSIGN_HEADER_SYSCALL_H
#define LPUSIGN_HEADER_SYSCALL_H

#include "prelude.h"

__hide long lpu_syscall0(long n);
__hide long lpu_syscall1(long n, long a1);
__hide long lpu_syscall2(long n, long a1, long a2);
__hide long lpu_syscall3(long n, long a1, long a2, long a3);
__hide long lpu_syscall4(long n, long a1, long a2, long a3, long a4);
__hide long lpu_syscall5(long n, long a1, long a2, long a3, long a4, long a5);
__hide long lpu_syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6);

#endif