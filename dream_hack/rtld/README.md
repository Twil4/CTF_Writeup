**1. Tìm lỗi**

Ta có file source như sau:

```
// gcc -o rtld rtld.c -fPIC -pie

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

void get_shell() {
    system("/bin/sh");
}

int main()
{
    long addr;
    long value; 

    initialize();

    printf("stdout: %p\n", stdout);

    printf("addr: ");
    scanf("%ld", &addr);

    printf("value: ");
    scanf("%ld", &value);

    *(long *)addr = value;
    return 0;
}

```

- Chương trình in ra địa chỉ của `stdout`.
- Sau đó cho nhập số vào biến `addr` và `value`.
- Rồi gán giá trị của `value` cho con trỏ biến `addr`

**2. Ý tưởng**

Dùng lệnh `checksec` kiểm tra:

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Ta thấy có `canary`.

Từ địa chỉ leak ra của `stdout` có thể tính toán được địa chỉ libc. 