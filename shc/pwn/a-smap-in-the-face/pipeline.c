/* pipeline.c */

__int64 pipeline_init() {
  pipeline_dev = 255;
  *((_QWORD *)&pipeline_dev + 1) = "pipeline";
  *((_QWORD *)&pipeline_dev + 2) = &pipeline_fops;
  if ( (int)misc_register(&pipeline_dev) < 0 )
    printk(&unk_668);  // ".3[!] Failed to install data processing kernel module!\n"
  printk(&unk_6A0);    // ".6Installed secure data processing pipeline kernel module v2.19.8-fe. \n"
  boot();
  return 0LL;
}

__int64 pipeline_exit() {
  misc_deregister(&pipeline_dev);
  return printk(&unk_6E8); // ".6[!] Released data processing pipeline kernel module!\n"
}

__int64 pipeline_open() { return 0LL; }
__int64 pipeline_release() { return 0LL; }

void __fastcall __noreturn copy_overflow(unsigned int a1, __int64 a2) {
  _warn_printk("Buffer overflow detected (%d < %lu)!\n", a1, a2);
  BUG();
}

__int64 boot() {
  int v0; // eax
  int v1; // eax
  int v3; // [rsp+4h] [rbp-Ch] BYREF
  int v4; // [rsp+8h] [rbp-8h] BYREF
  int v5; // [rsp+Ch] [rbp-4h] BYREF

  get_random_bytes(&v3, 4LL);
  get_random_bytes(&v4, 4LL);
  get_random_bytes(&v5, 4LL);
  v0 = (v3 % 100) >> 31;
  v3 = v0 ^ (v3 % 100);
  v3 -= v0;
  v1 = (v4 % 100) >> 31;
  v4 = v1 ^ (v4 % 100);
  v4 -= v1;
  v5 = abs32(v5 % 1000);
  printk(&unk_390);  // ".6-----------------------------------------------------\n"
  printk(&unk_3D0);  // ".6---------High Speed Data Processing Pipeline---------\n"
  printk(&unk_390);  // ".6-----------------------------------------------------\n"
  printk(&unk_410);  // ".6[*] .........Boot Sequence Initialized.\n"
  printk(&unk_440);  // ".6[*] .........Processing SystemInformation.\n"
  printk(&unk_470);  // ".6[*] .........Security Mitigations Enabled.\n"
  printk(&unk_73C);  // ".6[*] System Cores: %d\n"
  printk(&unk_754);  // ".6[*] Network Latency: %dms\n"
  printk(&unk_4A0);  // ".6[*] Memory Allocation: %dMB\n"
  printk(&unk_4C0);  // ".6[?] .........Awaiting User Data>_.\n"

  return 0LL;
}

void __fastcall pipeline_ioctl(__int64 fd, int ioctl_id, void *ioctl_param) {
  __int64 secret; // [rsp+0h] [rbp-28h] BYREF
  __int64 var1; // [rsp+8h] [rbp-20h] BYREF
  __int64 var2; // [rsp+10h] [rbp-18h]
  __int64 len; // [rsp+18h] [rbp-10h]

  switch ( ioctl_id )
  {
    case 0x10:
      // pipeline_ioctl_cold();
      printk(&unk_4E8);  // ".6[*] .........Checking communication link.\n"
      printk(&unk_518);  // ".6[*] .........Communication link established successful.\n"
      printk(&unk_558);  // ".6[-] .........Use command [1] to display this message.\n"
      printk(&unk_598);  // ".6[-] .........Use command [2] to read from pipeline.\n"
      printk(&unk_5D0);  // ".6[-] .........Use command [3] to push to pipeline.\n"
      printk(&unk_608);  // ".6[-] .........Use command [4] to show boot sequence.\n"
      break;
    case 0x20:
      // This effectively exports copy_from_kernel as ioctl 0x20, that can be
      // called with a 24-byte buffer containing three 64-bit values
      //   void *src_in_kernel
      //   void *dst_in_user
      //   long len
      if ( !copy_from_user(&var1, ioctl_param, 24LL) )
        copy_to_user(var2, var1, len);
      break;
    case 0x30:
      // Similarly, this exports copy_to_kernel as ioctl 0x30, with buffer containing:
      //    void *dst_in_kernel
      //    void *src_in_user
      //    long len
      if ( !copy_from_user(&var1, ioctl_param, 24LL) )
        copy_from_user(var1, var2, len);
      break;
    case 0x40:
      boot();
      break;
    case 0x1337:
      printk(&unk_640);  // ".6DEBUGGING ONLY - REMOVE IN PROD"
      // Extract an current_task->mm->pgd into address pointed by *second* item
      // in the long[3] buffer.
      secret = *(_QWORD *)(*(_QWORD *)(__readgsqword((unsigned int)&current_task) + 0x3D8) + 0x50LL);
      if ( !copy_from_user(&var1, ioctl_param, 24LL) )
        copy_to_user(var2, &secret, 8LL);
      break;
  }
}


char unk_720[] = "include/linux/thread_info.h";
/*
__bug_table:00000000000009E0 __bug_table     segment byte public 'DATA' use64
__bug_table:00000000000009E0                 dd FFFFF641h   ; signed int bug_addr_disp   points to ud2 in copy_overflow at 0x00021
__bug_table:00000000000009E4                 dd FFFFFD40h   ; signed int file_disp       dd offset _LC1+0FFFFF620h ; "include/linux/thread_info.h"
__bug_table:00000000000009E8                 dw 134         ; unsigned short line
__bug_table:00000000000009EA                 dw 0901h       ; unsigned short flags
__bug_table:00000000000009EB __bug_table     ends
*/


