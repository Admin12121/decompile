GHIDRA PSEUDOCODE OUTPUT
====================================================================================================
Program  : crackme
Language : x86:LE:64:default
Compiler : gcc
ImageBase: 00100000
====================================================================================================


====================================================================================================
FUNCTION: _DT_INIT
ADDRESS : 00101000
====================================================================================================


void _DT_INIT(void)

{
  __gmon_start__();
  return;
}



====================================================================================================
FUNCTION: FUN_00101020
ADDRESS : 00101020
====================================================================================================


void FUN_00101020(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



====================================================================================================
FUNCTION: __cxa_finalize
ADDRESS : 00101090
====================================================================================================


void __cxa_finalize(void)

{
  __cxa_finalize();
  return;
}



====================================================================================================
FUNCTION: puts
ADDRESS : 001010a0
====================================================================================================


/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int puts(char *__s)

{
  int iVar1;
  
  iVar1 = puts(__s);
  return iVar1;
}



====================================================================================================
FUNCTION: __stack_chk_fail
ADDRESS : 001010b0
====================================================================================================


void __stack_chk_fail(void)

{
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}



====================================================================================================
FUNCTION: strcmp
ADDRESS : 001010c0
====================================================================================================


/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int strcmp(char *__s1,char *__s2)

{
  int iVar1;
  
  iVar1 = strcmp(__s1,__s2);
  return iVar1;
}



====================================================================================================
FUNCTION: __printf_chk
ADDRESS : 001010d0
====================================================================================================


void __printf_chk(void)

{
  __printf_chk();
  return;
}



====================================================================================================
FUNCTION: __isoc99_scanf
ADDRESS : 001010e0
====================================================================================================


void __isoc99_scanf(void)

{
  __isoc99_scanf();
  return;
}



====================================================================================================
FUNCTION: exit
ADDRESS : 001010f0
====================================================================================================


/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void exit(int __status)

{
                    /* WARNING: Subroutine does not return */
  exit(__status);
}



====================================================================================================
FUNCTION: FUN_00101100
ADDRESS : 00101100
====================================================================================================


undefined8 FUN_00101100(undefined8 param_1,undefined8 *param_2)

{
  long in_FS_OFFSET;
  undefined4 local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  FUN_00101270(*param_2);
  __printf_chk(2,"Enter the magic number: ");
  __isoc99_scanf(&DAT_001020c1,&local_14);
  FUN_00101380(local_14);
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}



====================================================================================================
FUNCTION: entry
ADDRESS : 00101170
====================================================================================================


void processEntry entry(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  __libc_start_main(FUN_00101100,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



====================================================================================================
FUNCTION: FUN_001011a0
ADDRESS : 001011a0
====================================================================================================


/* WARNING: Removing unreachable block (ram,0x001011b3) */
/* WARNING: Removing unreachable block (ram,0x001011bf) */

void FUN_001011a0(void)

{
  return;
}



====================================================================================================
FUNCTION: FUN_001011d0
ADDRESS : 001011d0
====================================================================================================


/* WARNING: Removing unreachable block (ram,0x001011f4) */
/* WARNING: Removing unreachable block (ram,0x00101200) */

void FUN_001011d0(void)

{
  return;
}



====================================================================================================
FUNCTION: _FINI_0
ADDRESS : 00101210
====================================================================================================


void _FINI_0(void)

{
  if (DAT_00104010 != '\0') {
    return;
  }
  __cxa_finalize(PTR_LOOP_00104008);
  FUN_001011a0();
  DAT_00104010 = 1;
  return;
}



====================================================================================================
FUNCTION: _INIT_0
ADDRESS : 00101250
====================================================================================================


void _INIT_0(void)

{
  FUN_001011d0();
  return;
}



====================================================================================================
FUNCTION: FUN_00101260
ADDRESS : 00101260
====================================================================================================


uint FUN_00101260(int param_1,int param_2,int param_3)

{
  return param_1 * param_2 + param_3 ^ 0x5a;
}



====================================================================================================
FUNCTION: FUN_00101270
ADDRESS : 00101270
====================================================================================================


void FUN_00101270(char *param_1)

{
  char cVar1;
  char *__s1;
  int iVar2;
  long in_FS_OFFSET;
  bool bVar3;
  char local_18 [8];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  cVar1 = *param_1;
  __s1 = param_1;
  while (cVar1 != '\0') {
    param_1 = param_1 + 1;
    bVar3 = cVar1 == '/';
    cVar1 = *param_1;
    if (bVar3) {
      __s1 = param_1;
    }
  }
  builtin_strncpy(local_18,"crackme",8);
  iVar2 = strcmp(__s1,local_18);
  if (iVar2 != 0) {
    puts("Nothing interesting here. Move along.");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}



====================================================================================================
FUNCTION: FUN_00101300
ADDRESS : 00101300
====================================================================================================


void FUN_00101300(void)

{
  __printf_chk(2,"[debug] Data block size: %d\n",0x3d);
  __printf_chk(2,"[debug] Integrity check: 0x%02x\n",0x58);
  return;
}



====================================================================================================
FUNCTION: FUN_00101340
ADDRESS : 00101340
====================================================================================================


void FUN_00101340(void)

{
  puts("softwarica_ctf{fake_flag_try_harder_lol}");
  return;
}



====================================================================================================
FUNCTION: FUN_00101350
ADDRESS : 00101350
====================================================================================================


void FUN_00101350(undefined1 *param_1,byte *param_2,byte param_3)

{
  byte bVar1;
  long lVar2;
  
  bVar1 = *param_2;
  if (bVar1 != 0) {
    lVar2 = 0;
    do {
      param_1[lVar2] = bVar1 ^ param_3;
      lVar2 = lVar2 + 1;
      bVar1 = param_2[lVar2];
    } while (bVar1 != 0);
    param_1 = param_1 + lVar2;
  }
  *param_1 = 0;
  return;
}



====================================================================================================
FUNCTION: FUN_00101380
ADDRESS : 00101380
====================================================================================================


void FUN_00101380(int param_1)

{
  long lVar1;
  byte bVar2;
  long lVar3;
  long in_FS_OFFSET;
  byte local_98 [136];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 == 0x6042) {
    bVar2 = 0x29;
    lVar1 = 0;
    do {
      lVar3 = lVar1;
      local_98[lVar3] = bVar2 ^ 0x5a;
      bVar2 = (&DAT_001020e1)[lVar3];
      lVar1 = lVar3 + 1;
    } while (bVar2 != 0);
    local_98[lVar3 + 1] = 0;
    __printf_chk(2,"FLAG: %s\n",local_98);
    if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
      return;
    }
  }
  else if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    puts("softwarica_ctf{fake_flag_try_harder_lol}");
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}



====================================================================================================
FUNCTION: _DT_FINI
ADDRESS : 00101434
====================================================================================================


void _DT_FINI(void)

{
  return;
}



====================================================================================================
EXTRACTED FUNCTIONS: 22
====================================================================================================
