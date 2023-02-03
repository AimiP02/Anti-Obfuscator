#include <cstdio>
#include <cstring>
#include <iostream>

int main() {
  char input[100];
  scanf("%s", input);
  if (!strcmp(input, "1")) {
    puts("This is '1' branch");
  } else if (!strcmp(input, "2")) {
    puts("This is '2' branch");
  } else {
    puts("This is 'else' branch");
  }
  return 0;
}