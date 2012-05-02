#include "auto_home.h"

void hier()
{
  h(auto_home,-1,-1,02755);
  d(auto_home,"bin",-1,-1,02755);
  d(auto_home,"man",-1,-1,02755);
  d(auto_home,"cat",-1,-1,02755);
  d(auto_home,"man/man1",-1,-1,02755);
  d(auto_home,"cat/cat1",-1,-1,02755);

  c(auto_home,"bin","qmail-rblchk",-1,-1,0755);
  c(auto_home,"bin","getsenderip",-1,-1,0755);
  c(auto_home,"man/man1","qmail-rblchk.1",-1,-1,0644);
  c(auto_home,"man/man1","getsenderip.1",-1,-1,0644);
  c(auto_home,"cat/cat1","qmail-rblchk.0",-1,-1,0644);
  c(auto_home,"cat/cat1","getsenderip.0",-1,-1,0644);
}
