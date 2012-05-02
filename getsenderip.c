/*
  Copyright (c) 2005  Morettoni Luca <luca@morettoni.net>
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
  SUCH DAMAGE.

  $Id: getsenderip.c,v 1.2 2006/01/23 12:33:50 luca Exp $
*/

#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "str.h"
#include "stralloc.h"
#include "buffer.h"
#include "ip4.h"
#include "byte.h"
#include "strerr.h"
#include "error.h"
#include "fmt.h"
#include "open.h"
#include "scan.h"
#include "sgetopt.h"

#define TEMP_FAIL       111
#define EXIT_OK         0
#define FATAL		"getsenderip: fatal: "
#define BUF_LEN         1024

void nomem (void)
{
  strerr_die2x(TEMP_FAIL,FATAL,"out of memory");
}

void usage (void)
{
  buffer_puts (buffer_2, "getsenderip: usage: getsenderip [-s num] out\n\n");
  buffer_puts (buffer_2, " out is a file where getsenderip appends sender IP\n");
  buffer_puts (buffer_2, " you can skip first ``num'' IPs with option -s\n");
	  
  buffer_puts (buffer_2, "\nThe program exit status may be:\n");
  buffer_puts (buffer_2, " 0    normal processing\n");
  buffer_puts (buffer_2, " 111  when fails or out file is not given\n");

  buffer_flush (buffer_2);

  _exit (TEMP_FAIL);
}

int main (int argc, char* argv[])
{
  char ip[4];
  stralloc partial = {0};
  stralloc out = {0};
  char ip_fmt[IP4_FMT];
  char line[BUF_LEN];
  int r, i, j;
  int inbuflen = 0;
  int flag0 = 1;
  buffer sslist;
  int fdlist = 0;
  char outlist[BUF_LEN];
  unsigned long skip = 0;
  int opt;

  while ((opt = getopt (argc, argv, "s:")) != opteof)
    switch (opt) {
      case 's': scan_ulong (optarg, &skip); break;
      default:  usage ();
    }

  argc -= optind;
  argv += optind;

  if (!argc) usage ();

  fdlist = open_append(argv[0]);
  if (fdlist == -1) 
    strerr_die4sys (111,FATAL,"unable to write ",argv[0],": ");
  buffer_init (&sslist,write,fdlist,outlist,sizeof(outlist));

  if (!stralloc_copys (&partial, "")) nomem ();

  while (flag0 || inbuflen || partial.len) {
    if (flag0)
      if (inbuflen < sizeof line) {
        r = read (0, line+inbuflen, sizeof line-inbuflen);

        if (r <= 0)
          flag0 = 0;
        else
          inbuflen += r;
      }

    while (flag0) {
      i = byte_chr (line, inbuflen, '\n');
      if (inbuflen && (i == inbuflen)) {
        if (!stralloc_catb (&partial, line, inbuflen)) nomem ();
        inbuflen = 0;
        continue;
      }

      if ((i < inbuflen) || (!flag0 && partial.len)) {
        if (i < inbuflen) ++i;
        if (!stralloc_catb (&partial, line, i)) nomem ();

        inbuflen -= i;
        for (j = 0; j < inbuflen; ++j) line[j] = line[j + i];

        /* end of header */
        if (partial.len == 1) {
          inbuflen = partial.len = flag0 = 0;
          break;
        }

        if (partial.len && flag0) {
          if (str_start (partial.s, "Received: from ")) {
            for (j = str_rchr (partial.s, '(')+1; flag0 && j; j--) {
              i = ip4_scan (partial.s+j, ip);

	      if (skip && i) {
                skip--;
                break;
	      }

              if (i) {
                /* write the IP to the output file */
                stralloc_copyb (&out,ip_fmt, ip4_fmt (ip_fmt, ip));
                buffer_put (&sslist, out.s, out.len);
                buffer_puts (&sslist, "\n");
                flag0 = 0;
                inbuflen = 0;
              }
            }
          }
        }

        partial.len = 0;
        continue;
      }

      break;
    }
  }

  /* flush and close output file */
  buffer_flush (&sslist);
  fsync(fdlist);
  close(fdlist);

  _exit (EXIT_OK);
}
