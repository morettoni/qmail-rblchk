/*
  Copyright (c) 2006  Morettoni Luca <luca@morettoni.net>
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

  $Id: qmail-rblchk.c,v 1.8 2006/01/24 08:17:24 luca Exp $

  NOTE: functions ``buffer_copy, maildir_child and wait_pid'' plus all external
        file (like dns.h and more) are developed by Dr. Dan Bernstein and are
        free to use in the public domain.
*/

#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "alloc.h"
#include "dns.h"
#include "str.h"
#include "stralloc.h"
#include "buffer.h"
#include "ip4.h"
#include "byte.h"
#include "strerr.h"
#include "error.h"
#include "sgetopt.h"
#include "fmt.h"
#include "open.h"
#include "scan.h"
#include "timestamp.h"
#include "cdb.h"

static char seed[128];
struct rbl_entry {
  char *server;
  int txt;
  int rev;
  int otc;
} rbl[32];

char skipip[64];
int iptoskip = 0;
unsigned long ignore = 0;
int rblnum = 0;
int scan_all = 0;
int cond_redir = 0;
int verbose = 0;
int quiet = 0;
int tagspam = 0;
char *delivery = NULL;
char *cdbrules = NULL;
stralloc why = {0};
buffer *buffer_log;

char fntmptph[80 + FMT_ULONG * 2];
char fnnewtph[80 + FMT_ULONG * 2];
void tryunlinktmp() { unlink (fntmptph); }
void sigalrm() { tryunlinktmp (); _exit(3); }

#define TEMP_FAIL       111
#define EXIT_OK         (cond_redir ? 1 : 0)
#define EXIT_SPAM       (cond_redir ? 0 : (delivery ? 99 : 100))
#define FATAL		"qmail-rblchk: fatal: "
#define BUF_LEN		1024
#define VERSION		"qmail-rblchk 2.4.1"
#define AUTHOR		"Luca Morettoni <luca@morettoni.net>"

void do_log (void)
{
  char ts[TIMESTAMP];
  char s[FMT_ULONG];
  static pid_t pid = 0;

  if (!pid) pid = getpid();

  timestamp (ts);
  buffer_put (buffer_log, ts, TIMESTAMP);
  buffer_puts (buffer_log, " ");
  buffer_put (buffer_log, s, fmt_ulong (s,pid));
  buffer_puts (buffer_log, " ");
}

void nomem (void)
{
  strerr_die2x(111,FATAL,"out of memory");
}

void nocdb (void)
{
  strerr_die4sys(111,FATAL,"unable to read ",cdbrules,": ");
}

void usage (void)
{
  buffer_puts (buffer_2, "qmail-rblchk: usage: qmail-rblchk [opz] [dir]\n\n");
  buffer_puts (buffer_2, " options may be:\n");
  buffer_puts (buffer_2, "  -h       this screen\n");
  buffer_puts (buffer_2, "  -s       add X-Spam header into the incoming mail (work only with delivery ``dir'')\n");
  buffer_puts (buffer_2, "  -c       turn on condredirect compatibility mode\n");
  buffer_puts (buffer_2, "  -i NUM   ignore first ``NUM'' IPs found in the header\n");
  buffer_puts (buffer_2, "  -x IP    do not check ``IP'', try to find other address in header\n");
  buffer_puts (buffer_2, "  -v       verbose (debug) mode\n");
  buffer_puts (buffer_2, "  -V       show program version\n");
  buffer_puts (buffer_2, "  -q       quiet mode (suppress any output)\n");
  buffer_puts (buffer_2, "  -p       don't check private IP class:\n");
  buffer_puts (buffer_2, "             127.0.0.0   - 127.255.255.255\n");
  buffer_puts (buffer_2, "             10.0.0.0    - 10.255.255.255\n");
  buffer_puts (buffer_2, "             172.16.0.0  - 172.31.255.255\n");
  buffer_puts (buffer_2, "             192.168.0.0 - 192.168.255.255\n");
  buffer_puts (buffer_2, "  -m       check all IPs in email (default: check only first IP)\n");
  buffer_puts (buffer_2, "  -l log   write program action to ``log'' file\n");
  buffer_puts (buffer_2, "  -L data  write blocked IP to ``data'' file\n");
  buffer_puts (buffer_2, "  -r addr  use ``addr'' for RBL checking (if TXT record exist block mail)\n");
  buffer_puts (buffer_2, "  -R addr  use ``addr'' for RBL reverted checking (if TXT record NOT exist block mail)\n");
  buffer_puts (buffer_2, "  -C addr  use ``addr'' for one time RBL checking (if TXT or A record exist don't block mail)\n");
  buffer_puts (buffer_2, "  -a addr  use ``addr'' for anti-RBL checking (if A record NOT exist block mail)\n");
  buffer_puts (buffer_2, "  -A addr  use ``addr'' for anti-RBL reverted checking (if A record exist block mail)\n");
  buffer_puts (buffer_2, "  -X cdb   check IP from tcpserver-style ``cdb'' file (IP:deny block mail from that IP)\n");

  buffer_puts (buffer_2, "\nYou must specify one or more (max 32) RBL address, example:\n");
  buffer_puts (buffer_2, " qmail-rblchk -r dnsbl.sorbs.net -r sbl-xbl.spamhaus.org -r relays.ordb.org\n\n");
  buffer_puts (buffer_2, "You can ignore (-x option) no more than 16 IP address\n\n");
  buffer_puts (buffer_2, "If ``dir'' is given in command line and it exist all blocked mails are delivered\n");
  buffer_puts (buffer_2, "into Maildir ``dir'' (dir must start with a / or a . and end with a /);\n");
  buffer_puts (buffer_2, "the program run in ``delivery mode''.\n");

  buffer_puts (buffer_2, "\nThe program exit status may be (normal mode):\n");
  buffer_puts (buffer_2, " 0    when the message is not blocked\n");
  buffer_puts (buffer_2, " 100  when the message is blocked\n");
  buffer_puts (buffer_2, " 111  when fails or no checking options was given\n");
  buffer_puts (buffer_2, "In ``delivery mode'':\n");
  buffer_puts (buffer_2, " 0    the message is not blocked (continue .qmail checking)\n");
  buffer_puts (buffer_2, " 99   the blocked message has been wrote to ``dir'' Maildir\n");
  buffer_puts (buffer_2, " 111  same as above\n");
  buffer_puts (buffer_2, "In ``condredirect compatibility mode'':\n");
  buffer_puts (buffer_2, " 0    when the message is blocked\n");
  buffer_puts (buffer_2, " 1    when the message is not blocked\n");
  buffer_puts (buffer_2, " 111  same as above\n");

  buffer_flush (buffer_2);

  _exit (TEMP_FAIL);
}

int docheck (struct cdb *c, stralloc *ip)
{
  char *data;
  unsigned int datalen;
  int ret = -1; /* not found, try again! */

  switch (cdb_find (c, ip->s, ip->len)) {
    case -1: nocdb ();
    case 0: return -1;
  }

  datalen = cdb_datalen(c);
  data = alloc(datalen);
  if (!data) nomem ();
  if (cdb_read (c,data,datalen,cdb_datapos (c)) == -1) {
    alloc_free(data);
    nocdb ();
  }

  switch (data[0]) {
    case 'D': ret = 1; break; /* deny */
    default:  ret = 0; break; /* allow */
  }

  alloc_free(data);

  return ret;
}

int check_cdb (char ip[4])
{
  int fd;
  struct cdb c;
  char ip_fmt[IP4_FMT];
  stralloc ipcdb = {0};
  int ret = -1; /* default: NOT found in CDB file */

  ip4_fmt (ip_fmt, ip);
 
  fd = open_read (cdbrules);
  if (fd == -1)
    nocdb ();
  else {
    cdb_init(&c,fd);
    if (!stralloc_copyb (&ipcdb, ip_fmt, ip4_fmt (ip_fmt, ip))) nomem ();

    if (verbose) {
      do_log ();
      buffer_puts (buffer_log, "checking: ");
      buffer_put (buffer_log, ipcdb.s, ipcdb.len);
      buffer_puts (buffer_log, " into ");
      buffer_puts (buffer_log, cdbrules);
      buffer_puts (buffer_log, "\n");
      buffer_flush (buffer_log);
    }

    /* check all octets */
    ret = docheck (&c, &ipcdb);
    while (ipcdb.len > 0 && ret == -1) {
      /* delete right octect and try again */
      if (ip_fmt[ipcdb.len - 1] == '.')
        ret = docheck (&c, &ipcdb);
      --ipcdb.len;
    }
    /* if no match, we see the defaul rule in the file */
    if (ret == -1) ret = docheck (&c, &ipcdb);

    cdb_free(&c);
    close (fd);

    if (verbose) {
      do_log ();
      stralloc_copyb (&ipcdb, ip_fmt, ip4_fmt (ip_fmt, ip));
      buffer_put (buffer_log, ipcdb.s, ipcdb.len);
      switch (ret) {
        case -1: buffer_puts (buffer_log, " not listed"); break;
        case 0: buffer_puts (buffer_log, " allowed"); break;
        case 1: buffer_puts (buffer_log, " blocked"); break;
      }
      buffer_puts (buffer_log, "\n");
      buffer_flush (buffer_log);
    }

    if (ret == 1) {
      stralloc_copyb (&why, ip_fmt, ip4_fmt (ip_fmt, ip));
      stralloc_cats (&why, " is blocked (deny) in ");
      stralloc_cats (&why, cdbrules);
    }
  }

  return ret;
}

int check_ip (char ip[4]) 
{
  stralloc check = {0};
  stralloc out = {0};
  char ip_fmt[IP4_FMT];
  char rev[4];
  int i;
  char s[FMT_ULONG];

  for (i = 0; i < 4; i++) rev[i] = ip[3-i];

  for (i = 0; i < rblnum; i++) {
    stralloc_copyb (&check,ip_fmt, ip4_fmt (ip_fmt, rev));
    stralloc_cats (&check, ".");
    stralloc_cats (&check, rbl[i].server);

    if (verbose) {
      do_log ();
      if (rbl[i].otc) buffer_puts (buffer_log, "one time ");
      buffer_puts (buffer_log, "checking: ");
      buffer_put (buffer_log, check.s, check.len);
      buffer_puts (buffer_log, "\n");
      buffer_flush (buffer_log);
    }

    if ((!rbl[i].txt || rbl[i].otc) && dns_ip4 (&out, &check) != -1) {
      if (verbose) {
        do_log ();
        if (out.len) {
          buffer_puts (buffer_log, "list #");
          buffer_put (buffer_log, s, fmt_ulong (s,i+1));
          buffer_puts (buffer_log, ", A record: ");
          buffer_put (buffer_log, ip_fmt, ip4_fmt (ip_fmt, out.s));
          buffer_puts (buffer_log, "\n");
        } else {
          buffer_put (buffer_log, ip_fmt, ip4_fmt (ip_fmt, ip));
          buffer_puts (buffer_log, " no A record\n");
        }
        buffer_flush (buffer_log);
      }

      if (out.len && !rbl[i].rev) {
        stralloc_copyb (&why, ip_fmt, ip4_fmt (ip_fmt, ip));
        stralloc_cats (&why, " is listed in ");
        stralloc_cats (&why, rbl[i].server);
        return (rbl[i].otc ? 0 : 1);
      }

      if (!out.len && rbl[i].rev && !rbl[i].otc) {
        stralloc_copyb (&why, ip_fmt, ip4_fmt (ip_fmt, ip));
        stralloc_cats (&why, " is NOT listed in ");
        stralloc_cats (&why, rbl[i].server);
        return 1;
      }
    }

    if ((rbl[i].txt || rbl[i].otc) && dns_txt (&out, &check) != -1) {
      if (verbose) {
        do_log ();
        if (out.len) {
          buffer_puts (buffer_log, "list #");
          buffer_put (buffer_log, s, fmt_ulong (s,i+1));
          buffer_puts (buffer_log, ", TXT record: ");
          buffer_put (buffer_log, out.s, out.len);
          buffer_puts (buffer_log, "\n");
        } else {
          buffer_put (buffer_log, ip_fmt, ip4_fmt (ip_fmt, ip));
          buffer_puts (buffer_log, " no TXT record\n");
        }
        buffer_flush (buffer_log);
      }

      if (out.len && !rbl[i].rev) {
        stralloc_copy (&why, &out);
        return (rbl[i].otc ? 0 : 1);
      }

      if (!out.len && rbl[i].rev) {
        stralloc_copys (&why, "No TXTs for ");
        stralloc_catb (&why, ip_fmt, ip4_fmt (ip_fmt, ip));
        return 1;
      }
    }
  }

  return 0;
}

/* child process */
int buffer_copy(ssout,ssin)
register buffer *ssout;
register buffer *ssin;
{
  register int n;
  register char *x;
  stralloc tag = {0};

  if (tagspam) {
     stralloc_copys (&tag, "X-Spam: yes\n");
     if (buffer_put(ssout,tag.s,tag.len) == -1) return -3;

     stralloc_copys (&tag, "X-Spam-Status: ");
     stralloc_cat (&tag, &why);
     stralloc_cats (&tag, "\n");
     if (buffer_put(ssout,tag.s,tag.len) == -1) return -3;

     stralloc_copys (&tag, "X-Spam-Version: ");
     stralloc_cats (&tag, VERSION);
     stralloc_cats (&tag, "\n");
     if (buffer_put(ssout,tag.s,tag.len) == -1) return -3;
  }
  
  for (;;) {
    n = buffer_feed(ssin);
    if (n < 0) return -2;
    if (!n) return 0;
    x = buffer_PEEK(ssin);
    if (buffer_put(ssout,x,n) == -1) return -3;
    buffer_SEEK(ssin,n);
  }
}

void maildir_child(dir)
char *dir;
{
 unsigned long pid;
 unsigned long now;
 char host[64];
 char *s;
 int loop;
 struct stat st;
 int fd;
 char buf[BUF_LEN];
 char outbuf[BUF_LEN];
 buffer ss;
 buffer ssout;

 signal (SIGALRM,sigalrm);
 if (chdir(dir) == -1) { if (error_temp(errno)) _exit(1); _exit(2); }
 pid = getpid();
 host[0] = 0;
 gethostname(host,sizeof(host));
 for (loop = 0;;++loop)
  {
   now = time(0);
   s = fntmptph;
   s += fmt_str(s,"tmp/");
   s += fmt_ulong(s,now); *s++ = '.';
   s += fmt_ulong(s,pid); *s++ = '.';
   s += fmt_strn(s,host,sizeof(host)); *s++ = 0;
   if (stat(fntmptph,&st) == -1) if (errno == error_noent) break;
   /* really should never get to this point */
   if (loop == 2) _exit(1);
   sleep(2);
  }
 str_copy(fnnewtph,fntmptph);
 byte_copy(fnnewtph,3,"new");

 alarm(86400);
 fd = open_excl(fntmptph);
 if (fd == -1) _exit(1);

 buffer_init (&ss,read,0,buf,sizeof(buf));
 buffer_init (&ssout,write,fd,outbuf,sizeof(outbuf));

 switch(buffer_copy(&ssout,&ss))
  {
   case -2: tryunlinktmp(); _exit(4);
   case -3: goto fail;
  }

 if (buffer_flush(&ssout) == -1) goto fail;
 if (fsync(fd) == -1) goto fail;
 if (close(fd) == -1) goto fail; /* NFS dorks */

 if (link(fntmptph,fnnewtph) == -1) goto fail;
   /* if it was error_exist, almost certainly successful; i hate NFS */
 tryunlinktmp(); _exit(0);

 fail: tryunlinktmp(); _exit(1);
}

/* end child process */
int wait_pid(wstat,pid) int *wstat; int pid;
{
  int r;

  do
    r = waitpid(pid,wstat,0);
  while ((r == -1) && (errno == error_intr));
  return r;
}

int ip4_equal (const char *ip1, const char *ip2)
{
  register char i;

  for (i = 0; i < 4; i++)
    if (*(ip1+i) != *(ip2+i)) return 0;

  return 1;
}

int ip4_isprivate (const unsigned char *ip)
{
  /* 127.0.0.0 - 127.255.255.255 */
  if (*ip == 127) return 1;

  /* 10.0.0.0 - 10.255.255.255 */
  if (*ip == 10) return 1;

  /* 172.16.0.0 - 172.31.255.255 */
  if (*ip == 172 && (*(ip+1) >> 4 == 1)) return 1;

  /* 192.168.0.0 - 192.168.255.255 */
  if (*ip == 192 && *(ip+1) == 168) return 1;

  return 0;
}

int main (int argc, char* argv[])
{
  char ip[4];
  stralloc partial = {0};
  stralloc out = {0};
  char ip_fmt[IP4_FMT];
  char line[BUF_LEN];
  char s[FMT_ULONG];
  int r, i, j;
  int inbuflen = 0;
  int flag0 = 1;
  int opt;
  int block = 0;
  int skip_priv = 0;
  int list = 0;
  int child;
  int wstat;
  buffer ssout;
  buffer sslist;
  int fd = 0;
  int fdlist = 0;
  char outbuf[BUF_LEN];
  char outlist[BUF_LEN];

  buffer_log = buffer_2;

  while ((opt = getopt (argc, argv, "a:A:cC:hi:l:L:mpqr:R:svVx:X:")) != opteof)
    switch(opt) {
      case 'a':
      case 'A':
      case 'C':
        rbl[rblnum].server = optarg;
        rbl[rblnum].txt = 0;
        rbl[rblnum].rev = (opt == 'a');
        rbl[rblnum].otc = (opt == 'C');

        if (rblnum < 32-1) rblnum++;
        break;
      case 'c':
        cond_redir = 1;
        break;
      case 'i':
        scan_ulong (optarg, &ignore);
        if (ignore < 1) ignore = 1;
        if (ignore > 10) ignore = 10;
        scan_all = 1;
        break;
      case 'l':
        verbose = 1;
        fd = open_append(optarg);
        if (fd == -1) 
          strerr_die4sys (111,FATAL,"unable to write ",optarg,": ");
        buffer_init (&ssout,write,fd,outbuf,sizeof(outbuf));
        buffer_log = &ssout;
        break;
      case 'L':
        list = 1;
        fdlist = open_append(optarg);
        if (fdlist == -1) 
          strerr_die4sys (111,FATAL,"unable to write ",optarg,": ");
        buffer_init (&sslist,write,fdlist,outlist,sizeof(outlist));
        break;
      case 'm':
        scan_all = 1;
        break;
      case 'p':
        skip_priv = 1;
        break;
      case 'q':
        quiet = 1;
        verbose = 0;
        break;
      case 'r':
      case 'R':
        rbl[rblnum].server = optarg;
        rbl[rblnum].txt = 1;
        rbl[rblnum].rev = (opt == 'R');
	rbl[rblnum].otc = 0;

        if (rblnum < 32-1) rblnum++;
	break;
      case 's':
        tagspam = 1;
        break;
      case 'v':
        verbose = 1;
        break;
      case 'V':
        buffer_puts (buffer_2, VERSION); buffer_puts (buffer_2, " - ");
        buffer_puts (buffer_2, AUTHOR); buffer_puts (buffer_2, "\n");
        buffer_flush (buffer_2);
        _exit (TEMP_FAIL);
        break;
      case 'x':
        if (iptoskip < 16)
          if (ip4_scan (optarg, skipip+(iptoskip*4))) 
            iptoskip++;
          else
            strerr_die3x (111, FATAL, "unable to parse IP ", optarg);
        break;
      case 'X':
	cdbrules = optarg;
	break;
      case 'h':
      default:
        usage ();
    }

  argc -= optind;
  argv += optind;

  /* set verbose mode if we want to log */
  if (fd) verbose = 1;

  if (!rblnum && !cdbrules)
    strerr_die2x (111, FATAL, "you must supply one or more RLB list address or a CDB rule file");

  /* check if a delivery dir was given */
  if (argc > 0) {
    cond_redir = 0;
    delivery = argv[0];

    if ((*delivery != '.' && *delivery != '/') || *(delivery+str_len (delivery)-1) != '/')
      strerr_die2x (111, FATAL, "spam delivery path must start with . or / and end with /.");
  }

  dns_random_init(seed);

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
          if (verbose) {
            do_log ();
            buffer_puts (buffer_log, "header: ");
            buffer_put (buffer_log, partial.s, partial.len);
            buffer_flush (buffer_log);
          }

          if (str_start (partial.s, "Received: from ")) {
/* OLD SCAN MODE
            for (j = 15; flag0 && j < partial.len-8; j++) {
   OLD SCAN MODE */
            for (j = str_rchr (partial.s, '(')+1; flag0 && j; j--) {
              i = ip4_scan (partial.s+j, ip);
              if (i) {
                /* skip listed IP */
                for (r = 0; r < iptoskip; r++)
                  if (ip4_equal(ip, skipip+r*4)) {
                    j += i-1;
                    i = 0;

                    if (verbose) {
                      do_log ();
                      buffer_puts (buffer_log, "skip IP: ");
                      stralloc_copyb (&out,ip_fmt, ip4_fmt (ip_fmt, ip));
                      buffer_put (buffer_log, out.s, out.len);
                      buffer_puts (buffer_log, "\n");
                    }
                  }

                /* skip private IP */
                if (skip_priv && ip4_isprivate (ip)) {
                  j += i-1;
                  i = 0;
                  if (verbose) {
                    do_log ();
                    buffer_puts (buffer_log, "skip private IP: ");
                    stralloc_copyb (&out,ip_fmt, ip4_fmt (ip_fmt, ip));
                    buffer_put (buffer_log, out.s, out.len);
                    buffer_puts (buffer_log, "\n");
                  }
                }

                /* now we can check... */
                if (i) {
                  if (!ignore) {
		    if (cdbrules) {
		      block = check_cdb (ip);
		      if (block == -1) block = check_ip (ip);
		    } else
                      block = check_ip (ip);
		  } else
                    ignore--;

                  j += i-1;

                  if (!scan_all)
                    flag0 = 0;
                  else if (block)
                    flag0 = 0;

                  if (!flag0) inbuflen = 0;
                }
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

  if (block) {
    /* append blocked IP to the list */
    if (list) {
      stralloc_copyb (&out,ip_fmt, ip4_fmt (ip_fmt, ip));
      buffer_put (&sslist, out.s, out.len);
      buffer_puts (&sslist, "\n");
      buffer_flush (&sslist);
    }

    /* report why we block into qmail-send logs */
    if (!quiet) {
      if (delivery) {
        buffer_puts (buffer_2, "qmail-rblchk[spam]: writing to ");
        buffer_puts (buffer_2, delivery);
        buffer_puts (buffer_2, "\n");
      } else {
        buffer_puts (buffer_2, "qmail-rblchk[spam]: ");
        buffer_put (buffer_2, why.s, why.len);
        buffer_puts (buffer_2, "\n");
      }
      buffer_flush (buffer_2);
    }

    if (delivery) {
      if (verbose) {
        do_log ();
        buffer_puts (buffer_log, "spam, writing to ");
        buffer_puts (buffer_log, delivery);
        buffer_puts (buffer_log, "\n");
        buffer_flush (buffer_log);
      }

      /* write spam to spam maildir */
      if (lseek (0, 0, SEEK_SET) == -1)
        strerr_die1x (111, "Unable to rewind message. (#4.3.0)");

      switch (child = fork ()) {
        case -1:
          break;
        case 0:
          maildir_child (delivery);
          _exit(111);
      }

      wait_pid (&wstat, child);
      if (wstat & 127)
        strerr_die1x(111,"Aack, child crashed. (#4.3.0)");

      switch ((wstat >> 8)) {
        case 0: break;
        case 2: strerr_die1x(111,"Unable to chdir to maildir. (#4.2.1)");
        case 3: strerr_die1x(111,"Timeout on maildir delivery. (#4.3.0)");
        case 4: strerr_die1x(111,"Unable to read message. (#4.3.0)");
        default: strerr_die1x(111,"Temporary error on maildir delivery. (#4.3.0)");
      }
    } else {
      if (verbose) {
        do_log ();
        buffer_puts (buffer_log, "spam, exit code: ");
        buffer_put (buffer_log, s, fmt_ulong (s,(block ? EXIT_SPAM : EXIT_OK)));
        buffer_puts (buffer_log, "\n");
        buffer_flush (buffer_log);
      }
    }
  } else {
    if (verbose) {
      do_log ();
      buffer_puts (buffer_log, "ok, default delivery\n");
    }
  }

  buffer_flush (buffer_log);
  if (fd) {
    fsync(fd);
    close(fd);
  }

  if (fdlist) {
    fsync(fdlist);
    close(fdlist);
  }

  _exit (block ? EXIT_SPAM : EXIT_OK);
}
