#!/bin/sh

# $Id: spam-report.sh,v 1.4 2006/01/26 09:01:50 luca Exp $

# this script report to you the amount of messages
# and spam filtered by qmail-rblchk
# run it in crontab like:
# 0 0 * * * spam-report.sh email_addr num
# and every night you receive at <email_addr> a report
# the script save <num> file of log before deleting it
# <num> is the old log to be keeped (default 0, the log is
# untached!)

# usage: rotate NAME NUM EXT
rotate () {
	NAME=${1}
	NUM=${2}
	EXT=${3}

	while [ ${NUM} -gt 0 ]; do
		NEXT=`expr ${NUM} - 1`
		[ -e ${NAME}.${NEXT}${EXT} ] && rm -fr ${NAME}.${NUM}${EXT} && cp -Rp ${NAME}.${NEXT}${EXT} ${NAME}.${NUM}${EXT}
		NUM=${NEXT}
	done
	rm -fr ${NAME}.0${EXT} && mv ${NAME}${EXT} ${NAME}.0${EXT}
}

list_hits () {
	LIST=1
	TRY=3

	while [ ${TRY} -gt 0 ]; do
		NH=`grep "list #${LIST}" ${LOG} | wc -l`
		if [ ${NH} -gt 0 ]; then
			echo " list #${LIST} hits: $((${NH}))"
		else
			TRY=$((${TRY} - 1))
		fi
		LIST=$((${LIST} + 1))
	done
}


# path, adjust before use!!
LOG=./qmail-rblchk.log
DC=/usr/bin/dc
GZIP=/usr/bin/gzip
QMAILRBLCHK=/var/qmail/bin/qmail-rblchk

# no log, no report ;)
[ ! -f ${LOG} ] && exit 0

SPAM=`grep "spam, " ${LOG} | wc -l`
GOOD=`grep "ok, " ${LOG} | wc -l`
QUERY=`grep "checking: " ${LOG} | wc -l`
CDB=`grep "checking: .* into .*" ${LOG} | wc -l`
if [ ${CDB} -gt 0 ]; then
	CDB_BLOCK=`grep " blocked$" ${LOG} | wc -l`
	CDB_ALLOW=`grep " allowed$" ${LOG} | wc -l`
fi
TOTAL=$((${GOOD} + ${SPAM}))

# no messages, no mail ;)
[ ${TOTAL} = 0 ] && exit 0

# calc spam perc.
P_SPAM=`echo "3k ${SPAM} ${TOTAL} / 100.0 * p" | ${DC}`
P_GOOD=`echo "3k 100.0 ${P_SPAM} - p" | ${DC}`

# send report
(
	echo "qmail-rblchk report"
	echo "==================="
	echo ""
	echo "Messages:"
	echo " total: $((${TOTAL}))"
	echo " good:  $((${GOOD}))	(${P_GOOD}%)"
	echo " spam:  $((${SPAM}))	(${P_SPAM}%)"
	echo ""
	echo "Check:"
	echo " DNS query: $((${QUERY}-${CDB}))"
	[ ${CDB} -gt 0 ] && echo " over cdb:  $((${CDB}))"
	echo ""
	echo "RBL list usage:"
	list_hits
	if [ ${CDB} -gt 0 ]; then
		echo ""
		echo "cdb usage:"
		echo " allowed IPs:	$((${CDB_ALLOW}))"
		echo " blocked IPs:	$((${CDB_BLOCK}))"
	fi
	echo ""
	echo "--"
	${QMAILRBLCHK} -V 2>&1
	echo "See more at http://morettoni.net"
) | mail -s "qmail-rblchk report" ${1:-root}

# remove old log
if [ ${2:-0} -gt 0 ]; then
	${GZIP} ${LOG}
	rotate ${LOG} ${2} .gz
fi
