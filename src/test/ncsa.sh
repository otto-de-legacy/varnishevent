#!/bin/bash

# Outputs of varnishevent and varnishncsa for client formats are
# identical, except that varnishevent emits empty strings for data
# from headers that are empty, and varnishnca emits a '-'.

echo
echo "TEST: $0"
echo "... testing equivalence of output with varnishncsa"

# automake skip
SKIP=77

TMP=${TMPDIR:-/tmp}
EVENT="../varnishevent"
NCSA=$( which varnishncsa )

if [ -x "$NSCA" ]; then
    echo "varnishncsa not found or not executable ($NCSA), skipping"
    exit $SKIP
fi

EVENT_LOG=$TMP/event.log
NCSA_LOG=$TMP/ncsa.log
INPUT=varnish-4.1.0-doc.log

DIFF_CMD="diff $EVENT_LOG $NCSA_LOG"

echo "... default format"
$EVENT -r $INPUT | sed 's/-//g' > $EVENT_LOG
$NCSA -r $INPUT | sed 's/-//g' > $NCSA_LOG

$DIFF_CMD
RC=$?
rm $EVENT_LOG
rm $NCSA_LOG

if [ "$RC" -ne "0" ]; then
    echo "ERROR: outputs of no-arg varnishevent and varnishncsa differ"
    exit 1
fi

# Cannot test the %D formatter, because varnishevent gets it more accurately
# (varnishncsa has floating point errors).
# XXX: WIP -- bugs discovered with Debug and VSL:Timestamp
#FORMAT='%b %H %h %I %{Host}i %{Connection}i %{User-Agent}i %{X-Forwarded-For}i %{Accept-Ranges}o %{Age}o %{Connection}o %{Content-Encoding}o %{Content-Length}o %{Content-Type}o %{Date}o %{Last-Modified}o %{Server}o %{Transfer-Encoding}o %{Via}o %{X-Varnish}o %l %m %O %q %r %s %t %{%F-%T}t %U %u %{Varnish:time_firstbyte}x %{Varnish:hitmiss}x %{Varnish:handling}x %{VSL:Begin}x %{VSL:Debug}x %{VSL:End}x %{VSL:Gzip}x %{VSL:Hit}x %{VSL:Length}x %{VSL:Link}x %{VSL:ReqAcct}x %{VSL:ReqStart}x %{VSL:RespProtocol}x %{VSL:ReqMethod}x %{VSL:ReqURL}x %{VSL:ReqProtocol}x %{VSL:RespReason}x %{VSL:RespStatus}x %{VSL:Timestamp}x %{Varnish:vxid}x'
FORMAT='%b %H %h %I %{Host}i %{Connection}i %{User-Agent}i %{X-Forwarded-For}i %{Accept-Ranges}o %{Age}o %{Connection}o %{Content-Encoding}o %{Content-Length}o %{Content-Type}o %{Date}o %{Last-Modified}o %{Server}o %{Transfer-Encoding}o %{Via}o %{X-Varnish}o %l %m %O %q %r %s %t %{%F-%T}t %U %u %{Varnish:time_firstbyte}x %{Varnish:hitmiss}x %{Varnish:handling}x %{VSL:Begin}x %{VSL:End}x %{VSL:Gzip}x %{VSL:Hit}x %{VSL:Length}x %{VSL:Link}x %{VSL:ReqAcct}x %{VSL:ReqStart}x %{VSL:RespProtocol}x %{VSL:ReqMethod}x %{VSL:ReqURL}x %{VSL:ReqProtocol}x %{VSL:RespReason}x %{VSL:RespStatus}x %{Varnish:vxid}x'

echo "... custom -F format"
$EVENT -r $INPUT -F "$FORMAT" -v | sed 's/-//g' > $EVENT_LOG
$NCSA -r $INPUT -F "$FORMAT" | sed 's/-//g' > $NCSA_LOG

$DIFF_CMD
RC=$?
rm $EVENT_LOG
rm $NCSA_LOG

if [ "$RC" -ne "0" ]; then
    echo "ERROR: outputs of varnishevent/varnishncsa -F differ"
    exit 1
fi

FORMAT_EVENT='%{VSL:Timestamp[1]}x'
FORMAT_NCSA='%{VSL:Timestamp[2]}x'

echo "... VSL formatter"
$EVENT -r $INPUT -F "$FORMAT_EVENT" > $EVENT_LOG
$NCSA -r $INPUT -F "$FORMAT_NCSA"  > $NCSA_LOG

$DIFF_CMD
RC=$?
rm $EVENT_LOG
rm $NCSA_LOG

if [ "$RC" -ne "0" ]; then
    echo "ERROR: outputs of varnishevent/varnishncsa VSL formatter differ"
    exit 1
fi

FORMAT_EVENT='%{tag:Timestamp[1]}x'
FORMAT_NCSA='%{VSL:Timestamp[2]}x'

echo "... compatibility of tag and VSL formatter"
$EVENT -r $INPUT -F "$FORMAT_EVENT" > $EVENT_LOG
$NCSA -r $INPUT -F "$FORMAT_NCSA" > $NCSA_LOG

$DIFF_CMD
RC=$?
rm $EVENT_LOG
rm $NCSA_LOG

if [ "$RC" -ne "0" ]; then
    echo "ERROR: tag and VSL formatters for varnishevent and varnishncsa differ"
    exit 1
fi

FORMAT_EVENT='%{vxid}x'
FORMAT_NCSA='%{Varnish:vxid}x'

echo "... compatibility of the vxid and Varnish:vxid formatters"
$EVENT -r $INPUT -F "$FORMAT_EVENT" > $EVENT_LOG
$NCSA -r $INPUT -F "$FORMAT_NCSA" > $NCSA_LOG

$DIFF_CMD
RC=$?
rm $EVENT_LOG
rm $NCSA_LOG

if [ "$RC" -ne "0" ]; then
    echo "ERROR: vxid and Varnish:vxid formatters for varnishevent and varnishncsa differ"
    exit 1
fi

exit 0
