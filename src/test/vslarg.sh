#!/bin/bash

echo
echo "TEST: $0"
echo "... testing standard VSL args"

IN=varnish-4.1.0-doc.log
CONF=varnishevent.conf
LOG=/dev/null

# Ensure that the local time date formatters produce the same output
# wherever the test is run.
export TZ=UTC

echo "... no VSL args"
CKSUM=$( ../varnishevent -r ${IN} -f ${CONF} -l ${LOG} | cksum)

if [ "$CKSUM" != '2542287168 442191' ]; then
    echo "ERROR: no VSL args unexpected cksum: $CKSUM"
    exit 1
fi

echo "... -g vxid"
CKSUM=$( ../varnishevent -g vxid -r ${IN} -f ${CONF} -l ${LOG} | cksum)

# Same as default (no -g arg)
if [ "$CKSUM" != '2542287168 442191' ]; then
    echo "ERROR: -g vxid unexpected cksum: $CKSUM"
    exit 1
fi

echo "... -g request"
CKSUM=$( ../varnishevent -g request -r ${IN} -f ${CONF} -l ${LOG} | cksum)

if [ "$CKSUM" != '3970366484 443186' ]; then
    echo "ERROR: -g request unexpected cksum: $CKSUM"
    exit 1
fi

echo "... -g raw"
# Timestamps for raw grouping are always the time at which the tx was read,
# even for binary file reads. So we check against the last four columns.
# The query restricts output to Begin records; the previous invocation
# rendered every record with just the VXIDs.
CKSUM=$( ../varnishevent -g raw -r ${IN} -f raw.conf -l ${LOG} -q 'Begin' | cut -d' ' -f4- | cksum)

if [ "$CKSUM" != '3267477005 21053' ]; then
    echo "ERROR: -g raw with query unexpected cksum: $CKSUM"
    exit 1
fi

# Cannot mix raw grouping with client and/or backend formats
../varnishevent -g raw -f ${CONF}  -l ${LOG}

if [ "$?" != "1" ]; then
    echo "ERROR: -g raw with client/backend formats did not exit with failure as expected"
    exit 1
fi

echo '... -g session'
../varnishevent -g session -l ${LOG}

if [ "$?" != "1" ]; then
    echo "ERROR: -g session did not exit with failure as expected"
    exit 1
fi

echo "... -q query"
CKSUM=$( ../varnishevent -q 'ReqURL ~ "_static"' -r ${IN} -l ${LOG} | cksum)

if [ "$CKSUM" != '805680033 830' ]; then
    echo "ERROR: -q query unexpected cksum: $CKSUM"
    exit 1
fi

../varnishevent -q 'ReqURL ~' -l ${LOG}

if [ "$?" != "1" ]; then
    echo "ERROR: -q query with illegal VSL query did not exit with failure as expected"
    exit 1
fi

echo "... -C"
CKSUM=$( ../varnishevent -C -q 'ReqURL ~ "_STATIC"' -r ${IN} -l ${LOG} | cksum)

if [ "$CKSUM" != '805680033 830' ]; then
    echo "ERROR: -q query unexpected cksum: $CKSUM"
    exit 1
fi

exit 0
