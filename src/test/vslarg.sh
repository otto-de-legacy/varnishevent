#!/bin/bash

echo
echo "TEST: $0"
echo "... testing standard VSL args"

echo "... -g vxid"
# For grouping, use the larger test log that has some backend transactions,
# since the two groupings have the effect of exchanging the order of some
# output lines (no difference with the smaller log).
CKSUM=$( ../varnishevent -g vxid -r sw-doc.log -f varnishevent.conf | cksum)

# Same as default (no -g arg)
if [ "$CKSUM" != '1162093504 22636095' ]; then
    echo "ERROR: -g vxid unexpected cksum: $CKSUM"
    exit 1
fi

echo "... -g request"
CKSUM=$( ../varnishevent -g request -r sw-doc.log -f varnishevent.conf | cksum)

if [ "$CKSUM" != '2524911127 22637823' ]; then
    echo "ERROR: -g request unexpected cksum: $CKSUM"
    exit 1
fi

echo "... -g raw"
# Timestamps for raw grouping are always the time at which the tx was read,
# even for binary file reads. So we check against the last four columns.
CKSUM=$( ../varnishevent -g raw -r varnish-doc.log -f raw.conf | awk '{print $(NF-3), $(NF-2), $(NF-1), $NF}' | cksum)

if [ "$CKSUM" != '4287974290 4744' ]; then
    echo "ERROR: -g raw unexpected cksum: $CKSUM"
    exit 1
fi

# Cannot mix raw grouping with client and/or backend formats
../varnishevent -g raw -f varnishevent.conf

if [ "$?" != "1" ]; then
    echo "ERROR: -g raw with client/backend formats did not exit with failure as expected"
    exit 1
fi

echo '... -g session'
../varnishevent -g session

if [ "$?" != "1" ]; then
    echo "ERROR: -g session did not exit with failure as expected"
    exit 1
fi

echo "... -q query"
CKSUM=$( ../varnishevent -q 'ReqURL ~ "_static"' -r varnish-doc.log | cksum)

if [ "$CKSUM" != '2045926544 8190' ]; then
    echo "ERROR: -q query unexpected cksum: $CKSUM"
    exit 1
fi

../varnishevent -q 'ReqURL ~'

if [ "$?" != "1" ]; then
    echo "ERROR: -q query with illegal VSL query did not exit with failure as expected"
    exit 1
fi

exit 0
