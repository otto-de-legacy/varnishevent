#!/bin/bash

echo
echo "TEST: $0"
echo "... testing standard VSL args"

echo "... -g grouping"

# For grouping, use the larger test log that has some backend transactions,
# since the two groupings have the effect of exchanging the order of some
# output lines (no difference with the smaller log).
CKSUM=$( ../varnishevent -g vxid -r sw-doc.log -f varnishevent.conf | cksum)

# Same as default (no -g arg)
if [ "$CKSUM" != '3589078266 20793576' ]; then
    echo "ERROR: -g vxid unexpected cksum: $CKSUM"
    exit 1
fi

CKSUM=$( ../varnishevent -g request -r sw-doc.log -f varnishevent.conf | cksum)

if [ "$CKSUM" != '2107709581 20793576' ]; then
    echo "ERROR: -g request unexpected cksum: $CKSUM"
    exit 1
fi

exit 0

echo "... -m tag:regex"
CKSUM=$( ../varnishevent -m RxURL:manual -m RxURL:pt-br -r varnish.binlog | cksum)

if [ "$CKSUM" != '3698415327 24419' ]; then
    echo "ERROR: -m tag:regex incorrect cksum: $CKSUM"
    exit 1
fi

echo "... -s skip"
CKSUM=$( ../varnishevent -s 20000 -r varnish.binlog | cksum)

if [ "$CKSUM" != '3254949310 3668220' ]; then
    echo "ERROR: -s skip incorrect cksum: $CKSUM"
    exit 1
fi

echo "... -X regex"
CKSUM=$( ../varnishevent -X manual -r varnish.binlog | cksum)

if [ "$CKSUM" != '2279381770 3663437' ]; then
    echo "ERROR: -X regex incorrect cksum: $CKSUM"
    exit 1
fi

exit 0
