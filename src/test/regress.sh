#!/bin/bash

echo
echo "TEST: $0"
echo '... testing output and log against known checksums (long)'

LOG=test.log
OUT=output.log

rm -f $LOG $OUT

../varnishevent -f varnishevent.conf -r sw-doc.log -w $OUT -v

CKSUM=$( cksum $OUT )
if [ "$CKSUM" != "4102580059 20793538 $OUT" ]; then
    echo "ERROR: Regression test log output incorrect cksum: $CKSUM"
    exit 1
fi

# sed removes the version/revision from the "initializing" line.
# grep removes logs from the writer thread about returns to free lists,
# which are not relevant to the regression, and may appear at different
# places in the log (due to multi-threading).
CKSUM=$( sed -e 's/\(initializing\) \(.*\)/\1/' $LOG | grep -v 'Writer: returned' | cksum )

if [ "$CKSUM" != '214907488 66951871' ]; then
    echo "ERROR: Regression test varnishevent log incorrect cksum: $CKSUM"
    exit 1
fi

exit 0
