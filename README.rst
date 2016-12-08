============
varnishevent
============

----------------------------------------------------------------------------
Display Varnish log contents in formats for client, backend and other events
----------------------------------------------------------------------------

:Author: Geoffrey Simmons
:Date:   2016-12-08
:Version: trunk
:Manual section: 1


SYNOPSIS
========

::

  varnishevent [-a] [-d] [-D] [-f configfile] [-F format] [-g grouping]
               [-L txlimit] [-n varnish_name] [-N vsmfile] [-P file]
               [-q query] [-r file] [-T txtimeout] [-v] [-V] [-w file]
               [-l logfile]


DESCRIPTION
===========

The varnishevent utility reads varnishd(1) shared memory logs and
presents them one line per event, where an event is one or more of a
client transaction (request/response), backend transaction, or a raw
transaction, such as a backend health check. By specifying output
formats in the configuration, you decide which of the three kinds of
transactions are logged.

By default, varnishevent functions almost exactly as varnishncsa(1) --
it outputs client transaction events in the default format shown
below.

The main differences between varnishevent and varnishncsa(1) are:

* Outputs differ in a few cases where varnishevent emits an empty
  string for data that are absent or unknown, while varnishncsa emits a
  '-'.
* varnishncsa only logs client and/or backend transactions, and does so
  with one output format. varnishevent also allows raw transactions,
  as well as simultaneous client and backend logging with different
  output formats.
* Some additional output formatters are available.
* varnishevent is designed to keep pace reading the Varnish shared
  memory log while varnishd is writing to it rapidly under heavy load,
  and output channels are slow.

OPTIONS
=======

-a

	When writing to a file, append to it rather than overwrite it.

-d

	Start processing log records at the head of the log instead of the tail.

-D

	Daemonize.

-f file

	Read the configuration from the specified file.

-F format

	Set the output format string for client transactions.

-g <request|vxid|raw>

	The grouping of the log records. The default is to group by vxid.

-h

	Print program usage and exit

-l logfile

	Write the application log to ``logfile``. By default,
	syslog(3) is used.

-L limit

	Sets the upper limit of incomplete transactions kept before
	the oldest transaction is force completed. A warning record is
	synthesized when this happens. This setting keeps an upper
	bound on the memory usage of running queries. Defaults to 1000
	transactions.

-n name

	Specify the name of the varnishd instance to get logs
	from. If -n is not specified, the host name is used.

-N filename

	Specify the filename of a stale VSM instance. When using this
	option the abandonment checking is disabled.

-P file

	Write the process' PID to the specified file.

-q query

	Specifies the VSL query to use.

-r filename

	Read log in binary file format from this file.

-T seconds

	Sets the transaction timeout in seconds. This defines the
	maximum number of seconds elapsed between a Begin tag and the
	End tag. If the timeout expires, a warning record is
	synthesized and the transaction is force completed. Defaults
	to 120 seconds.

-v

	Set the log level to DEBUG.

-V

	Print version information and exit.

-w filename

	Redirect output to file. The file will be overwritten unless
	the -a option was specified. If the application receives a
	SIGHUP the file will be reopened allowing the old one to be
	rotated away.


The ``-f`` option is incompatible with varnishncsa's
option. varnishncsa uses ``-f`` to read a single output format from a
file, while varnishevent's config file, read with ``-f``, specifies a
configuration (as described below), which may have different output
formats for client and backend logging.

varnishncsa has the ``-b`` and ``-c`` options to select backend and/or
client loggging. In varnishevent, this is determined by whether output
formats are specified for client or backend logging in the
configuration.

FORMAT
======

The ``-F`` option specifies the format for client transactions, and
the configuration parameters ``cformat``, ``bformat`` and ``rformat``
specify formats for client, backend and raw transactions,
respectively. Both of the ``cformat`` and ``bformat`` parameters may
be specified to log both client and backend transactions; but if the
``rformat`` parameter is set, only raw transactions are logged, and
the other two parameters may not be set.

By default, varnishevent presents client transactions in this format::

  %h %l %u %t "%r" %s %b "%{Referer}i" "%{User-agent}i"

The ``cformat`` parameter has this value by default. If client
transactions should not be logged, set ``cformat`` to empty
(``cformat=`` in the configuration file, with no value).

Escape sequences \\n and \\t are supported.

The following formatters can be used, for the ``-F`` option or the
config values for client or backend transactions. For raw
transactions, only the formatters ``%t``, ``%{X}t``, ``%{tag}x`` and
``%{vxid}x`` are permitted.

%b 
  Size of response in bytes, excluding HTTP headers.  The value is 0
  when no bytes are sent (whereas varnishncsa emits a '-').

%D
  Time taken to serve the request, in microseconds.

%d
  The 'direction' of the logged event: ``c`` for client transactions,
  ``b`` for backend transactions, and the empty string otherwise.

%H 
  The request protocol. Defaults to HTTP/1.0 if not known.

%h
  Remote host. Empty string if unknown. (varnishncsa defaults to '-'
  or 127.0.0.1)

%I
  Total bytes received in the request.

%{X}i
  The contents of request header X.

%l
  Remote logname (always '-')

%m
  Request method. Empty string if unknown (varnishncsa defaults to
  '-'.)

%{X}o
  The contents of response header X.

%O
  Total bytes sent in the response.

%q
  The query string, if no query string exists, an empty string.

%r
  The first line of the request. Synthesized from other fields, so it
  may not be the request verbatim.

%s
  Status sent in the response.

%t
  Time when the request was received, in HTTP date/time format. For
  raw transactions, the time at which the transaction was read from
  the Varnish log.

%{X}t
  Time when the request was received, or the log read time for raw
  transactions, in the format specified by X.  The time specification
  format is the same as for strftime(3), with the addition of the
  formatter ``%i`` for the subsecond in microseconds.

%T
  Time taken to serve the request, in seconds.

%U
  The request URL without any query string. Empty if
  unknown. (varnishncsa defaults to '-'.)

%u
  Remote user from auth

%{X}x
  Extended variables.  Supported variables are:

  Varnish:time_firstbyte
    Time from when the request processing starts until the first byte
    of the response is sent.

  Varnish:hitmiss
    Whether the request was a cache hit or miss. Pipe and pass are
    considered misses. This formatter is only permitted for client
    transactions.

  Varnish:handling
    How the request was handled, whether it was a cache hit, miss,
    pass, pipe or error. This formatter is only permitted for client
    transactions.
	
  VCL_Log:key
    Output value set by std.log("key: value") in VCL.

  tag:tagname{:header}{[field]}
    The raw payload in the log for any entry with the tag ``tagname``;
    e.g. ``%{tag:ReqEnd}x``.  The contents of the payload may be
    restricted by header or field specifiers, as explained below.

  vxid
    The transaction XID (an ID set by Varnish).
		     
  pvxid
    The parent transaction XID. Always 0 except when request grouping
    is specified.
		     
If a header specifier is used with the ``%{tag}x`` formatter, then
only log payloads including that header (with the header name followed
by a colon) are formatted, excluding the header.

If a field specifier is used with ``%{tag}x``, where the field is a
number ``n``, then the formatter yields the nth whitespace-separated
field in the log payload for that tag, counting from 0.

Header and field specifiers may be combined, to specify a field in the
log payload prefixed by a header.

For example, if a log transaction contains these records::

	Timestamp      Resp: 1429726861.731394 0.000195 0.000060
	Backend        29 foo_d foo_b(127.0.0.1,,80)

then:

  ``%{tag:Backend}x`` yields ``29 foo_d foo_b(127.0.0.1,,80)``

  ``%{tag:Timestamp:Resp}`` yields ``1429726861.731394 0.000195 0.000060``

  ``%{tag:Backend[2]}x`` yields ``foo_b(127.0.0.1,,80)``

  ``%{tag:Timestamp:Resp[1]}`` yields ``0.000195``


REQUIREMENTS
============

This version of varnishevent requires Varnish 4.1.3 through 5.0.0.
See the project repository for version that are compatible with other
versions of Varnish.


DATA BUFFERS
============

To configure and monitor varnishevent, it is important to understand a
few of its internals. Log reads and writes are asynchronous -- a
reader thread reads from the Varnish log and saves data in buffers,
while a writer thread reads from the buffer and writes formatted
output.

Objects in the buffer are *transactions*, *records* and *chunks*. A
transaction is the complete log of an event in Varnish, consisting of
a number of records. Records are single log entries comprising a tag and
a payload, corresponding to a line of varnishlog(3) output.

The maximal length of a log payload is set by the config parameter
``max.reclen``, which should be equal to the varnishd parameter
``shm_reclen`` (payloads longer than the maximum are truncated). Since
a large majority of log payloads are typically much shorter than the
maximum, varnishevent divides them into smaller buffers called
*chunks*. The reader thread only copies into as many chunks as are
necessary to contain a log payload.

The ``max.data`` parameter sets the maximum number of transactions
that can be stored in the buffers; varnishevent computes the maximum
number of records and chunks necessary for that many transactions, as
required for the output formats.

Free entries in the buffers for transactions, records and chunks are
structured in free lists. The reader and writer threads each have
local free lists, and exchange data with global free lists. That is,
the reader thread takes free entries from its local free lists, and
gets new entries from the global lists when the local lists are
exhausted. The writer thread returns free data to its local free
lists, and returns its free lists to the global free lists
periodically.

If the reader thread cannot obtain free data from the buffers --
meaning that the buffers are full and the writer thread has not yet
returned free data -- then the reader may wait up to the interval set
by ``reader.timeout``, if it is non-zero. If the timeout is zero, or
if it expires and no free data become available, the reader discards
the transaction that it is currently reading from the Varnish log. No
data are buffered from the transaction, leading to a loss of data in
the varnishevent output.

Thus the configuration determines the memory footprint of
varnishevent, and whether the buffers are large enough to accomodate
pending data during load spikes, and when output channels are
slow. Monitoring statistics expose the state of the buffers.

CONFIGURATION
=============

Configuration values are set either from configuration files or
command-line options, in this hierarchy:

1. ``/etc/varnishevent.conf``, if it exists and is readable
2. a config file specified with the ``-f`` option
3. config values specified with other command-line options

If the same config parameter is specified in one or more of these
sources, then the value at the "higher" level is used. For example, if
``output.file`` is specified in both ``/etc/varnishevent.conf`` and a
``-f`` file, then the value from the ``-f`` file is used, unless a
value is specified with the ``-w`` option, in which case that value is
used.

The syntax of a configuration file is simply::

        # comment
        <param> = <value>

The ``<value>`` is all of the data from the first non-whitespace
character after the equals sign up to the last non-whitespace
character on the line. Comments begin with the hash character and
extend to the end of the line. There are no continuation lines.

All of the config parameters have default values, and some of them
correspond to command-line options, as shown below.

====================== ========== ========================================================================================= =======
Parameter              CLI Option Description                                                                               Default
====================== ========== ========================================================================================= =======
``output.file``        ``-w``     File to which logging output is written.                                                  ``stdout``
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``append``             ``-a``     (Boolean) Whether to append to ``output.file``.                                           false
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``output.bufsiz``                 Size of the buffer for output operations, used for setvbuf(3)                             ``BUFSIZ`` at compile time
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``varnish.bindump``    ``-r``     A binary dump of the Varnish shared memory log obtained from ``varnishlog -B -w``. If a   none
                                  value is specified, ``varnishevent`` reads from that file instead of a live Varnish log
                                  (useful for testing, debugging and replaying traffic). This parameter and the ``-n`` or
                                  ``-N`` options are mutually exclusive.
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``cformat``            ``-F``     Output format for client transactions, using the formatter syntax shown for the ``-F``    default for ``-F``
                                  option above. By default, client transactions are logged, using the default format
                                  shown above. If you don't want to log client transactions, set ``cformat`` to the empty
                                  string.
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``bformat``                       Output format for backend transactions.                                                   empty
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``rformat``                       Output format for raw transactions. May not be combined with ``cformat``, ``bformat`` or  empty
                                  the ``-F`` option. When this format is specified, the Varnish log is read with raw
                                  grouping (regardless of any value of the ``-g`` option).
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``max.data``                      Maximum number of transactions. This value should be large enough for the highest number  4096
                                  transactions that are buffered and waiting for output.
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``chunk.size``                    The size of chunk buffers in bytes. Only as many chunks as necessary are used to buffer   64
                                  log payloads.
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``max.reclen``                    The maximum length of a Varnish log entry in characters. Should be equal to the Varnish   255 (default ``shm_reclen`` in Varnish 4)
                                  parameter ``shm_reclen``.
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``log.file``           ``-l``     Log file for status, warning, debug and error messages, and monitoring statistics. If '-' ``syslog(3)``
                                  is specified, then log messages are written to stdout.
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``monitor.interval``              Interval in seconds at which monitoring statistics are emitted to the log (either         30
                                  ``syslog(3)`` or ``log.file``). If set to 0, then no statistics are logged.
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``syslog.facility``               See ``syslog(3)``; legal values are ``user`` or ``local0`` through ``local7``. If         ``local0``
                                  ``log.file`` is non-empty, this parameter is ignored.
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``syslog.ident``                  See ``syslog(3)``; this parameter is useful to distinguish ``varnishevent`` processes in  ``varnishevent``
                                  the syslog if more than one is running on the system.
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``output.timeout``                Output timeout in seconds used by the writer thread. If the timeout is set and the output 0
                                  stream is not ready when it elapses, the transaction to be output is discarded. If 0, the
                                  writer waits indefinitely.
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``reader.timeout``                Timeout in seconds used by the reader thread to wait for free data. If the reader         0
                                  encounters an empty free list and ``reader.timeout`` > 0, then it will wait until either
                                  data become available, or the timeout expires. If 0, the reader discards the transaction
                                  immediately.
====================== ========== ========================================================================================= =======

LOGGING AND MONITORING
======================

By default, ``varnishevent`` uses ``syslog(3)`` for logging with facility
``local0`` (unless otherwise specified by configuration as shown
above). In addition to informational, error and warning messages about
the running process, monitoring information is periodically emitted
to the log (as configured with the parameter
``monitor.interval``). The monitoring logs have this form (at the
``info`` log level, with additional formatting of the log lines,
depending on how syslog is configured)::

 Data tables: len_tx=5000 len_rec=70000 len_chunk=4480000 tx_occ=0 rec_occ=0 chunk_occ=0 tx_occ_hi=4 rec_occ_hi=44 chunk_occ_hi=48 global_free_tx=0 global_free_rec=0 global_free_chunk=0
 Reader:  (sleeping) seen=68 submitted=68 free_tx=5000 free_rec=70000 free_chunk=4480000 no_free_tx=0 no_free_rec=0 no_free_chunk=0 len_hi=1712 len_overflows=0 eol=67 idle_pause=0.010000 closed=0 overrun=0 ioerr=0 reacquire=0
 Writer (waiting): seen=68 writes=68 bytes=35881 errors=0 timeouts=0 waits=53 free_tx=0 free_rec=0 free_chunk=0 pollt=0.000000 writet=0.000150
 Queue: max=5000 len=0 load=0.00 occ_hi=4

The line prefixed by ``Data tables`` describes the data buffers. The
``len_*`` fields are constant, and the ``*_occ_hi`` fields are
monotonic increasing; all other fields in the ``Data tables`` line are
gauges (expressing a current state, which may rise and fall).

===================== =============================================
Field                 Description
===================== =============================================
``len_tx``            Size of the transaction table (always equal
                      to ``max.data``)
--------------------- ---------------------------------------------
``len_rec``           Size of the record table
--------------------- ---------------------------------------------
``len_chunk``         Size of the chunk table
--------------------- ---------------------------------------------
``tx_occ``            Current number of buffered transactions
--------------------- ---------------------------------------------
``rec_occ``           Current number of buffered records
--------------------- ---------------------------------------------
``chunk_occ``         Current number of buffered chunks
--------------------- ---------------------------------------------
``tx_occ_hi``         Transaction occupancy high watermark --
                      highest number of bufferend transactions
                      since startup
--------------------- ---------------------------------------------
``rec_occ_hi``        Record occupancy high watermark
--------------------- ---------------------------------------------
``chunk_occ_hi``      Chunk occupancy high watermark
--------------------- ---------------------------------------------
``global_free_tx``    Current length of the global transaction free
                      list
--------------------- ---------------------------------------------
``global_free_rec``   Current length of the global record free list
--------------------- ---------------------------------------------
``global_free_chunk`` Current length of the global chunk free list
===================== =============================================

The line prefixed by ``Reader`` describes the state of the thread that
reads from Varnish shared memory and writes to data tables. The thread
is any one of these states:

* ``initializing``
* ``running``
* ``sleeping``
* ``waiting``
* ``shutting down``

The thread is in the ``sleeping`` state when it has reached the end
of the Varnish log, and pauses briefly before attempting to read new
data. It is in the ``waiting`` state when it has encountered an empty
free list, and is waiting for either data to become free, or for the
``reader.timeout`` to expire.

A transaction is ``seen`` when it is read from the Varnish log, and
``submitted`` when it is queued for processing by the writer
thread. Transactions with no data required for the output formats are
not submitted.

When the reader thread is unable to read from the Varnish log, it may
be because the log was ``closed`` or abandoned (for example when
varnishd stops); because it was ``overrun`` (varnishd has cycled
around in its ring buffer and overtaken the read location of
varnishevent); or due to an I/O error (``ioerr``). When this happens,
the reader asks the Varnish log API to flush pending transactions,
which are buffered for writing, and attempts to re-acquire the log
(``reacquire``).

The ``free_*`` and ``idle_pause`` fields are gauges, and ``len_hi`` is
monotonic increasing. All of the other fields are cumulative counters:

=================== ===========================================================
Field               Description
=================== ===========================================================
``seen``            Number of transactions read from the Varnish log
------------------- -----------------------------------------------------------
``submitted``       Number of transactions submitted on the queue to the
                    writer thread
------------------- -----------------------------------------------------------
``free_tx``         Number of transactions in the reader thread's local free
                    list
------------------- -----------------------------------------------------------
``free_rec``        Number of records in the reader thread's local free list
------------------- -----------------------------------------------------------
``free_chunk``      Number of chunks in the reader thread's local free list
------------------- -----------------------------------------------------------
``no_free_tx``      Number of times that no free transactions were available
------------------- -----------------------------------------------------------
``no_free_rec``     Number of times that no free records were available
------------------- -----------------------------------------------------------
``no_free_chunk``   Number of times that no free chunks were available
------------------- -----------------------------------------------------------
``len_hi``          Length high watermark -- longest log payload since startup
                    (in bytes)
------------------- -----------------------------------------------------------
``len_overflows``   Number of Varnish log payloads seen with a length greater
                    than ``max.reclen``
------------------- -----------------------------------------------------------
``eol``             Number of times the reader thread reached the end of the
                    Varnish log and paused
------------------- -----------------------------------------------------------
``idle_pause``      Current length in seconds of an idle pause at end of log
                    (periodically adjusted to match the transaction read rate)
------------------- -----------------------------------------------------------
``closed``          Number of times the Varnish log was closed or abandoned
------------------- -----------------------------------------------------------
``overrun``         Number of times log reads were overrun
------------------- -----------------------------------------------------------
``ioerr``           Number of times log reads failed due to I/O errors
------------------- -----------------------------------------------------------
``reacquire``       Number of times the Varnish log was re-acquired
=================== ===========================================================

The line prefixed by ``Writer`` describes the thread that reads from
the data table and writes formatted output. The thread is any one of
these states:

* ``not started``
* ``initializing``
* ``running``
* ``waiting``
* ``shutting down``
* ``exited``

The writer is in the waiting state when there are no transactions
waiting on the queue from the reader thread.

The ``free_*`` fields are gauges; all of the fields in the ``Writer``
log line are cumulative counters:

=================== ===========================================================
Field               Description
=================== ===========================================================
``seen``            Number of records read from the internal queue
------------------- -----------------------------------------------------------
``writes``          Number of successful write operations
------------------- -----------------------------------------------------------
``bytes``           Number of bytes successfully written
------------------- -----------------------------------------------------------
``errors``          Number of write errors
------------------- -----------------------------------------------------------
``timeouts``        Number of timeouts waiting for ready output
------------------- -----------------------------------------------------------
``waits``           Number of wait states entered by the writer thread
------------------- -----------------------------------------------------------
``free_tx``         Current number of transactions in the writer's local free list
------------------- -----------------------------------------------------------
``free_rec``        Current number of records in the writer's local free list
------------------- -----------------------------------------------------------
``free_chunk``      Current number of chunks in the writer's local free list
------------------- -----------------------------------------------------------
``pollt``           Cumulative time since startup (in seconds) that the writer
                    thread has spent polling the output stream waiting for the
                    ready state.
------------------- -----------------------------------------------------------
``writet``          Cumulative time since startup (in seconds) that the writer
                    thread has spent writing data to the output stream.
=================== ===========================================================

The line prefixed by ``Queue`` describes the internal queue into which
the reader thread submits buffered transactions, and from which the
writer thread consumes transactions. The fields ``max``, ``len`` and
``load`` are gauges, and ``occ_hi`` is monotonic increasing:

=================== ===========================================================
Field               Description
=================== ===========================================================
``max``             Maximum length of the queue (always equal to ``max.data``)
------------------- -----------------------------------------------------------
``len``             Current length of the queue
------------------- -----------------------------------------------------------
``load``            Current length of the queue as percent
                    (100 * ``len`` / ``max``)
------------------- -----------------------------------------------------------
``occ_hi``          Occupancy high watermark -- highest length of the queue
                    since startup
=================== ===========================================================

SIGNALS
=======

``varnishevent`` responds to the following signals (all other signals
have default handlers):

====== =======================
Signal Response
====== =======================
TERM   Shutdown
------ -----------------------
INT    Shutdown
------ -----------------------
HUP    Re-open output
------ -----------------------
PIPE   Re-open output
------ -----------------------
USR1   Flush pending transactions
       from Varnish
------ -----------------------
USR2   Dump pending data to log
------ -----------------------
ABRT   Abort with stacktrace
------ -----------------------
SEGV   Abort with stacktrace
------ -----------------------
BUS    Abort with stacktrace
====== =======================

The ``HUP`` signal is ignored if ``varnishevent`` is configured to
write output to ``stdout``; otherwise, it re-opens its output file,
allowing for log rotation.

On receiving signal ``USR1``, varnishevent requests the Varnish log
API to flush all transactions that it is currently aggregating, even
if they are not yet complete (to the ``End`` tag).  These are consumed
by the reader thread and processed normally (although data may be
missing).

On receiving signal ``USR2``, varnishevent writes the contents of all
transactions in the internal buffers to the log (syslog, or log file
specified by config), for troubleshooting or debugging.

Where "abort with stacktrace" is specified above, ``varnishevent``
writes a stack trace to the log (syslog or otherwise) before aborting
execution; in addition, it executes the following actions:

* dump the current configuration
* dump the contents of pending transactions in the data buffers (as
  for the ``USR1`` signal)
* emit the monitoring stats

RETURN VALUES
=============

``varnishevent`` returns 0 on normal termination, and non-zero on
error.

SEE ALSO
========

* varnishd(1)
* varnishncsa(1)
* project repository: https://code.uplex.de/uplex-varnish/varnishevent

HISTORY
=======

Written by Geoffrey Simmons <geoffrey.simmons@uplex.de>, UPLEX Nils
Goroll Systemoptimierung, in cooperation with Otto Gmbh & Co KG.

The varnishncsa utility was developed by Poul-Henning Kamp in
cooperation with Verdens Gang AS and Varnish Software AS.  The manual
page for varnishncsa was initially written by Dag-Erling Smørgrav
⟨des@des.no⟩, and later updated by Martin Blix Grydeland.


COPYRIGHT AND LICENCE
=====================

For both the software and this document are governed by a BSD 2-clause
licence.

| Copyright (c) 2012-2016 UPLEX Nils Goroll Systemoptimierung
| Copyright (c) 2012-2016 Otto Gmbh & Co KG
| All rights reserved

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.

varnishncsa and its documentation are licensed under the same licence
as Varnish itself. See LICENCE in the Varnish distribution for
details.

* Copyright (c) 2006 Verdens Gang AS
* Copyright (c) 2006-2016 Varnish Software AS
