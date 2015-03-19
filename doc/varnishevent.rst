============
varnishevent
============

----------------------------------------------------------------------------
Display Varnish log contents in formats for client, backend and other events
----------------------------------------------------------------------------

:Author: Geoffrey Simmons
:Date:   2013-12-03
:Version: 1.0
:Manual section: 1


SYNOPSIS
========

varnishevent [-a] [-C] [-D] [-d] [-f] [-F format] [-g] [-G configfile]
             [-I regex] [-i tag] [-n varnish_name] [-m tag:regex ...] [-P file]
             [-r file] [-V] [-w file] [-X regex] [-x tag]


DESCRIPTION
===========

The varnishevent utility reads varnishd(1) shared memory logs and
presents them one line per event, where an event is one or more of a
client transaction (request/response), backend transaction, or an
event logged with the pseudo file descriptor 0, such as a backend
health check. By specifying output formats in the configuration,
you decide which of the three kinds of transactions are logged.

By default, varnishevent functions almost exactly as varnishncsa(1) --
it outputs client transaction events in the default format shown below
for the ``-F`` option.

Differences between varnishevent and varnishncsa(1) are noted in the
following.  In most cases, the difference is that varnishevent emits
an empty string for data that are absent or unknown, whereas
varnishncsa emits a '-'.

OPTIONS
=======

-a          When writing to a file, append to it rather than overwrite it.

-C          Ignore case when matching regular expressions.

-D          Daemonize.

-d          Process old log entries on startup.  Normally, varnishevent 
	    will only process entries which are written to the log 
	    after it starts.

-f          Prefer the X-Forwarded-For HTTP header over client.ip in 
	    the default format for client transactions.

-F format   Specify the format for client transactions. By default,
            varnishevent presents client transactions in this format:

            %h %l %u %t "%r" %s %b "%{Referer}i" "%{User-agent}i"

	    Escape sequences \\n and \\t are supported.

	    These formatters can be used, for the ``-F`` option or
            any of the format specifications in the configuration
            file.

	      %b 
	         Size of response in bytes, excluding HTTP headers.
   	         The value is 0 when no bytes are sent (whereas 
                 varnishncsa emits a '-').

              %d
                 The 'direction' of logged event: ``c`` for client
                 transactions, ``b`` for backend transactions, and
                 the empty string otherwise.

	      %H 
	         The request protocol. Empty string if unknown.
                 (varnishncsa defaults to HTTP/1.0 if not known.)

              %h
	         Remote host. Empty string if unknown.
                 (varnishnsa defaults to '-' or 127.0.0.1)

	      %{X}i
	         The contents of request header X.

	      %l
	         Remote logname (always '-')

	      %m
	         Request method. Empty string if unknown
                 (varnishncsa defaults to '-'.)

	      %q
	         The query string, if no query string exists, an
                 empty string.

	      %{X}o
	         The contents of response header X.

	      %r
	         The first line of the request. Synthesized from other
                 fields, so it may not be the request verbatim.

	      %s
	         Status sent to the client or received from the
	         backend.

	      %t
	         Time when the request was received, in HTTP date/time
	         format.

	      %{X}t
	         Time when the request was received, in the format
		 specified by X.  The time specification format is the
		 same as for strftime(3).

	      %U
	         The request URL without any query string. Empty if
                 unknown. (varnishncsa defaults to '-'.)

	      %u
	         Remote user from auth

	      %{X}x
	         Extended variables.  Supported variables are:

		   Varnish:time_firstbyte
		     Time to the first byte from the backend arrived

		   Varnish:hitmiss
		     Whether the request was a cache hit or miss. Pipe
		     and pass are considered misses.

		   Varnish:handling
		     How the request was handled, whether it was a
		     cache hit, miss, pass, pipe or error.
	
		   VCL_Log:key
		     Output value set by std.log("key: value") in VCL.
                     varnishevent requires the space after the colon,
                     so that the log entries have the same syntax as
                     a header.

		   tag:tagname
		     The raw payload in the log for any entry with
                     the tag ``tagname``; e.g. ``%{tag:ReqEnd}x``.

		   incomplete:Y:N
		     Emits the string ``Y`` or ``N``, depending on
                     whether varnishevent was able to read the entire
                     transaction before a timeout elapsed.
                     e.g. ``%{incomplete:true:false}x``
                     See the config parameter ``ttl`` below

-g          Set the log level for syslog(3) to LOG_DEBUG

-G file     Read configuration from the specified filexs	     

-m tag:regex  only list records where tag matches regex. Multiple
              -m options are AND-ed together.

-n          Specifies the name of the varnishd instance to get logs 
	    from.  If -n is not specified, the host name is used.

-P file     Write the process's PID to the specified file.

-r file     Read log entries from file instead of shared memory.

-V          Display the version number and exit.

-w file     Write log entries to file instead of displaying them.  
   	    The file will be overwritten unless the -a
	    option was specified.
	    
	    If varnishevent receives a SIGHUP while writing to a file, 
	    it will reopen the file, allowing the old one to be 
	    rotated away.

-X regex    Exclude log entries which match the specified 
   	    regular expression.

-x tag      Exclude log entries with the specified tag.

If the -m option was specified, a tag and a regex argument must be given.
varnishevent will then only log for request groups which include that tag
and the regular expression matches on that tag.

CONFIGURATION
=============

Configuration values are set either from configuration files or
command-line options, in this hierarchy:

1. ``/etc/varnishevent.conf``, if it exists and is readable
2. a config file specified with the ``-G`` option
3. config values specified with other command-line options

If the same config parameter is specified in one or more of these
sources, then the value at the "higher" level is used. For example, if
``varnish.name`` is specified in both ``/etc/varnishevent.conf`` and a
``-G`` file, then the value from the ``-G`` file is used, unless a
value is specified with the ``-n`` option, in which case that value is
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
``varnish.name``       ``-n``     Like the ``-n`` option for Varnish, this is the path to the file that is mmap'd to the    default for Varnish (the host name)
                                  shared memory segment for the Varnish log. This parameter and ``varnish.bindump`` are
                                  mutually exclusive.
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``output.file``        ``-w``     File to which logging output is written.                                                  ``stdout``
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``append``             ``-a``     (Boolean) Whether to append to ``output.file``.                                           false
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``output.bufsiz``                 Size of the buffer for output operations, used for setvbuf(3)                             ``BUFSIZ`` at compile time
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``varnish.bindump``    ``-r``     A binary dump of the Varnish shared memory log obtained from ``varnishlog -w``. If a
                                  value is specified, ``varnishevent`` reads from that file instead of a live Varnish log
                                  (useful for testing, debugging and replaying traffic). This parameter and
                                  ``varnish.name`` are mutually exclusive.
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``cformat``            ``-f``     Output format for client transactions, using the formatter syntax shown for the ``-f``    default for ``-f``
                                  option above. By default, client transactions are logged, using the default format
                                  shown above. If you don't want to log client transactions, set ``cformat`` to the empty
                                  string.
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``bformat``                       Output format for backend transactions.                                                   empty
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``zformat``                       Output format for entries with the pseudo file descriptor zero in the Varnish log (i.e.   empty
                                  ``0`` appears in the left column of varnishlog(1)).
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``max.fd``                        Maximum file descriptor number used in the Varnish log. For best results, set this value  1024
                                  to the open file descriptor limit (``ulimit -n``) for the varnishd process.
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``max.data``                      Maximum number of data records. Data records are opened for each new transaction seen in  4096
                                  the Varnish log, and closed once their formatted output has been emitted to the ouput
                                  stream. So this value should be large enough for the highest number of concurrently
                                  unfinished transactions in the Varnish log, plus the highest number of finished records
                                  that are buffered and waiting for output.
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``max.reclen``                    The maximum length of a Varnish log entry in characters. Should be equal to the Varnish   255 (default ``shm_reclen`` in Varnish 3)
                                  parameter ``shm_reclen``.
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``max.headers``                   The maximum number of request or response headers recorded for a transaction in the       64 (default ``http_max_hdr`` in Varnish 3)
                                  Varnish log. Should be equal to the Varnish parameter ``http_max_hdr``.
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``max.vcl_log``                   The maximum number of VCL_Log entires recorded for a transaction in the Varnish log.      64
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``max.vcl_call``                  The maximum number of VCL_call entires recorded for a transaction in the Varnish log      64
                                  (used to obtain the ``%{Varnish:hitmiss}x`` and ``%{Varnish:handling}x`` results).
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``ttl``                           Maximum time to live in seconds for an unfinished record. If the closing tag of a (client 120
                                  or backend) transaction is not read within this time, then ``varnishevent`` no longer
                                  waits for it, and schedules the data read thus far to be written to output. If the
                                  formatter ``%{incomplete:T:F}x`` is specified for the output, the second string (``F``)
                                  is emitted if ``ttl`` has elapsed, otherwise the first string (``T``). The value should
                                  be a bit longer than the sum of all timeouts configured for a Varnish request.
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``housekeep.interval``            The interval in seconds between checks for data records whose ``ttl`` has expired.        10
---------------------- ---------- ----------------------------------------------------------------------------------------- -------
``log.file``                      Log file for status, warning, debug and error messages, and monitoring statistics. If '-' ``syslog(3)``
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

 Data table: len=10000 open=82 done=0 load=0.82 occ_hi=10000 global_free=7709
 Reader (running): fd_max=10000 seen=559921834 open=82 load=0.82 submitted=247566967 not_logged=312354785 occ_hi=1807 waits=17279 expired=55 free=2209 len_hi=2048 fd_overflows=1 len_overflows=0 hdr_overflows=0 spec_mismatches=0 wrong_tags=0
 Writer (waiting): seen=247566967 writes=247566967 bytes=139367701123 errors=3 waits=17736487 free=0
 Queue: max=10000 len=0 load=0.00 occ_hi=9986

The line prefixed by ``Data table`` describes the table to which data
is copied from Varnish shared memory. A record is in the state
``open`` if the opening but not the closing tag for a transaction has
been read from the log; and in the state ``done`` if the closing tag
has been read, but the record has not yet been written to output. All
of the fields in the ``Data table`` line are gauges (expressing a
current state), except for ``occ_hi``, which is monotonic increasing:

=============== ============================================================
Field           Description
=============== ============================================================
``len``         Size of the data table (always equal to ``max.data``
--------------- ------------------------------------------------------------
``open``        Current number of open records in the table
--------------- ------------------------------------------------------------
``done``        Current number of records in state "done"
--------------- ------------------------------------------------------------
``load``        Current number of non-empry records in the table as percent
                (100 * (``open`` + ``done``)/``len``)
--------------- ------------------------------------------------------------
``occ_hi``      Occupancy high watermark -- highest number of records (open
                and done) since startup
--------------- ------------------------------------------------------------
``global_free`` Current number of records in the global free list
=============== ============================================================

The line prefixed by ``Reader`` describes the state of the thread that
reads from Varnish shared memory and writes to the data table. The
reader thread accesses a file descriptor table (fd table), which maps
to the data table and is indexed by the file descriptor number in the
Varnish log entry (the number in the left column of
``varnishlog(1)``). The reader maintains its own free list for the
data table, which is replenished from the global free list when
exhausted. If the reader cannot obtain a free data record, it goes
into a waiting state (waiting for the writer thread to output data and
free records). Thus the reader is in one of the states ``running`` or
``waiting`` after initialization.

A transaction is ``seen`` if its opening tag has been read. A data
record is ``submitted`` if the closing tag of the transaction has been
read and the record has been placed on the queue consumed by the
writer thread, and ``not_logged`` if its closing tag has been read,
but it does not contain any data needed for the output formats.  A
record is ``expired`` if its TTL has elapsed, so that it is placed on
the queue and considered done.

A ``spec_mismatch`` occurs when the reader thread has detected a
transaction in the Varnish log as a client or backend transaction, but
lines later in the log for the same fd indicate that it is the other
kind. ``wrong_tags`` occur when a tag is read that is not anticipated
for formatting output.

The fields ``fd_max``, ``open``, ``load`` and ``free`` are gauges;
``occ_hi`` and ``len_hi`` are monotonic increasing. All of the other
fields are cumulative counters:

=================== ===========================================================
Field               Description
=================== ===========================================================
``fd_max``          Size of the fd table (always equal to ``max.fd``
------------------- -----------------------------------------------------------
``seen``            Number of transactions seen
------------------- -----------------------------------------------------------
``open``            Number of open records indexed in the fd table
------------------- -----------------------------------------------------------
``load``            Current number of open records in the fd table as percent
                    (100 * ``open`` / ``len``)
------------------- -----------------------------------------------------------
``submitted``       Number of records submitted
------------------- -----------------------------------------------------------
``not_logged``      Number of records seen but not submitted
------------------- -----------------------------------------------------------
``occ_hi``          Occupancy high watermark of the fd table -- highest number
                    of open records indexed in the table since startup
------------------- -----------------------------------------------------------
``waits``           How many times the reader thread went into the ``waiting``
                    state
------------------- -----------------------------------------------------------
``expired``         Number of records for which ``ttl`` expired
------------------- -----------------------------------------------------------
``free``            Number of records in the reader threads local free list
------------------- -----------------------------------------------------------
``len_hi``          Length high watermark -- longest record since startup (in
                    bytes)
------------------- -----------------------------------------------------------
``fd_overflows``    Number of Varnish log lines seen with an fd greater than
                    ``max.fd``
------------------- -----------------------------------------------------------
``len_overflows``   Number of Varnish log lines seen with a length greater
                    than ``max.reclen``
------------------- -----------------------------------------------------------
``hdr_overflows``   Number of Varnish log transactions seen with more headers
                    than ``max.headers``
------------------- -----------------------------------------------------------
``spec_mismatches`` Number of spec mismatches found in the Varnish log
------------------- -----------------------------------------------------------
``wrong_tags``      Number of wrong tags found in the Varnish log
=================== ===========================================================

The line prefixed by ``Writer`` describes the state of the thread that
reads from the data table and writes formatted output. The thread is
any one of these states:

* ``not started``
* ``initializing``
* ``running``
* ``waiting``
* ``shutting down``
* ``exited``

The writer is in the waiting state when the queue from which it reads
data records that are ready for output is exhausted. It maintains a
free list of records whose output is completed, and the free list is
returned to the global free list when the writer thread is idle.

All of the fields in the ``Writer`` log line are cumulative counters,
except for the gauge ``free``:

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
``waits``           Number of wait states entered by the writer thread
------------------- -----------------------------------------------------------
``free``            Current number of records in the writer's local free list
=================== ===========================================================

The line prefixed by ``Queue`` describes the internal queue into which the
reader thread submits data records ready for output, and from which the
writer thread consumes records. The fields ``max``, ``len`` and ``load``
are gauges, and ``occ_hi`` is monotonic increasing:

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
USR1   Dump data table to log
------ -----------------------
USR2   Ignore
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

On receiving signal ``USR1``, the ``varnishevent`` writes the contents
of all records in the "open" or "done" states to the log (syslog, or
log file specified by config), for troubleshooting or debugging.

Where "abort with stacktrace" is specified above, ``varnishevent``
writes a stack trace to the log (syslog or otherwise) before aborting
execution; in addition, it executes the following actions:

* dump the current configuration
* dump the current contents of the data table (as for the ``USR1`` signal)
* emit the monitoring stats

RETURN VALUES
=============

``varnishevent`` returns 0 on normal termination, and non-zero on
error.

SEE ALSO
========

* varnishd(1)
* varnishncsa(1)

HISTORY
=======

Written by Geoffrey Simmons <geoffrey.simmons@uplex.de>, UPLEX Nils
Goroll Systemoptimierung, in cooperation with Otto Gmbh & Co KG.

The varnishncsa utility was developed by Poul-Henning Kamp in
cooperation with Verdens Gang AS and Varnish Software AS.  The manual
page for varnishncsa was written by Dag-Erling Smørgrav ⟨des@des.no⟩.


COPYRIGHT AND LICENCE
=====================

For both the software and this document are governed by a BSD 2-clause
licence.

| Copyright (c) 2012-2013 UPLEX Nils Goroll Systemoptimierung
| Copyright (c) 2012-2013 Otto Gmbh & Co KG
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
* Copyright (c) 2006-2011 Varnish Software AS
