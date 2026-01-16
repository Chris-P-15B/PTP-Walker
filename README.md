# PTP-Walker
Copyright (c) 2025 - 2026, Chris Perkins.

From a given seed device, walks up the PTP Slave port path towards the Grand Master, using LLDP to
discover upstream devices. It captures PTP & interface information, then displays any possible
concerns it finds to aid troubleshooting.
Works with Arista EOS & Cisco NX-OS.

Version History:

* v1.0 - Initial public release.
* v0.4 - Tidying, bug fixes & added PTP interface commands check.
* v0.3 - Bug fixes.
* v0.2 - Fixed typos & improved formatting of output.
* v0.1 - Initial development release.

# Pre-Requisites
* Python 3.7+
* Hostnames learnt via LLDP must be resolvable via DNS

# Usage
Within _PTP_walker.py_ there are some variables to customise to match your environment.

## Thresholds to check against
Defaults:
```
MAX_OFFSET = 250
MAX_MEAN_PATH_DELAY = 1500
MAX_ACCURACY = 39
SYNCHED_CLOCK_CLASS = ["6", "13"]
HOLDOVER_CLOCK_CLASS = ["7", "14"]
```

Explanation:\
Offset from master threshold of +/-250ns.\
Mean path delay threshold of 1500ns.\
Clock accuracy threshold of 39 decimal = 100us (0x27 hexadecimal).\
Clock classes considered synched to GNSS or atomic clock:\
Class 6 traces clock signals of the primary reference time source. The timescale distributed is the Precise Time Protocol (PTP).\
Class 13 synchronizes clock signals with a specific clock source. The timescale distributed is arbitrary waveform (ARB).\
\
Clock classes that were synched, but are in holdover:\
If a clock of class 6 becomes incapable of tracing clock signals of the primary reference time source, the clock obtains class 7 and works in hold mode. The timescale distributed is PTP.\
If a clock of class 13 becomes incapable of tracing clock signals of a specific clock source, the clock obtains class 14 and works in hold mode. The timescale distributed is ARB.

## List of interface commands for PTP that should be present
For example ["ptp", "ptp delay-request minimum interval 3", "ptp announce interval 2", "ptp sync interval 0"].
Refer to NX-OS or EOS configuration guides for details on customising PTP.\
Defaults are just minimum enabling of PTP:
```
NXOS_PTP_COMMANDS = ["ptp"]
EOS_PTP_COMMANDS = ["ptp enable"]
```