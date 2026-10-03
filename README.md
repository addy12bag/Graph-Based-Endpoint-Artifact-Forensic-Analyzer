# Who is compromised?



Organisation X runs about 250 Linux desktops in 19 units. Every desktop runs an endpoint agent that reports which
internet destinations it contacts, a nightly antivirus scan, a quarantine service, a web filter and USB monitoring.
You have been handed the agent logs for two weeks in September 2026.

**Your task: identify which endpoints are compromised and how, and suggest remedial measures.**



## Safety first

The web logs contain **real internet names and addresses, some of them malicious.** Do not open them in a browser and
do not connect to them from your own machine. Passive research is fine: public threat-intelligence lists, WHOIS,
passive DNS and published reports.

## The files

|File|Rows|Covers|What it is|
|-|-|-|-|
|`data/web\_activity.csv`|2,812,118|10–21 Sep 2026, 248 endpoints|every host name or IP address each endpoint contacted|
|`data/endpoint\_security.csv`|23,540|1–26 Sep 2026|antivirus scans, quarantine records and web-filter blocks|
|`data/usb\_events.csv`|8|Sep 2026|USB devices plugged into endpoints|

`SHA256SUMS` lists checksums for every file. 

All three files share one layout:

|Column|Meaning|
|-|-|
|`endpoint\_id`|the desktop's ID, the same in all three files|
|`endpoint\_name`|its host name|
|`mac`|its network card address|
|`unit`|the organisational unit it belongs to|
|`log\_type`|which part of the agent wrote the row (see below)|
|`event\_time`|when it happened, by the endpoint's own clock, local time (UTC+05:30), `DD-MM-YYYY HH:MM:SS`|
|`received\_time`|when the log server received it. Endpoints upload late, sometimes by days, and an endpoint clock can be wrong.|
|`message`|the payload (see below)|

### What each `log\_type` says

**`web`** has one contacted destination per row: a host name or an IP address. Home and office routers often append
their own search domain, so you will also see names like `example.com.hgu\_lan`, `….bbrouter`, `….dlink` or `….local`.
Short names without a dot are local network names.

**`web\_block`** is a destination the web filter blocked.

**`av\_scan`** holds the nightly antivirus scan lines:

* `Infected file is ----- System Scan Completed ------`: the scan ran, so the machine was on.
* `Knownviruses:…,Engineversion:…,Scannedfiles:…,Infectedfiles:…`: the scan summary, including how current the signatures are.
* `Infected file is <path>: <Signature> FOUND`: a detection.
* `Processing: …`, `Attempting to handle: …`, `Quarantined and deleted: <from> to <to>`,
`File not found or no permissions: …`: what the scanner did about it.

**`quarantine`** comes from the quarantine service. `No Malicious files found.` / `No suspicious file found by type or extension.` mean a scan found nothing. A record reads
`File: <name> | Quarantined At: <local time> | FileType: <type> | SHA256: <hash>`. Keep two things in mind:

* The service re-lists the whole quarantine folder at every scan, so one file can appear many times.
* `FileType: Malicious` means a signature matched. Any other file type means the file was quarantined for its type or
extension, not because it was found to be malicious.

**`usb`** is one row per second while a device is plugged in: the device name, its class and its `vendor:product` ID.

