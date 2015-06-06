<pre>
  <b>Warning:</b>
  This tool is <s>dirty</s> under construction, at this moment it will only work for Windows 8.1 x86-64 build 9600 !!

  <b>Winbagility</b>
  At this time it is just another crappy POC.
  It gives the ability to open debugged and undebugged 8.1 x64 RAW  physical memory dump "directly" in WinDbg.
  It gives the ability to debugged undebugged Windows 8.1 running in patched Vbox.

  <b>How does it works ?</b>
  A Kd server is implemented wich simulate a debugged Windows station that received commands thought named pipe.
  
  <b>Why ?</b>
  Patchguard analysis,
  DRM analysis,
  Malicious malware analysis,
  Fun

  <b>How to use (PHYSICAL DUMP MODE)?</b>
  1. Create a raw memory dump of 8.1 x64 and place it at "C:\8_1_x64.dmp"
  2. Start Winbagility
  3. Start Windbg and connect it to named pipe "\\.\pipe\client

  <b>How to use (VBOX MODE)?</b>
  1. Patch Vbox, compile it
  2. Add in VM_NAME.vbox:
  &lt;ExtraData&gt;
  ...
  &lt;ExtraDataItem name="VBoxInternal/DBGC/Address" value="127.0.0.1"/&gt;
  &lt;ExtraDataItem name="VBoxInternal/DBGC/Enabled" value="1"/&gt;
  &lt;ExtraDataItem name="VBoxInternal/DBGC/Port" value="5000"/&gt;
  ...
  &lt;/ExtraData&gt;
  3. Start it
  4. Start Winbagility
  3. Start Windbg and connect it to named pipe "\\.\pipe\client

  <b>Why did I commit this s**t ?</b>
  I wanted to save my work in progress...

  <b>Why virtualbox ?</b>
  1. Open source
  2. Working on Windows !

  <b>Todo list:</b>
  <s>Open Debugged 8.1 x64 raw memory dump</s>
  <s>Open Undebugged/Stock 8.1 x64 raw memory dump</s>
  <s>Integrate it in virtualbox</s>
  <s>Support "Go" Command</s>
  Register read (some are missing ex: GDT...)
  Manage multiple CPU support
  Code cleaning, checks, tests, optimisations...
  Memory writes
  Hardware/Memory breakpoint with EPTViolation
  Other windows build support
  Code cleaning
  Register writes
  Code cleaning
  Arguments and all Bullshit
  Code cleaning
  FDP(Fast Debugging Protocol) with SHM
  Virtual_Physical in FDP
  Profits !

  <b>Bonus:</b>
  A Kd proxy is present in the code :)
</pre>
