<pre>
<b>Winbagility</b>
At this time it is just another crappy POC. It gives the ability to open debugged 8.1 x64 RAW memory dump "directly" in WinDbg.
It is useless for the moment, Volatility is better than this !

<b>How does it works ?</b>
A Kd server is implemented wich simulate a debugged VM that received commands thought named pipe.

<b>How to use ?</b>
1. Create a raw memory dump of 8.1 x64 and place it at "C:\8_1_x64.dmp"
2. Start the winbagility
3. Start Windbg and connect it to named pipe "\\.\pipe\client"

<b>Why did I commit this s**t ?</b>
I wanted to save my work in progress...

<b>TODO:</b>
1. Open undebugged 8.1 x64 raw memory dump
2. Manage multiple CPU support
3. Integrate it in virtualbox
4. Checks, tests, optimisations...

<b>Bonus</b>
A Kd proxy is present in the code :)
</pre>