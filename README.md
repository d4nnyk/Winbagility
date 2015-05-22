<pre>
<b>Winbagility</b>
At this time it is just another crappy POC. It gives the ability to open debugged and undebugged 8.1 x64 RAW  physical memory dump "directly" in WinDbg.
It is useless for the moment, Volatility is better than this !

<b>How does it works ?</b>
A Kd server is implemented wich simulate a debugged Windows station that received commands thought named pipe.

<b>How to use ?</b>
1. Create a raw memory dump of 8.1 x64 and place it at "C:\8_1_x64.dmp"
2. Start Winbagility
3. Start Windbg and connect it to named pipe "\\.\pipe\client"

<b>Why did I commit this s**t ?</b>
I wanted to save my work in progress...

<b>Todo list:</b>
  <s>1. Open Debugged 8.1 x64 raw memory dump</s>
  <s>2. Open Undebugged/Stock 8.1 x64 raw memory dump</s>
  3. Manage multiple CPU support
  4. Integrate it in virtualbox
  5. Code cleaning, checks, tests, optimisations...
  6. Profits !

<b>Bonus:</b>
A Kd proxy is present in the code :)
</pre>
