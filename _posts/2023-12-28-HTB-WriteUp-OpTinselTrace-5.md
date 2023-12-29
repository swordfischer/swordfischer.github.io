---
layout: post
title:  "Sherlocks - OpTinselTrace-5"
category: HTB
---
{% include htb_sherlock.html title="OpTinselTrace-5" difficulty="Hard" scenario="You'll notice a lot of our critical server infrastructure was recently transferred from the domain of our MSSP - Forela.local over to Northpole.local. We actually managed to purchase some second hand servers from the MSSP who have confirmed they are as secure as Christmas is! It seems not as we believe christmas is doomed and the attackers seemed to have the stealth of a clattering sleigh bell, or they didn’t want to hide at all!!!!!! We have found nasty notes from the Grinch on all of our TinkerTech workstations and servers! Christmas seems doomed. Please help us recover from whoever committed this naughty attack!" %}

{% include danger.html content="<p>THIS SHERLOCK CONTAINS MALWARE.</p><p>CONSIDER YOUR ACTIONS.</p>" %}

# Tasks

1. [Which CVE did the Threat Actor (TA) initially exploit to gain access to DC01?](#1-which-cve-did-the-threat-actor-ta-initially-exploit-to-gain-access-to-dc01)
2. [What time did the TA initially exploit the CVE? (UTC)](#2-what-time-did-the-ta-initially-exploit-the-cve-utc)
3. [What is the name of the executable related to the unusual service installed on the system around the time of the CVE exploitation?](#3-what-is-the-name-of-the-executable-related-to-the-unusual-service-installed-on-the-system-around-the-time-of-the-cve-exploitation)
4. [What date & time was the unusual service start?](#4-what-date--time-was-the-unusual-service-start)
5. [What was the TA's IP address within our internal network?](#5-what-was-the-tas-ip-address-within-our-internal-network)
6. [Please list all user accounts the TA utilised during their access. (Ascending order)](#6-please-list-all-user-accounts-the-ta-utilised-during-their-access-ascending-order)
7. [What was the name of the scheduled task created by the TA?](#7-what-was-the-name-of-the-scheduled-task-created-by-the-ta)
8. [Santa's memory is a little bad recently! He tends to write a lot of stuff down, but all our critical files have been encrypted! Which creature is Santa's new sleigh design planning to use?](#8-santas-memory-is-a-little-bad-recently-he-tends-to-write-a-lot-of-stuff-down-but-all-our-critical-files-have-been-encrypted-which-creature-is-santas-new-sleigh-design-planning-to-use)
9. [Please confirm the process ID of the process that encrypted our files.](#9-please-confirm-the-process-id-of-the-process-that-encrypted-our-files)

# Discussion
We have read the scenario, and the tasks we are looking to answer. There are some points of information that we can pull from this, that can assist us in our further analysis.
- A domain controller has been exploited
- Files have been encrypted

Some of the keywords here are "task", "encrypt", "exploit".

It may not be all the relevant information that we can deduce, but limiting the information that we look for is crucial when sifting through mountains of data.


# Answering the tasks
First, we need to grab the `optinseltrace5.zip` file, and unzip it, it contains two files `DC01.northpole.local-KAPE.zip` and `encrypted_files_suspicious_file.zip`. The first is a forensic collection of data, and the latter is some encrypted files with `.xmax` ending and a `splunk_svc.dll` file.

Let's start by analyzing the data in our KAPE directory. Most likely, the CVE will not be shown as a clear-text string but rather a series of actions.

I recently came to learn of [Hayabusa](https://github.com/Yamato-Security/hayabusa), so I'll be using that. We'll just pull all information and dump that into a CSV we can view with a tool like [TimelineExplorer](https://ericzimmerman.github.io/#!index.md).

{% highlight powershell %}
hayabusa-2.10.1-win-x64.exe csv-timeline -d DC01.northpole.local-KAPE\uploads\auto\C%3A\Windows\System32\winevt -o OpTinselTrace5.csv

╔╗ ╔╦═══╦╗  ╔╦═══╦══╗╔╗ ╔╦═══╦═══╗
║║ ║║╔═╗║╚╗╔╝║╔═╗║╔╗║║║ ║║╔═╗║╔═╗║
║╚═╝║║ ║╠╗╚╝╔╣║ ║║╚╝╚╣║ ║║╚══╣║ ║║
║╔═╗║╚═╝║╚╗╔╝║╚═╝║╔═╗║║ ║╠══╗║╚═╝║
║║ ║║╔═╗║ ║║ ║╔═╗║╚═╝║╚═╝║╚═╝║╔═╗║
╚╝ ╚╩╝ ╚╝ ╚╝ ╚╝ ╚╩═══╩═══╩═══╩╝ ╚╝
   by Yamato Security

Start time: 2023/12/28 21:59

Total event log files: 146
Total file size: 261.4 MB

Scan wizard:

? Which set of detection rules would you like to load? ›
  1. Core ( status: test, stable | level: high, critical )
  2. Core+ ( status: test, stable | level: medium, high, critical )
  3. Core++ ( status: experimental, test, stable | level: medium, high, critical )
  4. All alert rules ( status: * | level: low+ )
❯ 5. All event and alert rules ( status: * | level: informational+ )

✔ Which set of detection rules would you like to load? · 5. All event and alert rules ( status: * | level: informational+ )
✔ Include deprecated rules? · yes
✔ Include noisy rules? · yes
✔ Include unsupported rules? · yes
✔ Include sysmon rules? · yes

{% endhighlight %}

Once we're done scanning, Hayabusa will present us with some summaries.
![Hayabusa](/img/htb/sherlock/optinseltrace-5/hayabusa.png)

First thing to note here is that we have a lot of critical detections on the `2023-12-13`, then `Active Directory Replication from Non Machine Account` and `Mimikatz DC Sync`.

### 1. Which CVE did the Threat Actor (TA) initially exploit to gain access to DC01?

When we open up Timeline Explorer with our Hayabusa output, we can filter it a bit more based on the previous information - let's look at the `2023-12-13` events.

Something that caught my eye, is that there is a Logon event for the DC, but coming from somewhere else than localhost. 

![Timeline Explorer](/img/htb/sherlock/optinseltrace-5/timeline.png)

By now, I already have an inkling of what kind of attack we're seeing - but a few lines higher we get a confirmation as `Svc: vulnerable_to_zerologon` states the obvious. The attacker is using a privilege escalation vulnerability in Netlogon called Zerologon, which has the CVE we will use as our answer.

{% include htb_flag.html id="1" description="Which CVE did the Threat Actor (TA) initially exploit to gain access to DC01?" flag="CVE-2020-1472" %}

### 2. What time did the TA initially exploit the CVE? (UTC)

We're still looking at the same sequence of events, and it shows the timestamp for which the exploit occured.

![Timeline Explorer](/img/htb/sherlock/optinseltrace-5/timeline_zerologon.png)

{% include htb_flag.html id="2" description="What time did the TA initially exploit the CVE? (UTC)" flag="2023-12-13 09:24:23" %}

### 3. What is the name of the executable related to the unusual service installed on the system around the time of the CVE exploitation?

The installation of a service called `vulnerable_to_zerologon` shows the path to the executable, which is our answer.

{% include htb_flag.html id="3" description="What is the name of the executable related to the unusual service installed on the system around the time of the CVE exploitation?" flag="hAvbdksT.exe" %}

### 4. What date & time was the unusual service start?

Hayabusa did not collection this information, but luckily we can read the events with PowerShell (or the event viewer). I find PowerShell to be much easier to filter with, than the event viewer.

This information is usually stored in the `System.evtx`.

{% highlight powershell %}
Get-WinEvent -FilterHashtable @{ Path="DC01.northpole.local-KAPE\uploads\auto\C%3A\Windows\System32\winevt\Logs\System.evtx"; StartTime=(Get-Date "2023-12-13"); Id=7036 } -ea 0 | ? { $_.Message -match 'ZeroLogon'}


   ProviderName: Service Control Manager

TimeCreated                      Id LevelDisplayName Message
-----------                      -- ---------------- -------
12/13/2023 10:24:28 AM         7036 Information      The vulnerable_to_zerologon service entered the stopped state.
12/13/2023 10:24:24 AM         7036 Information      The vulnerable_to_zerologon service entered the running state.

{% endhighlight %}

So, the machine I'm reading from has local time of UTC+1, so we need to subtract one hour. We could also use the `.ToUniversalTime()` function on the `datetime` object.

{% highlight powershell %}
Get-WinEvent -FilterHashtable @{ Path="DC01.northpole.local-KAPE\uploads\auto\C%3A\Windows\System32\winevt\Logs\System.evtx"; StartTime=(Get-Date "2023-12-13"); Id=7036 } -ea 0 | ? { $_.Message -match 'ZeroLogon'} | Select @{N='UTC Time'; E={ $_.TimeCreated.ToUniversalTime() }}

UTC Time
--------
12/13/2023 9:24:28 AM
12/13/2023 9:24:24 AM
{% endhighlight %}

{% include htb_flag.html id="4" description="What date & time was the unusual service start?" flag="2023-12-13 09:24:24" %}

### 5. What was the TA's IP address within our internal network?

We previously established that a non-local IP address was used for attacking the Domain Controller. If we filter on that IP, we see more events showing a sucessful compromise. 

![Timeline Explorer](/img/htb/sherlock/optinseltrace-5/timeline_ip.png)

{% include htb_flag.html id="5" description="What was the TA's IP address within our internal network?" flag="192.168.68.200" %}

### 6. Please list all user accounts the TA utilised during their access. (Ascending order)

The previous screenshot also shows which accounts that was used to access the Domain Controller from that IP.

{% include htb_flag.html id="6" description="Please list all user accounts the TA utilised during their access. (Ascending order)" flag="Administrator, Bytesparkle" %}

### 7. What was the name of the scheduled task created by the TA?

There is a very suspicious task creation: 

![Timeline Explorer](/img/htb/sherlock/optinseltrace-5/svc_vnc.png)


The task name includes the path, but we're only looking for the task name. We can also find evidence of this task in the KAPE files `DC01.northpole.local-KAPE\uploads\auto\C%3A\Windows\System32\Tasks\Microsoft\svc_vnc`.

{% include htb_flag.html id="7" description="What was the name of the scheduled task created by the TA?" flag="svc_vnc" %}

### 8. Santa's memory is a little bad recently! He tends to write a lot of stuff down, but all our critical files have been encrypted! Which creature is Santa's new sleigh design planning to use?

Seems like we need to do some reversing on the `splunk_svc.dll` file that was collected for us.

Let's start out with `strings`
{% highlight bash %}
$ strings splunk_svc.dll                        
... TRUNCATED ...
Dear Santa Claus,
It's time for a holiday twist you didn't see coming. Yours truly, the Grinch, has taken over your Christmas operation. Not only have I got my hands on your list of gift recipients, but I also hold the infamous Naughty List. The world is on the edge of discovering who's been less than angelic this year!
To keep Christmas from turning into a scandal, I demand a ransom of 5,000,000 XMAS tokens. Deposit them into my crypto wallet: GR1NCH-5ANTA-2023XMAS. Delay or non-compliance will lead to the Naughty List becoming public knowledge, destroying the festive spirit across the globe.
Tick tock, Santa. The deadline is midnight on Christmas Eve. Make the right choice. Together, we can still save Christmas.
Sinister holiday wishes,
The Grinch
\README.TXT
EncryptingC4Fun!
.3ds
.jpg
.JPG
.png
.PNG
.asp
.bak
.cfg
.cpp
.ctl
.dbf
.doc
.dwg
.eml
.fdb
.hdd
.mdb
.msg
.nrg
.ora
.ost
.ova
.ovf
.pdf
.php
.pmf
.ppt
.pst
.pvi
.pyc
.rar
.rtf
.sln
.sql
.tar
.vbs
.vcb
.vdi
.vfd
.vmc
.vmx
.vsv
.xls
.xvd
.zip
.accdb
.aspx
.avhd
.back
.conf
.disk
.djvu
.docx
.kdbx
.mail
.pptx
.vbox
.vmdk
.vmsd
.vsdx
.work
.xlsx
.xmax
XOR operation failed!
C:\Users
... TRUNCATED ...
D:\Payloads\Not_Petya_XOR_Dll\x64\Release\Not_Petya_Dll.pdb
... TRUNCATED ...
Not_Petya_Dll.dll
... TRUNCATED ...

{% endhighlight %}

From this output, we can assume a few things:
- the binary is not packed
- it's likely based on NotPetya
- it has a hardcoded directory to encrypt
- it has hardcoded filetypes to encrypt
- it likely uses XOR for encryption
- it seems to write a README.TXT as a ransom note
- EncryptingC4Fun! may be the XOR value

The theory here is that it gets all the listed filetypes in the `C:\Users\` directory, and XORs them with `EncryptingC4Fun!`. We could load this up in Ghidra and do some reversing to understand the methodology that the dll applies.

We can fiddle around in Ghidra, and search for some of the strings - and end up in a function we're assuming is doing the encryption. It looks a lot like a simple XOR encryption.

![Ghidra](/img/htb/sherlock/optinseltrace-5/ghidra_xor.png)

If something has been XOR'ed with a string, and you XOR it again with the same string - it returns to its original state. The best option would be to use tools readily to your disposal, such as [CyberChef](https://gchq.github.io/CyberChef).

___
#### Proper Solution
With CyberChef we can also XOR our file.

`Open File As Input` and select your `.xmax` file, choose `XOR` in your recipe, input the `key` = `EncryptingC4Fun!` and change the type to `UTF8`
![CyberChef XOR](/img/htb/sherlock/optinseltrace-5/cyberxor.png)

___
#### Alternate Solution
The user `mark0smith` used the following script in his writeup for the same:

{% highlight python %}
XOR_KEY = b"EncryptingC4Fun!"

def decrypt(filename):
    print(filename)
    assert filename.endswith(".xmax")
    originalFilename = filename.split(".xmax")[0]

    with open(originalFilename,"wb") as f:
        with open(filename,"rb") as fe:
            data = fe.read()
        for i,v in enumerate(data):
            pv = v ^ XOR_KEY[i % len(XOR_KEY)]
            f.write(pv.to_bytes(1,"big"))

# decrypt("topsecret.png.xmax")
{% endhighlight %}
___
#### My Solution

But, I did not choose the best path. I simply executed the malware and had it re-XOR the original files, not the best way to do dynamic analysis.

{% include danger.html content="<p>A word of warning, and I cannot stress this enough - when executing malware you are doing so at your own risk. Malware can break out of the container. It can have unforseen consequences.<br />I'm doing these Sherlocks on a device solely for the purpose of accessing CTFs / HTB and so forth - on which I have VMs that I can restore to before I execute malware. The device is not connected to my internal network. I've done what I can to safeguard myself and limit the impact of a potential threat, and so should you.</p>" %}

Let's copy over the `splunk_svc.dll` file to our [FlareVM](https://github.com/mandiant/flare-vm), so we can use it to decrypt our files.

As this is a `.dll` we need to use `rundll32.exe` to initiate it, but first we'll setup ProcMon to monitor the actions of `rundll32.exe`

![ProcMon Filter](/img/htb/sherlock/optinseltrace-5/procmonfilter.png)

Now we are ready to execute to figure out where it starts the encryption.

{% highlight cmd %}
rundll32.exe splunk_svc.dll,#1
{% endhighlight %}

![rundll32](/img/htb/sherlock/optinseltrace-5/splunk_ransom.png)

Looks like it is hitting our user directory, so let us dump our files in the first directory. One thing that we saw with the `strings` output was that the `.xmax` extension was listed, so we don't even need to rename the files!

![XOR'ed](/img/htb/sherlock/optinseltrace-5/xxor.png)

We placed our files in the directory, ran the `.dll` and now we have files with a double `.xmax` file extension. Let's see if we can view the encrypted files.

![Top Secret](/img/htb/sherlock/optinseltrace-5/topsecret.png)

Seems like our method worked - there is a PDF that describes the usage of "Enchanted Unicorns", but the answer is looking for the animal in singular form.

{% include htb_flag.html id="8" description="Santa's memory is a little bad recently! He tends to write a lot of stuff down, but all our critical files have been encrypted! Which creature is Santa's new sleigh design planning to use?" flag="Unicorn" %}

### 9. Please confirm the process ID of the process that encrypted our files.

This is a bit more complicated, as we need to figure out *when* the files were encrypted and *how* they got encrypted. Our trusty `$MFT` file may contains some information. 

{% highlight powershell %}
MFTECmd.exe -f 'DC01.northpole.local-KAPE\uploads\ntfs\%5C%5C.%5CC%3A\$MFT' --csv .
MFTECmd version 1.2.2.1
... TRUNCATED ...
        CSV output will be saved to 20231228215514_MFTECmd_$MFT_Output.csv
{% endhighlight %}

Now let's investigate the content of the csv

{% highlight powershell %}
Import-Csv '20231228215514_MFTECmd_$MFT_Output.csv' | ? { $_.Extension -eq '.xmax' } | Select Created0x10

Created0x10
-----------
2023-12-13 11.03.20.9408130
2023-12-13 11.03.20.4505795
2023-12-13 11.03.22.1495771
2023-12-13 11.03.20.4565771
2023-12-13 11.03.22.1545771
... TRUNCATED ...

{% endhighlight %}

We have a lot of events around `2023-12-13 11:03:20` and a couple of seconds after that. There are multiple event log entries to store process creation events, but none of which shows the information that we need. Let's search all our event logs for events happening at these two seconds.

{% highlight powershell %}
Get-ChildItem -Path "DC01.northpole.local-KAPE\uploads\auto\C%3A\Windows" -Include '*.evtx' -Recurse | % { Get-WinEvent -FilterHashtable @{ Path=$_.FullName; StartTime=(Get-Date "2023-12-13 12:03:20"); EndTime=(Get-Date "2023-12-13 12:03:22") } -ea 0 }


   ProviderName: Microsoft-Windows-UAC-FileVirtualization

TimeCreated                      Id LevelDisplayName Message
-----------                      -- ---------------- -------
12/13/2023 12:03:20 PM         5004 Verbose          Access was denied to delete file "\Device\HarddiskVolume4\ProgramData\VMware\VMware VGAuth\vgau...
12/13/2023 12:03:20 PM         5004 Verbose          Access was denied to delete file "\Device\HarddiskVolume4\ProgramData\VMware\VMware VGAuth\vgau...
12/13/2023 12:03:20 PM         5004 Verbose          Access was denied to delete file "\Device\HarddiskVolume4\ProgramData\VMware\VMware VGAuth\vgau...
12/13/2023 12:03:20 PM         5004 Verbose          Access was denied to delete file "\Device\HarddiskVolume4\ProgramData\VMware\VMware VGAuth\vgau...
12/13/2023 12:03:20 PM         4000 Information      Virtual file "\Device\HarddiskVolume4\ProgramData\VMware\VMware VGAuth\vgauth.conf.xmax" created.
... TRUNCATED ...
{% endhighlight %}

The good thing is that we don't have an awful amount of events occuring here, and there are only events occuring in the `Microsoft-Windows-UAC-FileVirtualization` event log. The `4000` event seems to be something we'd like to look at bit more into.

{% highlight powershell %}
Get-WinEvent -FilterHashtable @{ Path="DC01.northpole.local-KAPE\uploads\auto\C%3A\Windows\System32\winevt\Logs\Microsoft-Windows-UAC-FileVirtualization%254Operational.evtx"; StartTime=(Get-Date "2023-12-13 12:03:20"); EndTime=(Get-Date "2023-12-13 12:03:22"); Id=4000 } -ea 0  | Select -First 1 *


Message              : Virtual file "\Device\HarddiskVolume4\ProgramData\VMware\VMware VGAuth\vgauth.conf.xmax" created.
Id                   : 4000
Version              : 0
Qualifiers           :
Level                : 4
Task                 : 0
Opcode               : 0
Keywords             : -9223372036854775808
RecordId             : 42
ProviderName         : Microsoft-Windows-UAC-FileVirtualization
ProviderId           : c02afc2b-e24e-4449-ad76-bcc2c2575ead
LogName              : Microsoft-Windows-UAC-FileVirtualization/Operational
ProcessId            : 5828
ThreadId             : 6480
MachineName          : DC01.northpole.local
UserId               : S-1-5-21-555278382-3747106525-1010465941-1110
TimeCreated          : 12/13/2023 12:03:20 PM
ActivityId           :
RelatedActivityId    :
ContainerLog         : dc01.northpole.local-kape\uploads\auto\c%3a\windows\system32\winevt\logs\microsoft-windows-uac-filevirtu
                       alization%254operational.evtx
MatchedQueryIds      : {}
Bookmark             : System.Diagnostics.Eventing.Reader.EventBookmark
LevelDisplayName     : Information
OpcodeDisplayName    : Info
TaskDisplayName      :
KeywordsDisplayNames : {}
Properties           : {System.Diagnostics.Eventing.Reader.EventProperty, System.Diagnostics.Eventing.Reader.EventProperty,
                       System.Diagnostics.Eventing.Reader.EventProperty, System.Diagnostics.Eventing.Reader.EventProperty...}
{% endhighlight %}

This shows us a `ProcessId` which is exactly what we are looking for.

{% include htb_flag.html id="9" description="Please confirm the process ID of the process that encrypted our files." flag="5828" %}

## Congratulations

You've have pwned OpTinselTrace-5