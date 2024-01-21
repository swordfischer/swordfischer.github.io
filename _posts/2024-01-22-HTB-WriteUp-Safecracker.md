---
layout: post
title:  "Sherlocks - Safecracker"
category: HTB
---
{% include htb_sherlock.html title="Safecracker" difficulty="Insane" scenario="We recently hired some contractors to continue the development of our Backup services hosted on a Windows server. We have provided the contractors with accounts for our domain. When our system administrator recently logged on, we found some pretty critical files encrypted and a note left by the attackers. We suspect we have been ransomwared. We want to understand how this attack happened via a full in-depth analysis of any malicious files out of our standard triage. A word of warning, our tooling didn't pick up any of the actions carried out - this could be advanced. Warning This is a warning that this Sherlock includes software that is going to interact with your computer and files. This software has been intentionally included for educational purposes and is NOT intended to be executed or used otherwise. Always handle such files in isolated, controlled, and secure environments. One the Sherlock zip has been unzipped, you will find a DANGER.txt file. Please read this to proceed." %}

# Tasks

1. [Which user account was utilised for initial access to our company server?](#1-which-user-account-was-utilised-for-initial-access-to-our-company-server)

2. [Which command did the TA utilise to escalate to SYSTEM after the initial compromise?](#2-which-command-did-the-ta-utilise-to-escalate-to-system-after-the-initial-compromise)

3. [How many files have been encrypted by the the ransomware deployment?](#3-how-many-files-have-been-encrypted-by-the-the-ransomware-deployment)

4. [What is the name of the process that the unpacked executable runs as?](#4-what-is-the-name-of-the-process-that-the-unpacked-executable-runs-as)

5. [What is the XOR key used for the encrypted strings?](#5-what-is-the-xor-key-used-for-the-encrypted-strings)

6. [What encryption was the packer using?](#6-what-encryption-was-the-packer-using)

7. [What was the encryption key and IV for the packer?](#7-what-was-the-encryption-key-and-iv-for-the-packer)

8. [What was the name of the memoryfd the packer used?](#8-what-was-the-name-of-the-memoryfd-the-packer-used)

9. [What was the target directory for the ransomware?](#9-what-was-the-target-directory-for-the-ransomware)

10. [What compression library was used to compress the packed binary?](#10-what-compression-library-was-used-to-compress-the-packed-binary)

11. [The binary appears to check for a debugger, what file does it check to achieve this?](#11-the-binary-appears-to-check-for-a-debugger-what-file-does-it-check-to-achieve-this)

12. [What exception does the binary raise?](#12-what-exception-does-the-binary-raise)

13. [Out of this list, what extension is not targeted by the malware? `.pptx,.pdf,.tar.gz,.tar,.zip,.exe,.mp4,.mp3`](#13-out-of-this-list-what-extension-is-not-targeted-by-the-malware-pptxpdftargztarzipexemp4mp3)

14. [What compiler was used to create the malware?](#14-what-compiler-was-used-to-create-the-malware)

15. [If the malware detects a debugger, what string is printed to the screen?](#15-if-the-malware-detects-a-debugger-what-string-is-printed-to-the-screen)

16. [What is the contents of the `.comment` section?](#16-what-is-the-contents-of-the-comment-section)

17. [What file extension does the ransomware rename files to?](#17-what-file-extension-does-the-ransomware-rename-files-to)

18. [What is the bitcoin address in the ransomware note?](#18-what-is-the-bitcoin-address-in-the-ransomware-note)

19. [What string does the binary look for when looking for a debugger?](#19-what-string-does-the-binary-look-for-when-looking-for-a-debugger)

20. [It appears that the attacker has bought the malware strain from another hacker, what is their handle?](#20-it-appears-that-the-attacker-has-bought-the-malware-strain-from-another-hacker-what-is-their-handle)

21. [What system call is utilised by the binary to list the files within the targeted directories?](#21-what-system-call-is-utilised-by-the-binary-to-list-the-files-within-the-targeted-directories)

22. [Which system call is used to delete the original files?](#22-which-system-call-is-used-to-delete-the-original-files)

# Discussion
We have read the scenario, and the tasks we are looking to answer. There are some points of information that we can pull from this, that can assist us in our further analysis.
- This lab includes sophisticated malware
- We need to investigate both on Linux and Windows
- Seems reversing heavy *sigh*

Some of the keywords here are "packer", "debug", "xor" and "memoryfd".

It may not be all the relevant information that we can deduce, but limiting the information that we look for is crucial when sifting through mountains of data.


# Answering the tasks
First, we need to grab the `safecracker.zip` file, and unzip it, it contains another zip file named `WinServer-Collection.zip` and a `DANGER.txt`, which contains the KAPE files and a a warning about malware.

Keep in mind that Sherlocks are not forcing you to solve the tasks in a specific order. But for the purpose of the write-up I'll try to explain it in the order of which they appear.
Oftentimes you will get clues that assists you answering previous tasks.

I'll also switch between Windows and Linux frequently during Sherlocks - *most* Windows forensics is easier in Windows (to me), and sometimes I'm more comfortable doing a specific task with Linux - you choose your own battles, and pick the toolset which works for you.

Another important thing to note, is that I don't add **all** the steps I did before figuring out the solution. Sometimes a lot of time is spent on goosechases or rabbitholes - I learn from it, but there is not much value for you as a reader to go through that process (or perhaps there is). Nobody wants to see me run `strings` and `grep` a thousand times!

### 1. Which user account was utilised for initial access to our company server?

Let's first check what we have.

{% highlight shel %}
ls uploads
auto  ntfs  PhysicalMemory.raw
{% endhighlight %}

There is a memory dump, we'll save that for later, doesn't seem like we're going to use it, unless we need to recover some malware from memory - So let's check the two other folders, namely check the `C:\Users` directory, we can see which profiles has been created on the target:

{% highlight shell %}
ls auto/C%3A/Users  
'%2ENET v4.5'  '%2ENET v4.5 Classic'   Administrator   contractor01   Default   Public
{% endhighlight %}

There are 2 account names here that are interesting: `Administrator` and `contractor01`. We'll need to check some logs as well - but now we can scope our search.

{% highlight powershell %}
 hayabusa-2.10.1-win-x64.exe csv-timeline -d "uploads\auto\C%3A\Windows\System32\winevt\Logs" -o Safecracker.csv

╔╗ ╔╦═══╦╗  ╔╦═══╦══╗╔╗ ╔╦═══╦═══╗
║║ ║║╔═╗║╚╗╔╝║╔═╗║╔╗║║║ ║║╔═╗║╔═╗║
║╚═╝║║ ║╠╗╚╝╔╣║ ║║╚╝╚╣║ ║║╚══╣║ ║║
║╔═╗║╚═╝║╚╗╔╝║╚═╝║╔═╗║║ ║╠══╗║╚═╝║
║║ ║║╔═╗║ ║║ ║╔═╗║╚═╝║╚═╝║╚═╝║╔═╗║
╚╝ ╚╩╝ ╚╝ ╚╝ ╚╝ ╚╩═══╩═══╩═══╩╝ ╚╝
   by Yamato Security

Start time: 2024/01/17 21:18

Total event log files: 177
Total file size: 388.0 MB

Scan wizard:

✔ Which set of detection rules would you like to load? · 5. All event and alert rules ( status: * | level: informational+ )
✔ Include deprecated rules? · yes
✔ Include noisy rules? · yes
✔ Include unsupported rules? · yes
✔ Include sysmon rules? · yes

{% endhighlight %}

Once the scans are done, we can open up `Safecracker.csv` in `Timeline Explorer` and search for logons with event ID `4624`, and search for valid IP addresses.
Most of the events have an `SrcIP` which is `-` or `127.0.0.1`, the rest is from `192.168.0.0/16`
![Timeline Explorer 1](/img/htb/sherlock/safecracker/timeline_explorer_1.png)

We can see from the screenshot, that we have a few old events which we'll assume are not malicious - the newest come from another device, and after some time with `Contractor01` then `Administrator` logs on. 

Seems obvious that if we read the introduction that it's the contractor was using the aptly named account.

{% include htb_flag.html id="1" description="Which user account was utilised for initial access to our company server?" flag="contractor01" %}

### 2. Which command did the TA utilise to escalate to SYSTEM after the initial compromise?

A great place to look for executed commands (if run in PowerShell) is the posh equivalent of `.bash_history`: `ConsoleHost_history.txt`
{% highlight powershell %}
type uploads\auto\C%3A\Users\contractor01\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
ubuntu
whoami
net user
net group
net groups
cd ../../
cd .\Users\contractor01\Contacts\
ls
cd .\PSTools\
ls
.\PsExec64.exe -s -i cmd.exe
{% endhighlight %}

So, we can make a note here already - it seems like the command `Ubuntu` was run, which indicates the usage of Windows Subsystem for Linux.
Following that, there are some enumeration going on and a `PSTools` folder located in `Contacts` (that's not normal).

Then the TA executes psexec to run in SYSTEM context.

{% include htb_flag.html id="2" description="Which command did the TA utilise to escalate to SYSTEM after the initial compromise?" flag=".\PsExec64.exe -s -i cmd.exe" %}

### 3. How many files have been encrypted by the the ransomware deployment?

First we need to figure out which files are encrypted - usually they are renamed with a different extension or is accompanied with a ransom note.

{% highlight powershell %}
gci uploads\auto\C%3A -Recurse | group Extension | sort count

Count Name                      Group
----- ----                      -----
... TRUNCATED ...
    3 .31337                    {sales-pitch.mp4.31337, updates.zip.31337, Sysmon.zip.31337}
... TRUNCATED ...
    3 .note                     {sales-pitch.mp4.note, updates.zip.note, Sysmon.zip.note}
... TRUNCATED ...
{% endhighlight %}

`.31337` is not an ordinary file extension, and certainly having two extensions is not normal. As well as a corresponding `.note`

It could be that we have had files deleted, so let's check the `$MFT` for more files, and count the files with `.31337`

{% highlight powershell %}
MFTECmd.exe -f '.\$MFT' --csv "Safecracker\"

Import-Csv 'Safecracker\20240117210208_MFTECmd_$MFT_Output.csv' | ? { $_.Extension -eq '.31337' } | Measure
Count    : 33
{% endhighlight %}

{% include htb_flag.html id="3" description="How many files have been encrypted by the the ransomware deployment?" flag="33" %}

### 4. What is the name of the process that the unpacked executable runs as?

Unpacked executable? Now we need to find a *suspicious* binary. Let's check some home directories, perhaps `Downloads`

{% highlight powershell %}
gci .\auto\C%3A\Users\*\Downloads\*


    Directory: auto\C%3A\Users\Administrator\Downloads


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------         6/21/2023   3:19 PM             84 desktop.ini
------         6/12/2023  12:43 PM        4301472 MsMpEng.exe
------         6/21/2023   3:06 PM        5097152 Sysmon.zip.31337
------         6/21/2023   3:06 PM            336 Sysmon.zip.note


    Directory: auto\C%3A\Users\contractor01\Downloads


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------         6/21/2023   3:19 PM             84 desktop.ini
{% endhighlight %}

You can't tell me that `MsMpEng.exe` is a normal file to find in your administrators downloads folder. So let's look a bit more at that file.

{% highlight shell %}
file MsMpEng.exe
MsMpEng.exe: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e2097187e976e108f5b233c0a288cc35ae5886b8, for GNU/Linux 3.2.0, stripped
{% endhighlight %}

ELF binaries are for Linux, and not Windows. The file extension is a Windows one. Think we've hit our jackpot.

But let's use Detect it Easy to pull some more information about the file
![DIE Entropy](/img/htb/sherlock/safecracker/die_packer.png)

I'm not a super qualified reverse engineer - my goto tool is `strings`. Regardless, the information from DIE tells us that the file is likely packed (the tasks tells us it is as well). Packed binaries are not really `strings` compatible, which is the intention of it being packed.

Normally, I'd turn to `Ghidra` to reverse the binary, but we're being asking what the unpacked executable runs as. We can load the binary up in `gdb` and check the running processes.

{% highlight shell %}
ps aux     

USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
... TRUNCATED ...
kali       121148  0.1  0.9 673584 75988 pts/1    Sl+  22:24   0:00 gdb MsMpEng.exe
kali       121158  0.0  0.0   6024  3720 pts/1    t    22:24   0:00 PROGRAM
... TRUNCATED ...
kali       121187  0.0  0.0  10828  4260 pts/2    R+   22:31   0:00 ps aux

{% endhighlight %}

Now we have a name of an application, and if we search Ghidra for the same, we can see a call for that.
![Ghidra PROGRAM](/img/htb/sherlock/safecracker/ghidra_program.png)

{% include htb_flag.html id="4" description="What is the name of the process that the unpacked executable runs as?" flag="PROGRAM" %}

### 5. What is the XOR key used for the encrypted strings?
While the application is still running in `gdb`, we can grab some more information from it. As it's being packed it somehow needs to unpacked, which the application takes care of by itself.

We can grab the unpacked binary from `/proc` (the binary uses MemProcFS, so if you run it outside gdb it will get removed once the process is shut down)

{% highlight shell %}
cp /proc/121158/exe .
file exe                                                   
exe: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=02dbb3e4159827041282eeb0b88b6cfe5e2821a5, for GNU/Linux 3.2.0, stripped

strings WinServer-Collection/uploads/auto/C%3A/Users/Administrator/Downloads/MsMpEng.exe | grep 31337
                                                                                                                                                                            
strings exe | grep 31337                                                                              
%s.31337
{% endhighlight %}
Seems like we have gotten hold of the correct file - at least `strings` output is more promising, and shows the file extension we saw in [#4](#4-what-is-the-name-of-the-process-that-the-unpacked-executable-runs-as).

Let's open up that file in Ghidra instead, so we can find our XOR key.
I'll start by searching for the `31337`, and work my way backwards.

![Ghidra 31337](/img/htb/sherlock/safecracker/ghidra_encryption.png)

Then we'll find the references to the function `FUN_0014a5c1`, to see where it was called from.

![Ghidra Call](/img/htb/sherlock/safecracker/ghidra_function.png)

`local_28` is interesting in the context, so let's check if it's being referenced somewhere else

![Ghidra XOR](/img/htb/sherlock/safecracker/ghidra_xor.png)

Without fully understanding what is going on here, my assumption is that the file is read into memory and &DAT is a representation of that - that information is XOR'ed with the key before and written back. (denoted by the caret `^`)

If information is XOR'ed, we can XOR it again to "decrypt" the information.

{% include htb_flag.html id="5" description="What is the XOR key used for the encrypted strings?" flag="daV324982S3bh2" %}

### 6. What encryption was the packer using?

We'll know the length of they key in [#7](#7-what-was-the-encryption-key-and-iv-for-the-packer), which is 64 characters long, or 32 bytes. When we have 32 bytes keys for encryption with that function, it'll be AES-256.

My answer here was a qualified guess, more than a solid answer.

{% include htb_flag.html id="6" description="What encryption was the packer using?" flag="AES-256-CBC" %}

### 7. What was the encryption key and IV for the packer?
Fiddling about in `Ghidra`, we run into this:

{% highlight c %}


int FUN_0013a29b(undefined8 param_1,long param_2,undefined4 param_3)

{
  int iVar1;
  undefined8 uVar2;
  int local_28;
  int local_24;
  long local_20;
  void *local_18;
  void *local_10;
  
  local_10 = malloc(0x20);
  local_18 = malloc(0x10);
  FUN_0013a95d(PTR_s_a5f41376d435dc6c61ef9ddf2c4a9543_00518ee8,local_10);
  FUN_0013a95d(PTR_s_95e61ead02c32dab646478048203fd0b_00518ef0,local_18);
  local_20 = FUN_0013e9a0();
  if (local_20 == 0) {
    FUN_0013a285();
    local_24 = 0;
  }
  else {
    uVar2 = FUN_0013e2e0();
    iVar1 = FUN_0013fc70(local_20,uVar2,0,local_10,local_18);
    if (iVar1 == 1) {
      iVar1 = FUN_001402d0(local_20,param_2,&local_28,param_1,param_3);
      if (iVar1 == 1) {
        local_24 = local_28;
        iVar1 = FUN_00140aa0(local_20,local_28 + param_2,&local_28);
        if (iVar1 == 1) {
          local_24 = local_24 + local_28;
          FUN_0013e9c0(local_20);
        }
        else {
          FUN_0013a285();
          local_24 = 0;
        }
      }
      else {
        FUN_0013a285();
        local_24 = 0;
      }
    }
    else {
      FUN_0013a285();
      local_24 = 0;
    }
  }
  return local_24;
}
{% endhighlight %}

The functions that sets `local_10` and `local_18` from a pointer, is what we are looking for. That information is used in `FUN_0013fc70` which looks an awful lot of a call to decrypt [according to openssl](https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Decrypting_the_Message). So we'll read the `PTR` records, `local_10` is Key and `local_18` is IV.

{% include htb_flag.html id="7" description="What was the encryption key and IV for the packer?" flag="a5f41376d435dc6c61ef9ddf2c4a9543c7d68ec746e690fe391bf1604362742f:95e61ead02c32dab646478048203fd0b" %}

### 8. What was the name of the memoryfd the packer used?
When we grabbed the binary in [#4](#4-what-is-the-name-of-the-process-that-the-unpacked-executable-runs-as), we could've shown a bit more information - specifically the name of memoryfd. 
{% highlight shell %}
ls /proc/121158/exe -la
lrwxrwxrwx 1 kali kali 0 Jan 18 22:24 /proc/121158/exe -> '/memfd:test (deleted)'
{% endhighlight %}

Another way to find the systems memfd if we do not know the process id:  `ls -alR /proc/*/exe 2> /dev/null | grep memfd`

{% include htb_flag.html id="8" description="What was the name of the memoryfd the packer used?" flag="test" %}

### 9. What was the target directory for the ransomware?

During [#5](#5-what-is-the-xor-key-used-for-the-encrypted-strings) we already saw a very fitting directory if our hypothesis of this malware being run inside WSL is true.

{% highlight c %}

undefined8 FUN_0014a1be(void)

{
  int iVar1;
  undefined *local_38;
  undefined8 local_30;
  char *local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;
  
  local_38 = &DAT_0046dfc0;
  local_28 = "daV324982S3bh2";
  local_30 = 0;
  local_20 = 0xe;
  local_18 = 0;
  local_10 = 0;
  iVar1 = FUN_0014add8();
  if (iVar1 == 0) goto LAB_0014a210;
  do {
    do {
      do {
        do {
          do {
            do {
              FUN_0038164a();
LAB_0014a210:
              iVar1 = FUN_0014aa3d();
            } while (iVar1 != 0);
            raise(0xb);
            iVar1 = FUN_0014a3b5();
          } while (iVar1 != 0);
          iVar1 = FUN_0014a3f6(&local_38);
        } while (iVar1 != 0);
        raise(0xb);
        puts("Running update, testing update endpoints");
        iVar1 = FUN_0014ab00(&local_38);
      } while (iVar1 != 0);
      iVar1 = FUN_0014ac39("/mnt/c/Users",&local_38);
    } while (iVar1 != 0);
    raise(0xb);
    FUN_0014a8f6(&local_38);
    iVar1 = FUN_0014a5c1(&local_38);
  } while (iVar1 != 0);
  raise(0xb);
  puts("-----------------------------------------");
  puts("Configuration Successful\nYou can now connect to the Corporate VPN");
  return 0;
}
{% endhighlight %}

The directory `/mnt/c/Users` in WSL is the `C:\Users` directory on the host, coincidentally the location where we found the encrypted files.
It would seem logical if the `FUN_0014ac39` function would be a `process_directory` type function. 

{% highlight c %}

undefined8 FUN_0014ac39(char *param_1,undefined8 param_2)

{
  int iVar1;
  DIR *__dirp;
  dirent *pdVar2;
  undefined8 uVar3;
  char acStack_1038 [4104];
  
  __dirp = opendir(param_1);
  if (__dirp == (DIR *)0x0) {
    uVar3 = 1;
  }
  else {
    while( true ) {
      pdVar2 = readdir(__dirp);
      if (pdVar2 == (dirent *)0x0) break;
      raise(0xb);
      snprintf(acStack_1038,0x1000,"%s/%s",param_1,pdVar2->d_name);
      if (pdVar2->d_type == '\x04') {
        iVar1 = FUN_0014abf9(pdVar2->d_name);
        if (iVar1 == 0) {
          FUN_0014ac39(acStack_1038,param_2);
        }
      }
      else if (pdVar2->d_type == '\b') {
        iVar1 = FUN_0014ab61(acStack_1038);
        if (iVar1 != 0) {
          FUN_0014a955(param_2,acStack_1038);
        }
      }
    }
    closedir(__dirp);
    uVar3 = 0;
  }
  return uVar3;
}

{% endhighlight %}

At least, it calls a `opendir` on the parameter, then gets a list of files - and seems to do so recursively.

{% include htb_flag.html id="9" description="What was the target directory for the ransomware?" flag="/mnt/c/Users" %}

### 10. What compression library was used to compress the packed binary?

Once again, I'm basing this on pure speculation, there is a some `Z<something>` references and a `1.2.13` reference as well, which returns [this](https://github.com/madler/zlib/releases/tag/v1.2.13) result.

{% include htb_flag.html id="10" description="What compression library was used to compress the packed binary?" flag="zlib" %}

### 11. The binary appears to check for a debugger, what file does it check to achieve this?

If we follow the function calls in the unpacked binary, we at some point end up in `FUN_0014ad2c` which seems to be the debugger check:
{% highlight c %}

int FUN_0014ad2c(void)

{
  int iVar1;
  FILE *__stream;
  char *pcVar2;
  char *local_408;
  char local_400 [1008];
  
  local_408 = (char *)0x0;
  __stream = fopen("/proc/self/status","r");
  if (__stream == (FILE *)0x0) {
    fclose((FILE *)0x0);
  }
  else {
    do {
      pcVar2 = fgets(local_400,0x3de,__stream);
      if (pcVar2 == (char *)0x0) {
        return -1;
      }
      pcVar2 = strstr(local_400,"TracerPid");
    } while (pcVar2 == (char *)0x0);
    pcVar2 = strtok_r(pcVar2,":",&local_408);
    if ((pcVar2 != (char *)0x0) &&
       (pcVar2 = strtok_r((char *)0x0,":",&local_408), pcVar2 != (char *)0x0)) {
      iVar1 = atoi(pcVar2);
      return iVar1;
    }
  }
  return -1;
}
{% endhighlight %}

According to multiple [sources](https://linuxsecurity.com/features/anti-debugging-for-noobs-part-1) online, it's common to check for debuggers by checking `/proc/self/status` and looking for `TracerPid`

{% include htb_flag.html id="11" description="The binary appears to check for a debugger, what file does it check to achieve this?" flag="/proc/self/status" %}

### 12. What exception does the binary raise?
Just run the binary with a piece of software that sets the TracerPid - it's also visible within Ghidra.

{% highlight shell %}
ltrace ./exe
... TRUNCATED ...
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
{% endhighlight %}

{% include htb_flag.html id="12" description="What exception does the binary raise?" flag="SIGSEGV" %}

### 13. Out of this list, what extension is not targeted by the malware  `.pptx,.pdf,.tar.gz,.tar,.zip,.exe,.mp4,.mp3`?
I'm sure this is readable in the binary if you have some more reversing experience - I don't. However, I'll never shy away from bombing a VM!

{% highlight shell %}
touch /mnt/c/Users/Test/test{.pptx,.pdf,.tar.gz,.tar,.zip,.exe,.mp4,.mp3}

ls /mnt/c/Users/Test/
test.exe  test.mp3  test.mp4  test.pdf  test.pptx  test.tar  test.tar.gz  test.zip

./exe

Running update, testing update endpoints
Checking uri: http://google.com .......... [SUCCESS]
Checking uri: http://icanhazip.com .......... [SUCCESS]
Checking uri: http://something.com .......... [SUCCESS]
Checking uri: http://ifconfig.me .......... [SUCCESS]
Checking uri: https://reddit.com .......... [SUCCESS]
Checking uri: https://wikipedia.org .......... [SUCCESS]
Files found:
    - /mnt/c/Users/Test/test.tar
    - /mnt/c/Users/Test/test.pdf
    - /mnt/c/Users/Test/test.tar.gz
    - /mnt/c/Users/Test/test.mp4
    - /mnt/c/Users/Test/test.pptx
    - /mnt/c/Users/Test/test.mp3
    - /mnt/c/Users/Test/test.zip
-----------------------------------------
Configuration Successful
You can now connect to the Corporate VPN

{% endhighlight %}

Easy to see that one file type was not mentioned here!


{% include htb_flag.html id="13" description="Out of this list, what extension is not targeted by the malware? `.pptx,.pdf,.tar.gz,.tar,.zip,.exe,.mp4,.mp3`" flag=".exe" %}

### 14. What compiler was used to create the malware? 
For this we can use Detect it Easy, or `strings` and a bit of qualified guesses.
{% highlight shell %}
diec MsMpEng.exe 
ELF64
    Compiler: gcc((Debian 10.2.1-6) 10.2.1 20210110)[DYN AMD64-64]
    Library: GLIBC(2.7)[DYN AMD64-64]

{% endhighlight %}

{% include htb_flag.html id="14" description="What compiler was used to create the malware?" flag="gcc" %}

### 15. If the malware detects a debugger, what string is printed to the screen?
We can `strings` again, or we can debug it:
{% highlight shell %}
gdb-peda$ run
Starting program: MsMpEng.exe
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
process 2175516 is executing new program: /memfd:test (deleted)
warning: Could not load symbols for executable /memfd:test (deleted).
Do you need "set sysroot"?
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
*******DEBUGGED********

Program received signal SIGSEGV, Segmentation fault.
{% endhighlight %}

{% include htb_flag.html id="15" description="If the malware detects a debugger, what string is printed to the screen?" flag="*******DEBUGGED********" %}

### 16. What is the contents of the `.comment` section?
Let's read the binary with `readelf`

{% highlight shell %}
readelf -p .comment MsMpEng.exe

String dump of section '.comment':
  [     0]  GCC: (Debian 10.2.1-6) 10.2.1 20210110
{% endhighlight %}

{% include htb_flag.html id="16" description="What is the contents of the `.comment` section?" flag="GCC: (Debian 10.2.1-6) 10.2.1 20210110" %}

### 17. What file extension does the ransomware rename files to?
During [#3](#3-how-many-files-have-been-encrypted-by-the-the-ransomware-deployment) we found some `.31337` files which is what the task is refering to.

{% include htb_flag.html id="17" description="What file extension does the ransomware rename files to?" flag=".31337" %}

### 18. What is the bitcoin address in the ransomware note?

Again, during [#3](#3-how-many-files-have-been-encrypted-by-the-the-ransomware-deployment) we found some `.note` files which is what the task is refering to.

![ransom note](/img/htb/sherlock/safecracker/ransomnote.png)


{% include htb_flag.html id="18" description="What is the bitcoin address in the ransomware note?" flag="16ftSEQ4ctQFDtVZiUBusQUjRrGhM3JYwe" %}

### 19. What string does the binary look for when looking for a debugger?

We somewhat answered this during [#11](#11-the-binary-appears-to-check-for-a-debugger-what-file-does-it-check-to-achieve-this), the application looks at `/proc/self/status` and for a specific string.

{% include htb_flag.html id="19" description="What string does the binary look for when looking for a debugger?" flag="TracerPid" %}

### 20. It appears that the attacker has bought the malware strain from another hacker, what is their handle?
If we `binwalk` the file, we get a few references to a users home directory (`strings | grep home` is also sufficient)
{% highlight shell %}
binwalk -B exe

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             ELF, 64-bit LSB shared object, AMD x86-64, version 1 (SYSV)
760627        0xB9B33         PGP RSA encrypted session key - keyid: 4889 EFE87029 RSA (Encrypt or Sign) 1024b
1283710       0x13967E        bix header, header size: 64 bytes, header CRC: 0xF30F6F, created: 2045-04-05 17:04:00, image size: 987531 bytes, Data Address: 0x90000000, Entry Point: 0x488B85A0, data CRC: 0x48, compression type: none, image name: ""
1335247       0x145FCF        bix header, header size: 64 bytes, header CRC: 0x14883, created: 2093-05-05 21:43:37, image size: 1127777273 bytes, Data Address: 0x10761148, Entry Point: 0xC1E00889, data CRC: 0xCE31D248, image name: "C0s"
1636640       0x18F920        SHA256 hash constants, little endian
1641600       0x190C80        SHA256 hash constants, little endian
1641616       0x190C90        SHA256 hash constants, little endian
1899840       0x1CFD40        SHA256 hash constants, little endian
1899856       0x1CFD50        SHA256 hash constants, little endian
2631744       0x282840        Base64 standard index table
2640320       0x2849C0        Base64 standard index table
2703264       0x293FA0        Unix path: /home/blitztide/Projects/Payloads/LockPick3.0/lib/ssl/ct_log_list.cnf
2726216       0x299948        Unix path: /home/blitztide/Projects/Payloads/LockPick3.0/lib/ssl/lib/engines-1.1
2792296       0x2A9B68        Unix path: /home/blitztide/Projects/Payloads/LockPick3.0/lib/ssl/private
2801888       0x2AC0E0        AES Inverse S-Box
2889280       0x2C1640        Base64 standard index table
2956912       0x2D1E70        Copyright string: "Copyright 1995-2017 Mark Adler "
2957088       0x2D1F20        CRC32 polynomial table, little endian
2961184       0x2D2F20        CRC32 polynomial table, big endian
{% endhighlight %}

{% include htb_flag.html id="20" description="It appears that the attacker has bought the malware strain from another hacker, what is their handle?" flag="blitztide" %}

### 21. What system call is utilised by the binary to list the files within the targeted directories?

As we know the application looks for `TracerPid`, what we can do - is patch it in Ghidra and `strace`. Essentially we're going to have it look for the string in another "file". 
If we patch it to read from `/tmp/tracerpid` instead of `/proc/self/status` - we already know that it looks for a string, `TracerPid` and expects the value to be zero. We can either create a new file with just that, or write the status of cat to tmp, `cat /proc/selv/status > /tmp/tracerpid`.
We also know which directory it tries to manipulate, so I've created a `/mnt/c/Users` with some dummy files.

Let's navigate to the section where it checks `/proc/self/status`

![TracerPid](/img/htb/sherlock/safecracker/tracerpid_0.png)

Then go and `Patch Data`, to `/tmp/tracerpid`

![TracerPid](/img/htb/sherlock/safecracker/tracerpid_1.png)

The code should look like this now 

![TracerPid](/img/htb/sherlock/safecracker/tracerpid_2.png)

Now we can execute `strace ./exe_patched`

{% highlight shell %}
strace ./exe_patched
... TRUNCATED ...
getdents64(4, 0x565074c8c7f0 /* 0 entries */, 32768) = 0
close(4)                                = 0
gettid()                                = 1114798
getpid()                                = 1114798
tgkill(1114798, 1114798, SIGSEGV)       = 0
--- SIGSEGV {si_signo=SIGSEGV, si_code=SI_TKILL, si_pid=1114798, si_uid=1000} ---
rt_sigaction(SIGSEGV, NULL, {sa_handler=0x565074080cfe, sa_mask=[], sa_flags=SA_RESTORER|SA_SIGINFO, sa_restorer=0x7f2e0643c510}, 8) = 0
rt_sigreturn({mask=[]})                 = 0
write(1, "Files found:\n", 13Files found:
)          = 13
write(1, "\t- /mnt/c/Users/Test/2.pdf."..., 37     - /mnt/c/Users/Test/2.pdf.note
{% endhighlight %}

I'm assuming that `getdents64` is what we are looking for, at least my brain tells me it means `get diretory entries`. Looking at some [documentation](https://aquasecurity.github.io/tracee/v0.13/docs/events/builtin/syscalls/getdents64/) it seems like `getdents64` does in fact list directories.

{% include htb_flag.html id="21" description="What system call is utilised by the binary to list the files within the targeted directories?" flag="getdents64" %}

### 22. Which system call is used to delete the original files?
If we look a bit further down in our output from `strace` we also see how the application deletes files

{% highlight shell %}
write(6, "You have been hacked by Cybergan"..., 336) = 336
close(6)                                = 0
close(4)                                = 0
write(5, "\347\252\360\316\274z<\322\245\256\236&&\237l\271\222\256:\373a\257\315y\365h\251\23ZOn^"..., 368) = 368
close(5)                                = 0
unlink("/mnt/c/Users/Test/1.pdf") = 0
gettid()                                = 1114798
getpid()                                = 1114798
tgkill(1114798, 1114798, SIGSEGV)       = 0
--- SIGSEGV {si_signo=SIGSEGV, si_code=SI_TKILL, si_pid=1114798, si_uid=1000} ---
rt_sigaction(SIGSEGV, NULL, {sa_handler=0x565074080cfe, sa_mask=[], sa_flags=SA_RESTORER|SA_SIGINFO, sa_restorer=0x7f2e0643c510}, 8) = 0
rt_sigreturn({mask=[]})                 = 0
write(1, "--------------------------------"..., 42-----------------------------------------
) = 42
write(1, "Configuration Successful\n", 25Configuration Successful
) = 25
write(1, "You can now connect to the Corpo"..., 41You can now connect to the Corporate VPN
{% endhighlight %}

It does something to the original file, which according to [documentation](https://aquasecurity.github.io/tracee/v0.13/docs/events/builtin/syscalls/unlink/) deletes files.


{% include htb_flag.html id="22" description="Which system call is used to delete the original files?" flag="unlink" %}