---
layout: post
date: 2024-11-26
platform: "CD"
title: "Brutal Tank"
difficulty: "Hard"
scenario: "Your expertise as a Cybersecurity Incident Responder is urgently needed following a severe incident at our industrial facility. An attacker appears to have successfully breached our network and significantly damaged our Programmable Logic Controller (PLC), responsible for regulating the pressurized airflow. This breach led to the destruction of one air tank and the damage to another. Thankfully, our network TAPs captured the critical moments of this attack, which have been logged in our ARKIME packet capture and search system. You are tasked with determining the events that led to the PLC compromise and identifying the attacker&#39;s entry point. Your findings will be crucial in reinforcing our network defenses and preventing such breaches in the future."
question_1: "Knowing which machines the attacker targets helps understand their motives and goals. What is the IP address of the machine targeted by the attacker?"
question_2: "The role and importance of the targeted device within the industrial facility infrastructure dictate the potential impact of the attack. What&#39;s the name of the device being attacked? (Format: Manufacturer Product)"
question_3: "Accessing specific memory locations can lead to information disclosure about the PLC&#39;s state or configuration. Which memory locations were read by the attacker? Provide the byte address only in decimal format."
question_4: "The URL path can sometimes indicate the potential attack vector the attacker is trying to exploit. What URL path was the attacker targeting to gain unauthorized access?"
question_5: "We need to determine whether the attacker was successful. What is the security hint of the attacker&#39;s successful login session?"
question_6: "One of the features of the web interface is the ability to set I/O point states. What is the first command the attacker sent to set the states of these I/O points?"
question_7: "What is the last command the attacker used to read the states of the I/O points?"
question_8: "Following up on the previous questions, what is the MITRE ICS ID of the technique the attacker used?"
---
{% include scenario.html %}

# Questions

1. [{{ page.question_1}}](#question-1)
2. [{{ page.question_2}}](#question-2)
3. [{{ page.question_3}}](#question-3)
4. [{{ page.question_4}}](#question-4)
5. [{{ page.question_5}}](#question-5)
6. [{{ page.question_6}}](#question-6)
7. [{{ page.question_7}}](#question-7)
8. [{{ page.question_8}}](#question-8)

# Discussion
For this lab will be using [ARKIME](https://arkime.com/) which is a Full Packet Capture platform - or SIEM for network captures.

# Answering the Tasks

## Question 1
{% include item.html type="question" id="1" question=page.question_1 %}

If we navigate to the **Connections** tabs in ARKIME, we can get an overview of the connections in the environment. 

![Q1 Overview](/img/cd/blueyard/brutaltank/q1_overview.png)

This gives a node overview of the connections between the hosts - some multicast traffic (224.0.0.0-239.255.255.255), APIPA traffic (169.254.0.0-169.254.255.255) and then 3 hosts. Those hosts are the ones we will be looking at.

* 10.1.1.1
* 10.1.1.11
* 10.1.1.15

Let's rule out the `10.1.1.1` address - presumeably the gateway address, since it's at the `.1` and both `.11` and `.15` communicates through it.

If we navigate to the **SPIView**, we can see a session profile information view. We can further narrow our information to the two hosts we are curious about with `(ip == 10.1.1.15 || ip == 10.1.1.11)`.

![Q1 SPIView](/img/cd/blueyard/brutaltank/q1_spiview.png)

There is some identified HTTP traffic, then the rest is TCP (and a few pings).

If we click the **Load All** button the **General** pane, we get a lot of statistics and neat information about the sessions. Scrolling a bit down we get a `Dst OUI` field, this is the identified vendor for the devices MAC addresses. Since we are looking for a PLC it makes sense that this would be the target device. 

Click the `Siemens` OUI and open a new sessions tab for further confirmation

![Q1 Siemens Sessions](/img/cd/blueyard/brutaltank/q1_sessiontab.png)

This shows some connections towards a webservice on the targeted IP - so now we know the `target`.

![Q1 Answer](/img/cd/blueyard/brutaltank/q1_answer.png)

{% include item.html type="answer" id="1" description=page.question_1 answer="10.1.1.15" %}

## Question 2
{% include item.html type="question" id="2" question=page.question_2 %}

If we expand the first session, we are then able to go a bit more in depth on the captures

![Q2 Expanded](/img/cd/blueyard/brutaltank/q2_expanded.png)

There is quite a lot of packages, so instead of trying to figure out if the name of the system is mentioned somewhere - we can use a bit of logic and OSINT.

We already know it's a Siemens system, based on the mac OUI. We just need to determine the product name of the siemens PLC.
Most of the files in the `referer header` field are named `logo_`-something. Searching for some of those files could lead us to [this](https://support.industry.siemens.com/forum/WW/de/posts/web-user-is-disabled/266510) forum post for a `LOGO!` system. 

Searching for that text confirms the name of the product, in the HTTP title tag.

![Q2 Answer](/img/cd/blueyard/brutaltank/q2_answer.png)

{% include item.html type="answer" id="2" description=page.question_2 answer="Siemens LOGO!" %}

## Question 3
{% include item.html type="question" id="3" question=page.question_3 %}

Figuring out how the PLC works usually requires reading a bit of information, such as the [documentation](https://assets.new.siemens.com/siemens/assets/api/uuid:557e34c1-4111-4625-921a-0717d0053571/Manual-LOGO-2020.pdf) or if you are lucky, then someone has already done a bit of [offensive research](https://github.com/jankeymeulen/siemens-logo-rest).

By going through the information, we will learn that `tcp/102` is the port service. Using the filter `(ip == 10.1.1.15 || ip == 10.1.1.11) && port.dst == 102` will give us these results:

![Q3 Query](/img/cd/blueyard/brutaltank/q3_query.png)

Selecting the first session and downloading the PCAP allows us to analyze the data in Wireshark.

![Q3 PCAP download](/img/cd/blueyard/brutaltank/q3_download.png)

There are multiple invocations of `ROSCRTR:[JOB]` which according to [2.1 on this website](http://gmiru.com/article/s7comm/) can mean a read of a memory addresses.

The byte address found in the `Item [1]: (DB 1.DBX ****.0 BIT1)` is what we are looking for.

![Q3 Answer](/img/cd/blueyard/brutaltank/q3_answer.png)

{% include item.html type="answer" id="3" description=page.question_3 answer="1064" %}

## Question 4
{% include item.html type="question" id="4" question=page.question_4 %}

Going back to question 3, someone has [done some research](https://github.com/jankeymeulen/siemens-logo-rest) where we can see how the authentcation flow is, more or less.

Let's modify our search query to HTTP instead of HMI: `(ip == 10.1.1.15 || ip == 10.1.1.11) && port.dst == 80`
Find a POST to `/AJAX` and we can see which page is being used for logins.

![Q4 Answer](/img/cd/blueyard/brutaltank/q4_answer.png)

{% include item.html type="answer" id="4" description=page.question_4 answer="logo_login.shtm" %}

## Question 5
{% include item.html type="question" id="5" question=page.question_5 %}

Keeping the reference from the research, it describes sending a `Security-Hint: p` which will return some values in `UAMCHAL` that will be the basis of the Security Hint.

The attacker tried multiple times, so scroll to the last session to view the event where they gain access, this is visible when the http referrer header contains the Security-Hint.

![Q5 Last Packet](/img/cd/blueyard/brutaltank/q5_security-hint.png)

If we scroll further down the session, we can see the Security-Hint be set as the cookie

![Q5 Answer](/img/cd/blueyard/brutaltank/q5_answer.png)

{% include item.html type="answer" id="5" description=page.question_5 answer="9E2D4B28BDCCE7C1BACFC0E7E51C55F7" %}

## Question 6
{% include item.html type="question" id="6" question=page.question_6 %}

A part of the research contains references to `SETVARS` and `GETVARS`. So let's hunt for `VARS:` by going to **Hunt** and create a new hunt. Remember to set the filter to `(ip == 10.1.1.15 || ip == 10.1.1.11)`, set a higher number of packages to examine per session.

![Q6 Varsearch](/img/cd/blueyard/brutaltank/q6_varsearch.png)

Once the search has concluded, press the Folder icon so you are directed to the hunt query. Download the hunt as a pcap, and open in Wireshark.

When opened in Wireshark, we need to filter for commands sent by the attacker - this can be done by looking for `POST` with the `SETVARS` text: `http.request.method == "POST" && data-text-lines contains "SETVARS"`

![Q6 Answer](/img/cd/blueyard/brutaltank/q6_answer.png)


{% include item.html type="answer" id="6" description=page.question_6 answer="SETVARS:_local_=v0,Q..1:1-1,01;v1,Q..1:2-1,00;v2,Q..1:3-1,00;v3,Q..1:4-1,00" %}

## Question 7
{% include item.html type="question" id="7" question=page.question_7 %}

Similarly, we can also search for `GETVARS` with `http.request.method == "POST" && data-text-lines contains "GETVARS"` and scroll all the way to the bottom (or reverse based on time):

![Q7 Answer](/img/cd/blueyard/brutaltank/q7_answer.png)

{% include item.html type="answer" id="7" description=page.question_7 answer="GETVARS:_local_=v0,Q..1:1-1;v1,Q..1:2-1;v2,Q..1:3-1" %}

## Question 8
{% include item.html type="question" id="8" question=page.question_8 %}

We need to look at the [MITRE ICS](https://attack.mitre.org/techniques/ics/) techniques and the capture that we have.

From the capture there is a sequence of `SETVARS`:

|`SETVARS:_local_=v0,Q..1:1-1,01;v1,Q..1:2-1,00;v2,Q..1:3-1,00;v3,Q..1:4-1,00`|
|`SETVARS:_local_=v0,Q..1:1-1,00;v1,Q..1:2-1,01;v2,Q..1:3-1,01`|
|`SETVARS:_local_=v0,Q..1:1-1,00;v1,Q..1:2-1,00;v2,Q..1:3-1,01`|
|`SETVARS:_local_=v0,Q..1:1-1,00;v1,Q..1:2-1,00;v2,Q..1:3-1,00`|
|`SETVARS:_local_=v0,Q..1:1-1,01;v1,Q..1:2-1,00;v2,Q..1:3-1,00`|
|`SETVARS:_local_=v0,Q..1:1-1,01;v1,Q..1:2-1,01;v2,Q..1:3-1,00`|
|`SETVARS:_local_=v0,Q..1:1-1,01;v1,Q..1:2-1,01;v2,Q..1:3-1,01`|

As you may notice, each invocation are changing at least a single bit indicative of [Brute Force I/O](https://attack.mitre.org/techniques/T0806/) which is a [Impair Process Control](https://attack.mitre.org/tactics/TA0106/) tactic.

{% include item.html type="answer" id="8" description=page.question_8 answer="T0806" %}

