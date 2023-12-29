---
layout: post
title:  "Sherlocks - OpTinselTrace-4"
category: HTB
---
{% include htb_sherlock.html title="OpTinselTrace-4" difficulty="Easy" scenario="Printers are important in Santa’s workshops, but we haven’t really tried to secure them! The Grinch and his team of elite hackers may try and use this against us! Please investigate using the packet capture provided! The printer server IP Address is 192.168.68.128" %}

# Tasks

1. [The performance of the network printer server has become sluggish, causing interruptions in the workflow at the North Pole workshop. Santa has directed us to generate a support request and examine the network data to pinpoint the source of the issue. He suspects that the Grinch and his group may be involved in this situation. Could you verify if there is an IP Address that is sending an excessive amount of traffic to the printer server?](#1-the-performance-of-the-network-printer-server-has-become-sluggish-causing-interruptions-in-the-workflow-at-the-north-pole-workshop-santa-has-directed-us-to-generate-a-support-request-and-examine-the-network-data-to-pinpoint-the-source-of-the-issue-he-suspects-that-the-grinch-and-his-group-may-be-involved-in-this-situation-could-you-verify-if-there-is-an-ip-address-that-is-sending-an-excessive-amount-of-traffic-to-the-printer-server)
2. [Bytesparkle being the technical Lead, found traces of port scanning from the same IP identified in previous attack. Which port was then targeted for initial compromise of the printer?](#2-bytesparkle-being-the-technical-lead-found-traces-of-port-scanning-from-the-same-ip-identified-in-previous-attack-which-port-was-then-targeted-for-initial-compromise-of-the-printer)
3. [What is the full name of printer running on the server?](#3-what-is-the-full-name-of-printer-running-on-the-server)
4. [Grinch intercepted a list of nice and naughty children created by Santa. What was name of the second child on the nice list?](#4-grinch-intercepted-a-list-of-nice-and-naughty-children-created-by-santa-what-was-name-of-the-second-child-on-the-nice-list)
5. [The Grinch obtained a print job instruction file intended for a printer used by an employee named Elfin. It appears that Santa and the North Pole management team have made the decision to dismiss Elfin. Could you please provide the word for word rationale behind the decision to terminate Elfin's employment?](#5-the-grinch-obtained-a-print-job-instruction-file-intended-for-a-printer-used-by-an-employee-named-elfin-it-appears-that-santa-and-the-north-pole-management-team-have-made-the-decision-to-dismiss-elfin-could-you-please-provide-the-word-for-word-rationale-behind-the-decision-to-terminate-elfins-employment)
6. [What was the name of the scheduled print job?](#6-what-was-the-name-of-the-scheduled-print-job)
7. [Amidst our ongoing analysis of the current packet capture, the situation has escalated alarmingly. Our security system has detected signs of post-exploitation activities on a highly critical server, which was supposed to be secure with SSH key-only access. This development has raised serious concerns within the security team. While Bytesparkle is investigating the breach, he speculated that this security incident might be connected to the earlier printer issue. Could you determine and provide the complete path of the file on the printer server that enabled the Grinch to laterally move to this critical server?](#7-amidst-our-ongoing-analysis-of-the-current-packet-capture-the-situation-has-escalated-alarmingly-our-security-system-has-detected-signs-of-post-exploitation-activities-on-a-highly-critical-server-which-was-supposed-to-be-secure-with-ssh-key-only-access-this-development-has-raised-serious-concerns-within-the-security-team-while-bytesparkle-is-investigating-the-breach-he-speculated-that-this-security-incident-might-be-connected-to-the-earlier-printer-issue-could-you-determine-and-provide-the-complete-path-of-the-file-on-the-printer-server-that-enabled-the-grinch-to-laterally-move-to-this-critical-server)
8. [What is size of this file in bytes?](#8-what-is-size-of-this-file-in-bytes)
9. [What was the hostname of the other compromised critical server?](#9-what-was-the-hostname-of-the-other-compromised-critical-server)
10. [When did the Grinch attempt to delete a file from the printer? (UTC)](#10-when-did-the-grinch-attempt-to-delete-a-file-from-the-printer-utc)

# Discussion
We have read the scenario, and the tasks we are looking to answer. There are some points of information that we can pull from this, that can assist us in our further analysis.
- This involves printers and therefore likely PJL commands
- There is important files stored on the printer

Some of the keywords here are "delete", "server", "elfin", "management", "nice".

It may not be all the relevant information that we can deduce, but limiting the information that we look for is crucial when sifting through mountains of data.


# Answering the tasks
First, we need to grab the `optinseltrace4.zip` file, and unzip it, it contains another zip file named `networktraffic.zip`, which contains a packet capture file.
This is a dump of some network communication that we need to dig into.

### 1. The performance of the network printer server has become sluggish, causing interruptions in the workflow at the North Pole workshop. Santa has directed us to generate a support request and examine the network data to pinpoint the source of the issue. He suspects that the Grinch and his group may be involved in this situation. Could you verify if there is an IP Address that is sending an excessive amount of traffic to the printer server?

During the scenario we were informed of the IP address for the printer, so let us filter in [Wireshark](https://www.wireshark.org/) for connections with that ip as the destination. `ip.dst == 192.168.68.128`.

![Initial Scan](/img/htb/sherlock/optinseltrace-4/initial_scan.png)

It's evident that `172.17.79.133` is doing a port scan, but let's check the conversations. In Wireshark we can view conversations based on the current filter, `Statistics -> Conversations`. This shows that the previously mentioned IP address is the only one communicating (and thus excessively) with the printer.

![Conversations](/img/htb/sherlock/optinseltrace-4/conversations.png)

{% include htb_flag.html id="1" description="The performance of the network printer server has become sluggish, causing interruptions in the workflow at the North Pole workshop. Santa has directed us to generate a support request and examine the network data to pinpoint the source of the issue. He suspects that the Grinch and his group may be involved in this situation. Could you verify if there is an IP Address that is sending an excessive amount of traffic to the printer server?" flag="172.17.79.133" %}

### 2. Bytesparkle being the technical Lead, found traces of port scanning from the same IP identified in previous attack. Which port was then targeted for initial compromise of the printer?

By using the conversation information from earlier, combined with information from the portscan, we can see that `tcp/9100` is where most of the data exchange happens. This is also a port used for network communication with printers, such as HP JetDirect or PDL. Safe to say, we know which port the TA is communicating with the printer on.

{% include htb_flag.html id="2" description="Bytesparkle being the technical Lead, found traces of port scanning from the same IP identified in previous attack. Which port was then targeted for initial compromise of the printer?" flag="9100" %}

### 3. What is the full name of printer running on the server?

Now, we need to look into the conversations happening between the TA and the printer. An easy way to do this without Wireshark is basically just to `strings` the packet capture, and deduce the answers from that. The majority of this sherlock can be answered like that.

However, let's look at how we can view that information with Wireshark. If we filter our communication on the required port by using `tcp.port == 9100` and go to the `Statistics -> Conversations` tab once again, then we have a nice view of the `Stream ID` - we need to use these in order to view the commands sent to the printer.

![Conversations](/img/htb/sherlock/optinseltrace-4/conversations_streams.png)

If we check the different dialogues, then we find the first real conversation on `Stream ID 28`.

![Conversations 28](/img/htb/sherlock/optinseltrace-4/conversations_stream_28.png)

Here, we see a PJL (Printer Job Language) query `@PJL INFO ID`, where our answer is found.

{% include htb_challenge.html content="If you would like to be on the red side of such a challenge, I can recommend <a href='https://app.hackthebox.com/challenges/gawk' style='color: #ffaf00'>Gawk</a>" %}

{% include htb_flag.html id="3" description="What is the full name of printer running on the server?" flag="Northpole HP LaserJet 4200n" %}

### 4. Grinch intercepted a list of nice and naughty children created by Santa. What was name of the second child on the nice list?

If we continue down the same conversation, we find a query `@PJL FSUPLOAD FORMAT:BINARY NAME="0:/christmas/2023/Nice-kids/list1.txt"`. We need the second child on this list to answer.

![Conversations 28](/img/htb/sherlock/optinseltrace-4/conversations_stream_28_nice.png)

{% include htb_flag.html id="4" description="Grinch intercepted a list of nice and naughty children created by Santa. What was name of the second child on the nice list?" flag="Douglas Price" %}

### 5. The Grinch obtained a print job instruction file intended for a printer used by an employee named Elfin. It appears that Santa and the North Pole management team have made the decision to dismiss Elfin. Could you please provide the word for word rationale behind the decision to terminate Elfin's employment?

We'll read further and discover a layoff notice `@PJL FSUPLOAD FORMAT:BINARY NAME="0:/saveDevice/SavedJobs/InProgress/Layoff-notice/Personal-Notice-Employee43.pcl" OFFSET=0 SIZE=696`. It contains the message we need to answer with, after `Reason for layoff : `.
![Conversations 28](/img/htb/sherlock/optinseltrace-4/conversations_stream_28_layoff.png)

{% include htb_flag.html id="5" description="The Grinch obtained a print job instruction file intended for a printer used by an employee named Elfin. It appears that Santa and the North Pole management team have made the decision to dismiss Elfin. Could you please provide the word for word rationale behind the decision to terminate Elfin's employment?" flag="The addressed employee is confirmed to be working with grinch and team. According to Clause 69 , This calls for an immediate expulsion." %}

### 6. What was the name of the scheduled print job?
This threw me off a bit, as I thought it was referencing the previous print job. In any case, we had to check some of the other streams and if they had a `ScheduledJobs` section.

![Conversations 46](/img/htb/sherlock/optinseltrace-4/conversations_stream_46_scheduledjob.png)

Seems like getting rid of Elfin may be a joyous thing for the other elfs. Either way, the answer is the `@PJL JOB NAME`.

{% include htb_flag.html id="6" description="What was the name of the scheduled print job?" flag="MerryChristmas+BonusAnnouncment" %}

### 7. Amidst our ongoing analysis of the current packet capture, the situation has escalated alarmingly. Our security system has detected signs of post-exploitation activities on a highly critical server, which was supposed to be secure with SSH key-only access. This development has raised serious concerns within the security team. While Bytesparkle is investigating the breach, he speculated that this security incident might be connected to the earlier printer issue. Could you determine and provide the complete path of the file on the printer server that enabled the Grinch to laterally move to this critical server?

The TA goes on to explore the filesystem on the printer in `Stream ID 46` still, and they discover a private key on the printer.

![Conversations 46](/img/htb/sherlock/optinseltrace-4/conversations_stream_46_ssh.png)

If you want to read some documentation on the PJL, you can read [this](https://developers.hp.com/system/files/PJL_Technical_Reference_Manual.pdf) from HP.

The `0:` describes the Volume, and the text following that is the path - which is what we need to input as an answer.

{% include htb_flag.html id="7" description="Amidst our ongoing analysis of the current packet capture, the situation has escalated alarmingly. Our security system has detected signs of post-exploitation activities on a highly critical server, which was supposed to be secure with SSH key-only access. This development has raised serious concerns within the security team. While Bytesparkle is investigating the breach, he speculated that this security incident might be connected to the earlier printer issue. Could you determine and provide the complete path of the file on the printer server that enabled the Grinch to laterally move to this critical server?" flag="/Administration/securitykeys/ssh_systems/id_rsa" %}

### 8. What is size of this file in bytes?

This is more or less answered a couple of times in the previous screenshot, but `@PJL FSDIRLIST NAME="0:/Administration/securitykeys/ssh_systems" ENTRY=1` returns a single file named `id_rsa`, to which the `SIZE=` is the answer.

{% include htb_flag.html id="8" description="What is size of this file in bytes?" flag="1914" %}

### 9. What was the hostname of the other compromised critical server?

Not only are they storing private keys on their printer, they are also adding a comment to the file where the key is to be used. I don't know what happened during the 2022 christmas for them to use that kind of tactic!

`PJL FSUPLOAD FORMAT:BINARY NAME="0:/Administration/securitykeys/ssh_systems/id_rsa" OFFSET=0 SIZE=1914` then the following line contains our answer.

{% include htb_flag.html id="9" description="What was the hostname of the other compromised critical server?" flag="christmas.gifts" %}

### 10. When did the Grinch attempt to delete a file from the printer? (UTC)

If we read the documentation on the PJL commands, we know that we are looking for a `FSDELETE` command, and we find one of those in `Stream ID 71`.

![Conversations 71](/img/htb/sherlock/optinseltrace-4/conversations_stream_71_fsdelete.png)

We can click the line with `FSDELETE`, then Wireshark will mark the packet in the main view. Once done, we can view the timestamp of that packet in the Time column

![Conversations 71](/img/htb/sherlock/optinseltrace-4/conversations_stream_71_fsdeleteTS.png)

If you have a sequence number or anything else in the time column, you can modify the information in the columns by alternate clicking the column, go to `Column Preferences` then select the `Time` column and change the type to `UTC date, as YYYY-MM-DD, and time`

{% include htb_flag.html id="10" description="When did the Grinch attempt to delete a file from the printer? (UTC)" flag="2023-12-08 12:18:14" %}

## Congratulations

You've have pwned OpTinselTrace-4