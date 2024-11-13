---
layout: post
date: 2023-12-28
platform: "HTB"
title:  "OpTinselTrace-4"
difficulty: "Easy"
scenario: "Printers are important in Santa’s workshops, but we haven’t really tried to secure them! The Grinch and his team of elite hackers may try and use this against us! Please investigate using the packet capture provided! The printer server IP Address is 192.168.68.128"
question_1: "The performance of the network printer server has become sluggish, causing interruptions in the workflow at the North Pole workshop. Santa has directed us to generate a support request and examine the network data to pinpoint the source of the issue. He suspects that the Grinch and his group may be involved in this situation. Could you verify if there is an IP Address that is sending an excessive amount of traffic to the printer server?"
question_2: "Bytesparkle being the technical Lead, found traces of port scanning from the same IP identified in previous attack. Which port was then targeted for initial compromise of the printer?"
question_3: "What is the full name of printer running on the server?"
question_4: "Grinch intercepted a list of nice and naughty children created by Santa. What was name of the second child on the nice list?"
question_5: "The Grinch obtained a print job instruction file intended for a printer used by an employee named Elfin. It appears that Santa and the North Pole management team have made the decision to dismiss Elfin. Could you please provide the word for word rationale behind the decision to terminate Elfin's employment?"
question_6: "What was the name of the scheduled print job?"
question_7: "Amidst our ongoing analysis of the current packet capture, the situation has escalated alarmingly. Our security system has detected signs of post-exploitation activities on a highly critical server, which was supposed to be secure with SSH key-only access. This development has raised serious concerns within the security team. While Bytesparkle is investigating the breach, he speculated that this security incident might be connected to the earlier printer issue. Could you determine and provide the complete path of the file on the printer server that enabled the Grinch to laterally move to this critical server?"
question_8: "What is size of this file in bytes?"
question_9: "What was the hostname of the other compromised critical server?"
question_10: "When did the Grinch attempt to delete a file from the printer? (UTC)"
---
{% include scenario.html %}

# Tasks

1. [{{ page.question_1 }}](#question-1)
2. [{{ page.question_2 }}](#question-2)
3. [{{ page.question_3 }}](#question-3)
4. [{{ page.question_4 }}](#question-4)
5. [{{ page.question_5 }}](#question-5)
6. [{{ page.question_6 }}](#question-6)
7. [{{ page.question_7 }}](#question-7)
8. [{{ page.question_8 }}](#question-8)
9. [{{ page.question_9 }}](#question-9)
10. [{{ page.question_10}}](#question-10)

# Discussion
We have read the scenario, and the tasks we are looking to answer. There are some points of information that we can pull from this, that can assist us in our further analysis.
- This involves printers and therefore likely PJL commands
- There is important files stored on the printer

Some of the keywords here are "delete", "server", "elfin", "management", "nice".

It may not be all the relevant information that we can deduce, but limiting the information that we look for is crucial when sifting through mountains of data.


# Answering the tasks
First, we need to grab the `optinseltrace4.zip` file, and unzip it, it contains another zip file named `networktraffic.zip`, which contains a packet capture file.
This is a dump of some network communication that we need to dig into.

## Question 1
{% include item.html type="question" id="1" question=page.question_1 %}

During the scenario we were informed of the IP address for the printer, so let us filter in [Wireshark](https://www.wireshark.org/) for connections with that ip as the destination. `ip.dst == 192.168.68.128`.

![Initial Scan](/img/htb/sherlock/optinseltrace-4/initial_scan.png)

It's evident that `172.17.79.133` is doing a port scan, but let's check the conversations. In Wireshark we can view conversations based on the current filter, `Statistics -> Conversations`. This shows that the previously mentioned IP address is the only one communicating (and thus excessively) with the printer.

![Conversations](/img/htb/sherlock/optinseltrace-4/conversations.png)

{% include item.html type="answer" id="1" description=page.question_1 answer="172.17.79.133" %}

## Question 2
{% include item.html type="question" id="2" question=page.question_2 %}

By using the conversation information from earlier, combined with information from the portscan, we can see that `tcp/9100` is where most of the data exchange happens. This is also a port used for network communication with printers, such as HP JetDirect or PDL. Safe to say, we know which port the TA is communicating with the printer on.

{% include item.html type="answer" id="2" description=page.question_2 answer="9100" %}

## Question 3
{% include item.html type="question" id="3" question=page.question_3 %}

Now, we need to look into the conversations happening between the TA and the printer. An easy way to do this without Wireshark is basically just to `strings` the packet capture, and deduce the answers from that. The majority of this sherlock can be answered like that.

However, let's look at how we can view that information with Wireshark. If we filter our communication on the required port by using `tcp.port == 9100` and go to the `Statistics -> Conversations` tab once again, then we have a nice view of the `Stream ID` - we need to use these in order to view the commands sent to the printer.

![Conversations](/img/htb/sherlock/optinseltrace-4/conversations_streams.png)

If we check the different dialogues, then we find the first real conversation on `Stream ID 28`.

![Conversations 28](/img/htb/sherlock/optinseltrace-4/conversations_stream_28.png)

Here, we see a PJL (Printer Job Language) query `@PJL INFO ID`, where our answer is found.

{% include message.html image="/img/htb/logo-htb.svg" content="If you would like to be on the red side of such a challenge, I can recommend <a href='https://app.hackthebox.com/challenges/gawk'>Gawk</a>" %}

{% include item.html type="answer" id="3" description=page.question_3 answer="Northpole HP LaserJet 4200n" %}

## Question 4
{% include item.html type="question" id="4" question=page.question_4 %}

If we continue down the same conversation, we find a query `@PJL FSUPLOAD FORMAT:BINARY NAME="0:/christmas/2023/Nice-kids/list1.txt"`. We need the second child on this list to answer.

![Conversations 28](/img/htb/sherlock/optinseltrace-4/conversations_stream_28_nice.png)

{% include item.html type="answer" id="4" description=page.question_4 answer="Douglas Price" %}

## Question 5
{% include item.html type="question" id="5" question=page.question_5 %}

We'll read further and discover a layoff notice `@PJL FSUPLOAD FORMAT:BINARY NAME="0:/saveDevice/SavedJobs/InProgress/Layoff-notice/Personal-Notice-Employee43.pcl" OFFSET=0 SIZE=696`. It contains the message we need to answer with, after `Reason for layoff : `.
![Conversations 28](/img/htb/sherlock/optinseltrace-4/conversations_stream_28_layoff.png)

{% include item.html type="answer" id="5" description=page.question_5 answer="The addressed employee is confirmed to be working with grinch and team. According to Clause 69 , This calls for an immediate expulsion." %}

## Question 6
{% include item.html type="question" id="6" question=page.question_6 %}
This threw me off a bit, as I thought it was referencing the previous print job. In any case, we had to check some of the other streams and if they had a `ScheduledJobs` section.

![Conversations 46](/img/htb/sherlock/optinseltrace-4/conversations_stream_46_scheduledjob.png)

Seems like getting rid of Elfin may be a joyous thing for the other elfs. Either way, the answer is the `@PJL JOB NAME`.

{% include item.html type="answer" id="6" description=page.question_6 answer="MerryChristmas+BonusAnnouncment" %}

## Question 7
{% include item.html type="question" id="7" question=page.question_7 %}

The TA goes on to explore the filesystem on the printer in `Stream ID 46` still, and they discover a private key on the printer.

![Conversations 46](/img/htb/sherlock/optinseltrace-4/conversations_stream_46_ssh.png)

If you want to read some documentation on the PJL, you can read [this](https://developers.hp.com/system/files/PJL_Technical_Reference_Manual.pdf) from HP.

The `0:` describes the Volume, and the text following that is the path - which is what we need to input as an answer.

{% include item.html type="answer" id="7" description=page.question_7 answer="/Administration/securitykeys/ssh_systems/id_rsa" %}

## Question 8
{% include item.html type="question" id="8" question=page.question_8 %}

This is more or less answered a couple of times in the previous screenshot, but `@PJL FSDIRLIST NAME="0:/Administration/securitykeys/ssh_systems" ENTRY=1` returns a single file named `id_rsa`, to which the `SIZE=` is the answer.

{% include item.html type="answer" id="8" description=page.question_8 answer="1914" %}

## Question 9
{% include item.html type="question" id="9" question=page.question_9 %}

Not only are they storing private keys on their printer, they are also adding a comment to the file where the key is to be used. I don't know what happened during the 2022 christmas for them to use that kind of tactic!

`PJL FSUPLOAD FORMAT:BINARY NAME="0:/Administration/securitykeys/ssh_systems/id_rsa" OFFSET=0 SIZE=1914` then the following line contains our answer.

{% include item.html type="answer" id="9" description=page.question_9 answer="christmas.gifts" %}

## Question 10
{% include item.html type="question" id="10" question=page.question_10 %}

If we read the documentation on the PJL commands, we know that we are looking for a `FSDELETE` command, and we find one of those in `Stream ID 71`.

![Conversations 71](/img/htb/sherlock/optinseltrace-4/conversations_stream_71_fsdelete.png)

We can click the line with `FSDELETE`, then Wireshark will mark the packet in the main view. Once done, we can view the timestamp of that packet in the Time column

![Conversations 71](/img/htb/sherlock/optinseltrace-4/conversations_stream_71_fsdeleteTS.png)

If you have a sequence number or anything else in the time column, you can modify the information in the columns by alternate clicking the column, go to `Column Preferences` then select the `Time` column and change the type to `UTC date, as YYYY-MM-DD, and time`

{% include item.html type="answer" id="10" description=page.question_10 answer="2023-12-08 12:18:14" %}