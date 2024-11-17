---
layout: post
date: 2024-11-14
platform: "CD"
title:  "NerisBot"
difficulty: "Easy"
scenario: "As a security engineer recalled to investigate a university environment, you've identified unusual network activities indicative of malicious intent. These anomalies, observed just six hours ago, suggest the operation of command and control communications along with other potentially harmful behaviors.

Your mission is to analyze recent network traffic logs to pinpoint and investigate malicious interactions. Identify command and control servers, and segregate malicious flows."
question_1: "Can you identify the IP address from which the initial unauthorized access originated?"
question_2: "What is the domain name of the attacker server?"
question_3: "What is the IP address of the system that was targeted in this breach?"
question_4: "Identify all the unique files downloaded to the compromised host. How many of these files could potentially be malicious?"
question_5: "What is the sha256 hash of the malicious file disguised as a txt file?"
---
{% include scenario.html %}

# Questions

1. [{{ page.question_1 }}](#question-1)
2. [{{ page.question_2 }}](#question-2)
3. [{{ page.question_3 }}](#question-3)
4. [{{ page.question_4 }}](#question-4)
5. [{{ page.question_5 }}](#question-5)

# Answering the Tasks

This lab runs on Splunk, so make sure to set the search time to "All time" to begin with, so we get all the events. We can narrow down our search later.

This lab is for the Neris botnet, and if someone has done the research before us we can utilize that information in our querying. Searching the internet for research related to Neris can give us [this publication](https://www.osti.gov/servlets/purl/1543482) and many others.

## Question 1
{% include item.html type="question" id="1" question=page.question_1 %}

We need to look at some of the source we have available, so let's query the sourcetypes
{% highlight kql %}
| metadata type=sourcetypes index=*
{% endhighlight %}
![Q1 sourcetypes](/img/cd/blueyard/nerisbot/q1_sourcetypes.png)

There is a source for [Suricata](https://suricata.io/), which is an IDS and likely a good source for some intrusion detection events.

So lets see what event types we can get from Suricata:
{% highlight kql %}
index=* sourcetype=suricata
{% endhighlight %}
![Q1 suricata events](/img/cd/blueyard/nerisbot/q1_suricata_events.png)

There is even an eventtype named `suricata_eve_ids_attack`, lets poke around in that index for some information.

{% highlight kql %}
index=* sourcetype=suricata eventtype=suricata_eve_ids_attack
{% endhighlight %}
This still yields us a lot of sources (2872 to be precise), so we need to make an overview of what is happening.

That can be done in splunk with grouping data by a value and then list all values associated in a table. `stats values(values_we_want) by value_we_want_to_group`

{% highlight kql %}
index=* sourcetype=suricata eventtype=suricata_eve_ids_attack
| stats values(dest_ip) values(http.http_user_agent) values(http.http_content_type) values(http.http_protocol) values(http.status) values(http.hostname) values(http.url) by src_ip
{% endhighlight %}

![Q1 suricata groups](/img/cd/blueyard/nerisbot/q1_suricata_groups.png)

Scrolling a bit down, we'll find some `exe` being downloaded.

![Q1 answer](/img/cd/blueyard/nerisbot/q1_nerisbot_answer.png)

We can also correlate the query with the publication we have read. On page 15 there is a table which describes the User-Agent used by Neris: `Download`.

Filtering by that, we can get a better overview, that we can use to search "backwards"

![Q1 download](/img/cd/blueyard/nerisbot/q1_nerisbot_download.png)

This gives us 3 interesting IP addresses `147.32.84.165`, `60.190.223.75` and `195.88.191.59`. If we search for them as the destination, where the url has some content:

{% highlight kql %}
index=* sourcetype=suricata dest_ip IN (60.190.223.75, 195.88.191.59) http.url=*
| table _time values dest_ip http.http_user_agent http.http_content_type http.status http.hostname http.url src_ip
| sort + _time
{% endhighlight %}

![Q1 answer](/img/cd/blueyard/nerisbot/q1_nerisbot_answer_depth.png)

This shows us the source ip accessing a website with (what looks like) their browser, downloading a file `/temp/3425.exe` and a good 5 minutes later then another client is accessing the exact same website.

{% include item.html type="answer" id="1" description=page.question_1 answer="195.88.191.59" %}

## Question 2
{% include item.html type="question" id="2" question=page.question_2 %}

When we found the IP, the information for the domain was stored in the `http.hostname` property. As we are getting Suricata logs, we should also be able to find a DNS related event: 
{% highlight kql %}
index=* sourcetype=suricata event_type=dns "dns.answers{}.rdata"="195.88.191.59" 
| stats count by dns.rrname
{% endhighlight %}

This query reveals the same, as the `http.hostname`.

![Q2 DNS](/img/cd/blueyard/nerisbot/q2_answer_dns.png)

{% include item.html type="answer" id="2" description=page.question_2 answer="nocomcom.com" %}

## Question 3
{% include item.html type="question" id="3" question=page.question_3 %}

This information has already been presented to us a couple of times. Essentially we would be looking at `src_ip` for any of the above queries.

![Q3 DNS](/img/cd/blueyard/nerisbot/q3_answer_dns.png)
![Q3 HTTP](/img/cd/blueyard/nerisbot/q3_answer_http.png)

{% include item.html type="answer" id="3" description=page.question_3 answer="147.32.84.165" %}

## Question 4
{% include item.html type="question" id="4" question=page.question_4 %}

Knowing the source and destination IPs helps us a lot so we can search for files downloaded to the device, and get a count of files - assuming that the different filesize is their uniqueness:
{% highlight kql %}
index=* sourcetype=suricata src_ip=147.32.84.165 dest_ip=195.88.191.59 url=*
{% endhighlight %}

![Q4 count](/img/cd/blueyard/nerisbot/q4_count.png)

We need to determine how many of those files are potentially malicious. Suricata does not cover the hashes for files - but Zeek/Bro does, so let's check the downloaded files from our destination IP.

![Q5 hashes](/img/cd/blueyard/nerisbot/q5_hashes.png)

{% highlight kql %}
index=* sourcetype=zeek:files tx_hosts="195.88.191.59"
| table _time seen_bytes md5 sha1 sha256
{% endhighlight %}

Now we have some hashes we can work with. 

{% include vt.html md5="7c8d12f776b17da6576c6469d8ad5a2b" sha1="5dc958a367b495b48bb548177ae7558e842acb1f" sha256="617520dbb4c29f0d072ffb6f9f637c558dc224441d235943957aaa8f5de8db6f" scorec=63 scoret=72 created="2011-08-08 02:02:57 UTC" %}
{% include vt.html md5="a7d0e9196d472dbaa6948fdeb33045a0" sha1="cc32bf22df045a6e787da42e3b011eac8f02ee85" sha256="2ed4a4ad94c6148b013aecacae783748d51d429de4f1d477a79bbf025d03d47a" scorec=57 scoret=71 created="2011-03-30 17:41:15 UTC" %}
{% include vt.html md5="564048b35da9d447f2e861d5896d908d" sha1="2a6d5ad9a782c96f9cd214fcd105056248e6df31" sha256="6fbc4d506f4d4e0a64ca09fd826408d3103c1a258c370553583a07a4cb9a6530" scorec=64 scoret=72 created="2011-03-30 17:41:15 UTC" %}   
{% include vt.html md5="42d00e295e1c3715acd51a0fc54bad87" sha1="e88ba2c9a9948f238cbdb3193e067fc95281c715" sha256="00f15e22ab95632fc51d09f179eb22f5a36e92f6e99390f08a4161f2f93e1717" scorec=60 scoret=68 created="2011-08-06 19:20:59 UTC" %}
{% include vt.html md5="8ed68a129b3634320780719abf6635cc" sha1="29b4edb6a1ebe70a8fe876a5652ed7de067269f4" sha256="6d8353efda8438bf2dff79d6a4c174d5593450858c74c45c6f2718927546c1bd" scorec=56 scoret=72 created="2005-11-08 22:31:42 UTC" %}

Based on the results from VirusTotal, it seems like all the files are known as malicious.

{% include item.html type="answer" id="4" description=page.question_4 answer="5" %}

## Question 5
{% include item.html type="question" id="5" question=page.question_5 %}

As we may have noticed during our last query, then we were unable to see the SHA256. However, our lookups to VirusTotal have gotten us a SHA256 we can use.

One of those files did not have a `.exe` extension. That's the file we are looking for.

Let's see if we can just join the `bytes` from the Suricata to the `seen_bytes` Zeek.
{% highlight kql %}
index=* sourcetype=zeek:files tx_hosts="195.88.191.59" 
| join left=L right=R where L.seen_bytes=R.bytes
    [search index=* sourcetype=suricata src_ip=147.32.84.165 dest_ip=195.88.191.59 url=* ]
| table L.md5, L.sha1, R.url
{% endhighlight %}

![Q6 answer](/img/cd/blueyard/nerisbot/q6_answer.png)

We can then reuse our lookups to VirusTotal, and find the SHA256.

{% include item.html type="answer" id="5" description=page.question_5 answer="6fbc4d506f4d4e0a64ca09fd826408d3103c1a258c370553583a07a4cb9a6530" %}