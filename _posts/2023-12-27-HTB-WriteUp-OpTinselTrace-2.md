---
layout: post
title:  "Sherlocks - OpTinselTrace-2"
category: HTB
---
{% include htb_sherlock.html title="OpTinselTrace-2" difficulty="Easy" scenario="It seems our precious technology has been leaked to the threat actor. Our head Elf, PixelPepermint, seems to think that there were some hard-coded sensitive URLs within the technology sent. Please audit our Sparky Cloud logs and confirm if anything was stolen! PS - Santa likes his answers in UTC..."  %}

# Tasks

1. [What is the MD5 sum of the binary the Threat Actor found the S3 bucket location in?](#1-what-is-the-md5-sum-of-the-binary-the-threat-actor-found-the-s3-bucket-location-in)
2. [What time did the Threat Actor begin their automated retrieval of the contents of our exposed S3 bucket?](#2-what-time-did-the-threat-actor-begin-their-automated-retrieval-of-the-contents-of-our-exposed-s3-bucket)
3. [What time did the Threat Actor complete their automated retrieval of the contents of our exposed S3 bucket?](#3-what-time-did-the-threat-actor-complete-their-automated-retrieval-of-the-contents-of-our-exposed-s3-bucket)
4. [Based on the Threat Actor's user agent - what scripting language did the TA likely utilise to retrieve the files?](#4-based-on-the-threat-actors-user-agent---what-scripting-language-did-the-ta-likely-utilise-to-retrieve-the-files)
5. [Which file did the Threat Actor locate some hard coded credentials within?](#5-which-file-did-the-threat-actor-locate-some-hard-coded-credentials-within)
6. [Please detail all confirmed malicious IP addresses. (Ascending Order)](#6-please-detail-all-confirmed-malicious-ip-addresses-ascending-order)
7. [We are extremely concerned the TA managed to compromise our private S3 bucket, which contains an important VPN file. Please confirm the name of this VPN file and the time it was retrieved by the TA.](#7-we-are-extremely-concerned-the-ta-managed-to-compromise-our-private-s3-bucket-which-contains-an-important-vpn-file-please-confirm-the-name-of-this-vpn-file-and-the-time-it-was-retrieved-by-the-ta)
8. [Please confirm the username of the compromised AWS account?](#8-please-confirm-the-username-of-the-compromised-aws-account)
9. [Based on the analysis completed Santa Claus has asked for some advice. What is the ARN of the S3 Bucket that requires locking down?](#9-based-on-the-analysis-completed-santa-claus-has-asked-for-some-advice-what-is-the-arn-of-the-s3-bucket-that-requires-locking-down)

# Discussion
We have read the scenario, and the tasks we are looking to answer. There are some points of information that we can pull from this, that can assist us in our further analysis.
- The TA has automated retrieval of content from an open S3 bucket
- The TA as accessed a file with credentials, potentially compromising a private S3 bucket
- The TA may have grabbed a VPN file.

Some of the keywords here are "vpn" and "private".

It may not be all the relevant information that we can deduce, but limiting the information that we look for is crucial when sifting through mountains of data.

# Answering the tasks
First, we need to grab the `optinseltrace2.zip` file, and unzip it, it contains a folder called `optinseltrace2-cloudtrail`.
This is a dump of an Amazon Web Services cloud service, where the majority of the information is stored in json format.

### 1. What is the MD5 sum of the binary the Threat Actor found the S3 bucket location in?
This references the `top-secret` directory we found in OpTinselTrace-1, and the content of the `santa_deliveries.zip` file.
{% highlight bash %}
kali$ unzip santa_deliveries.zip
Archive:  santa_deliveries.zip
  inflating: santa_deliveries        

kali$ md5sum santa_deliveries                   
62d5c1f1f9020c98f97d8085b9456b05  santa_deliveries

kali$ strings santa_deliveries | grep 'aws'
https://papa-noel.s3.eu-west-3.amazonaws.com/santa-list.csv

{% endhighlight %}

We `strings` the binary, just to confirm there is references for AWS - which there is (there is also a username and a password).

| **Answer for #1** | `62d5c1f1f9020c98f97d8085b9456b05` |

### 2. What time did the Threat Actor begin their automated retrieval of the contents of our exposed S3 bucket?
Now we need to determine which IP the TA is using, to figure out when they were pulling data from the S3 bucket.

Let's start by figuring out which source IP addresses are present in our cloudtrail logs. The obvious choice here is [jq](https://jqlang.github.io/jq/).

{% highlight bash %}
OpTinselTrace-2$ find . -name '*.json' -exec cat {} \; | jq '.Records[] | .sourceIPAddress' | sort | uniq -c 2>/dev/null
      1 "109.205.185.126"
      2 "138.199.59.46"
     13 "191.101.31.26"
     50 "191.101.31.57"
      6 "195.181.170.226"
      1 "3.236.115.9"
      1 "3.236.226.247"
      4 "45.133.193.41"
      1 "45.148.104.164"
   8197 "86.5.206.121"
    253 "access-analyzer.amazonaws.com"
  11516 "cloudtrail.amazonaws.com"
   1414 "dynamodb.application-autoscaling.amazonaws.com"
    635 "resource-explorer-2.amazonaws.com"
    346 "X.X.X.X"
{% endhighlight %}

We can immediately remove the ones with a PTR record / DNS name, as it they seem to be a part of the Amazon services.

{% highlight bash %}
      1 "109.205.185.126"
      2 "138.199.59.46"
     13 "191.101.31.26"
     50 "191.101.31.57"
      6 "195.181.170.226"
      1 "3.236.115.9"
      1 "3.236.226.247"
      4 "45.133.193.41"
      1 "45.148.104.164"
{% endhighlight %}

Keep in mind that I'm particularly good at ending up in one-liner hell, and a better way would be to dump all the useful data into a new json file we could work on.

But, let's filter the events that has happened, based on the source IPs:

{% highlight bash %}
OpTinselTrace-2$ find . -name '*.json' -exec cat {} \; | jq '.Records[] | select( .sourceIPAddress as $a | ["109.205.185.126", "138.199.59.46", "191.101.31.26", "191.101.31.57", "195.181.170.226", "3.236.115.9", "3.236.226.247", "45.133.193.41", "45.148.104.164"] | index($a) ) | [.sourceIPAddress, .requestParameters.bucketName, .eventName] | @csv' | sort | uniq -c 2>/dev/null 
      1 "\"109.205.185.126\",\"papa-noel\",\"HeadBucket\""
      1 "\"138.199.59.46\",\"papa-noel\",\"GetBucketAcl\""
      1 "\"138.199.59.46\",\"papa-noel\",\"HeadBucket\""
      3 "\"191.101.31.26\",\"papa-noel\",\"GetBucketAcl\""
      2 "\"191.101.31.26\",\"papa-noel\",\"GetObject\""
      3 "\"191.101.31.26\",\"papa-noel\",\"HeadBucket\""
      5 "\"191.101.31.26\",\"papa-noel\",\"ListObjects\""
      2 "\"191.101.31.57\",\"north-pole-private\",\"GetBucketAcl\""
      4 "\"191.101.31.57\",\"north-pole-private\",\"HeadBucket\""
      1 "\"191.101.31.57\",\"north-pole-private\",\"ListObjects\""
     43 "\"191.101.31.57\",\"papa-noel\",\"GetObject\""
      2 "\"195.181.170.226\",\"papa-noel\",\"GetBucketAcl\""
      2 "\"195.181.170.226\",\"papa-noel\",\"HeadBucket\""
      2 "\"195.181.170.226\",\"papa-noel\",\"ListObjects\""
      1 "\"3.236.115.9\",\"papa-noel\",\"ListObjects\""
      1 "\"3.236.226.247\",\"papa-noel\",\"GetObject\""
      2 "\"45.133.193.41\",\"north-pole-private\",\"GetObject\""
      2 "\"45.133.193.41\",\"north-pole-private\",\"ListObjects\""
      1 "\"45.148.104.164\",\"papa-noel\",\"HeadBucket\""
{% endhighlight %}

This gives us a list of IP addresses, which buckets they have accessed and what events they made on those buckets. The TA is mentioned to be pulling data, which leads me to look at the GetObjects solely.

{% highlight bash %}
OpTinselTrace-2$ find . -name '*.json' -exec cat {} \; | jq '.Records[] | select( .sourceIPAddress as $a | ["109.205.185.126", "138.199.59.46", "191.101.31.26", "191.101.31.57", "195.181.170.226", "3.236.115.9", "3.236.226.247", "45.133.193.41", "45.148.104.164"] | index($a) ) | select(.eventName == "GetObject") | [.sourceIPAddress, .requestParameters.bucketName, .eventName] | @csv' | sort | uniq -c 2>/dev/null 
      2 "\"191.101.31.26\",\"papa-noel\",\"GetObject\""
     43 "\"191.101.31.57\",\"papa-noel\",\"GetObject\""
      1 "\"3.236.226.247\",\"papa-noel\",\"GetObject\""
      2 "\"45.133.193.41\",\"north-pole-private\",\"GetObject\""
{% endhighlight %}

Now we are at a point where we have 4 source IPs we can look at. There are two here that stands out: `191.101.31.57` and `45.133.193.41`. The first because it have made so many gets compared to the others, an the second one because of the access to the `north-pole-private` bucket. But let's check the one with the many hits out, intution tells me that this is the IP used by the TA to pull data.

{% highlight bash %}
OpTinselTrace-2$ find . -name '*.json' -exec cat {} \; | jq '.Records[] | select( .sourceIPAddress == "191.101.31.57" ) | select(.eventName == "GetObject") | [.eventTime, .sourceIPAddress, .userAgent, .requestParameters.key] | @csv'
"\"2023-11-29T08:24:07Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/description\""
"\"2023-11-29T08:24:07Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/COMMIT_EDITMSG\""
"\"2023-11-29T08:24:07Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/hooks/applypatch-msg.sample\""
"\"2023-11-29T08:24:07Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/HEAD\""
"\"2023-11-29T08:24:08Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/hooks/pre-applypatch.sample\""
"\"2023-11-29T08:24:07Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/config\""
"\"2023-11-29T08:24:08Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/hooks/fsmonitor-watchman.sample\""
"\"2023-11-29T08:24:09Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/hooks/pre-merge-commit.sample\""
"\"2023-11-29T08:24:09Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/hooks/pre-commit.sample\""
"\"2023-11-29T08:24:09Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/hooks/pre-push.sample\""
"\"2023-11-29T08:24:08Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/hooks/post-update.sample\""
"\"2023-11-29T08:24:09Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/hooks/pre-receive.sample\""
"\"2023-11-29T08:24:08Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/hooks/commit-msg.sample\""
"\"2023-11-29T08:24:09Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/hooks/pre-rebase.sample\""
"\"2023-11-29T08:24:10Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/hooks/prepare-commit-msg.sample\""
"\"2023-11-29T08:24:10Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/hooks/update.sample\""
"\"2023-11-29T08:24:11Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/logs/refs/heads/master\""
"\"2023-11-29T08:24:10Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/hooks/push-to-checkout.sample\""
"\"2023-11-29T08:24:12Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/objects/62/13ad5b238260339ce346bf8f9063a8559c538a\""
"\"2023-11-29T08:24:10Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/info/exclude\""
"\"2023-11-29T08:24:10Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/index\""
"\"2023-11-29T08:24:12Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/objects/69/a6bf0c5763a8cfc8d52d123e29986441869eab\""
"\"2023-11-29T08:24:11Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/logs/HEAD\""
"\"2023-11-29T08:24:11Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/objects/5d/24a8f411fc931b54fb9a4b58b6b55f1016c34d\""
"\"2023-11-29T08:24:11Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/objects/38/938fa8723c40cedfb7819340563c81961d7712\""
"\"2023-11-29T08:24:12Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/objects/6e/e67e3c147c7b310ea95271f07165056a84a1aa\""
"\"2023-11-29T08:24:12Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/objects/8f/3ebb72ee80ee21f35e64ff2040ffbfb8d78d90\""
"\"2023-11-29T08:24:13Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/objects/da/4d9a7c2824a50b8615b0149da53df83e812529\""
"\"2023-11-29T08:24:13Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/objects/d5/4035991ea077b39062f858dfab56ea4fc1eb32\""
"\"2023-11-29T08:24:13Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/objects/a9/2e975c8c52221d5c1c371d5595f65eb13f8be5\""
"\"2023-11-29T08:24:13Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/objects/99/9775de5661604d8b3e7b5929d1fd1818db40ac\""
"\"2023-11-29T08:24:13Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/objects/99/dbe4b3d52641ecb95dc3361bc7c324ba20f8e1\""
"\"2023-11-29T08:24:14Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/refs/heads/master\""
"\"2023-11-29T08:24:14Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/check.js\""
"\"2023-11-29T08:24:14Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/backup.py\""
"\"2023-11-29T08:24:14Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/objects/f1/3ae004942c081e8a345a35bc4c1a006fb9a9d6\""
"\"2023-11-29T08:24:14Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/.git/objects/ff/46564b94ef03aca8f76224d3286e7e608276e4\""
"\"2023-11-29T08:24:15Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/disk.ps\""
"\"2023-11-29T08:24:15Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/organise.rb\""
"\"2023-11-29T08:24:15Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/claus.py\""
"\"2023-11-29T08:24:16Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/update.sh\""
"\"2023-11-29T08:24:15Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"NPoleScripts/santa_journey_log.csv\""
"\"2023-11-29T08:24:16Z\",\"191.101.31.57\",\"[python-requests/2.25.1]\",\"santa-list.csv\""
{% endhighlight %}

We notice that they are pulling a git repository, with `python-requests/2.25.1`. Let's make a note of that IP address, as well as the information they have pulled. Git repositories can be a treasure trove of information, and so does the python and bash scripts.

In any case, the first file downloaded is the `description` files in the git repository.

| **Answer for #2** | `2023-11-29 08:24:07` |

### 3. What time did the Threat Actor complete their automated retrieval of the contents of our exposed S3 bucket?

The last file that was fetched within a short period of time, was `santa-list.csv`. It's fair to assume that this was the full automated scan, and any other data gatherings would be manual.

| **Answer for #3** | `2023-11-29 08:24:16` |

### 4. Based on the Threat Actor's user agent - what scripting language did the TA likely utilise to retrieve the files?

As we pulled the user agent, we know that the `requests` python library was used.

| **Answer for #4** | `python` |

### 5. Which file did the Threat Actor locate some hard coded credentials within?

For this we need to check some of the files that was fetched by the TA. If you remember, the `santa_deliveries` binary had a link to `https://papa-noel.s3.eu-west-3.amazonaws.com/santa-list.csv`. I wonder if we can fetch some of the files without authentication. 

{% highlight bash %}
kali$ curl https://papa-noel.s3.eu-west-3.amazonaws.com/NPoleScripts/backup.py
kali$ curl https://papa-noel.s3.eu-west-3.amazonaws.com/NPoleScripts/check.js
kali$ curl https://papa-noel.s3.eu-west-3.amazonaws.com/NPoleScripts/claus.py
kali$ curl https://papa-noel.s3.eu-west-3.amazonaws.com/NPoleScripts/disk.ps
kali$ curl https://papa-noel.s3.eu-west-3.amazonaws.com/NPoleScripts/organise.rb
kali$ curl https://papa-noel.s3.eu-west-3.amazonaws.com/NPoleScripts/update.sh

{% endhighlight %}

Well, that didn't yield any useful results (the scripts had data, but removed it as it was irrelevant), but let's try to grab the git repository - could be that someone made an oopsie.

{% highlight bash %}
OpTinselTrace-2$ find . -name '*.json' -exec cat {} \; | jq '.Records[] | select( .sourceIPAddress == "191.101.31.57" ) | select(.eventName == "GetObject") |  .requestParameters.key' | sed 's\^"\https://papa-noel.s3.eu-west-3.amazonaws.com/\g' | sed 's\"\\' | xargs -L1 wget -m

OpTinselTrace-2$ cd papa-noel.s3.eu-west-3.amazonaws.com/NPoleScripts                                                 
OpTinselTrace-2/papa-noel.s3.eu-west-3.amazonaws.com/NPoleScripts$ git log
commit a92e975c8c52221d5c1c371d5595f65eb13f8be5 (HEAD -> master)
Author: Author Name <bytesparkle@papanoel.co.uk>
Date:   Tue Nov 28 09:42:16 2023 +0000

    Removed the sparkly creds from the script! How silly of me! Sometimes I'm about as useful as a screen saver on Santa's Sleigh!!!!!!

commit 5d24a8f411fc931b54fb9a4b58b6b55f1016c34d
Author: Author Name <bytesparkle@papanoel.co.uk>
Date:   Tue Nov 28 09:15:34 2023 +0000

    First commit! Happy elf times all around. Christmas is SO close!
{% endhighlight %}

Well, look at that, `bytesparkle` made a commit message mentioning they removed some credentials. Let's check the change they did.

{% highlight diff %}
OpTinselTrace-2/papa-noel.s3.eu-west-3.amazonaws.com/NPoleScripts$ git diff a92e975c8c52221d5c1c371d5595f65eb13f8be5 5d24a8f411fc931b54fb9a4b58b6b55f1016c34d
diff --git a/claus.py b/claus.py
index 38938fa..6ee67e3 100644
--- a/claus.py
+++ b/claus.py
@@ -5,7 +5,9 @@ import csv
 import boto3
 from botocore.exceptions import NoCredentialsError, ClientError
 
-# Removed keys for safer method
+# AWS Credentials -  Should probably come up with a safer way to store these elf lolz!
+AWS_ACCESS_KEY = 'AKIA52GPOBQCBTZ6NJXM'
+AWS_SECRET_KEY = '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'
 BUCKET_NAME = 'north-pole-private'
 REGION_NAME = 'eu-west-2'
 
{% endhighlight %}

Now we know, `claus.py` used to have two variables `AWS_SECRET_KEY` and `AWS_ACCESS_KEY` which contained the secrets.

| **Answer for #5** | `claus.py` |

### 6. Please detail all confirmed malicious IP addresses. (Ascending Order)

So far, we have found one malicious IP address `191.101.31.57`, then we need to find the second one. If we go back to one our previous queries, and modify it a bit to contain the IPs which pulled data, that is not the first malicious IP.

{% highlight bash %}
find . -name '*.json' -exec cat {} \; | jq '.Records[] | select( .sourceIPAddress as $a | ["191.101.31.26", "3.236.226.247", "45.133.193.41"] | index($a) ) | select(.eventName == "GetObject") | [.sourceIPAddress, .requestParameters.bucketName, .eventName, .requestParameters.key] | @csv'  
"\"45.133.193.41\",\"north-pole-private\",\"GetObject\",\"bytesparkle.ovpn\""
"\"45.133.193.41\",\"north-pole-private\",\"GetObject\",\"santa_journey_log.csv\""
"\"3.236.226.247\",\"papa-noel\",\"GetObject\",\"favicon.ico\""
"\"191.101.31.26\",\"papa-noel\",\"GetObject\",\"favicon.ico\""
"\"191.101.31.26\",\"papa-noel\",\"GetObject\",\"NPoleScripts/update.sh\""
{% endhighlight %}

As mentioned earlier, I found the request to the `north-pole-private` was a bit off, combined with the next question we can assume that a request for the OpenVPN file can be considered malicious, which is done by `45.133.193.41`.

| **Answer for #6** | `45.133.193.41, 191.101.31.57` |

### 7. We are extremely concerned the TA managed to compromise our private S3 bucket, which contains an important VPN file. Please confirm the name of this VPN file and the time it was retrieved by the TA.

We kind of already answered this in the previous question, we just failed to print a timestamp. We could also answer this by search for VPN in the `requestParameter.key`.

{% highlight bash %}
OpTinselTrace-2$ find . -name '*.json' -exec cat {} \; | jq '.Records[] | select( .sourceIPAddress as $a | ["191.101.31.26", "3.236.226.247", "45.133.193.41"] | index($a) ) | select(.eventName == "GetObject") | [.eventTime, .sourceIPAddress, .requestParameters.bucketName, .eventName, .requestParameters.key] | @csv'  
"\"2023-11-29T10:16:53Z\",\"45.133.193.41\",\"north-pole-private\",\"GetObject\",\"bytesparkle.ovpn\""
{% endhighlight %}

| **Answer for #6** | `bytesparkle.ovpn, 2023-11-29 10:16:53` |

### 8. Please confirm the username of the compromised AWS account?
We can check the identity property of our output, perhaps for the download of the VPN file.

{% highlight bash %}
OpTinselTrace-2$ find . -name '*.json' -exec cat {} \; | jq '.Records[] | select( .sourceIPAddress as $a | ["191.101.31.57", "45.133.193.41"] | index($a) ) | select(.eventName == "GetObject") | [.eventTime, .sourceIPAddress, .requestParameters.bucketName, .eventName, .requestParameters.key, .userIdentity.userName] | @csv'  
"\"2023-11-29T10:16:53Z\",\"45.133.193.41\",\"north-pole-private\",\"GetObject\",\"bytesparkle.ovpn\",\"elfadmin\""
"\"2023-11-29T10:16:53Z\",\"45.133.193.41\",\"north-pole-private\",\"GetObject\",\"santa_journey_log.csv\",\"elfadmin\""

{% endhighlight %}

| **Answer for #8** | `elfadmin` |

### 9. Based on the analysis completed Santa Claus has asked for some advice. What is the ARN of the S3 Bucket that requires locking down?

As we know that the `north-pole-private` bucket was accessed with credentials, those secrets should just be rotated. So the suggestion should be for Santa to lock down the publicly available bucket we grabbed the git repository from.

{% highlight bash %}
OpTinselTrace-2$ find . -name '*.json' -exec cat {} \; | jq '.Records[] | select( .sourceIPAddress as $a | ["191.101.31.57"] | index($a) ) | select(.eventName == "GetObject") | [.eventTime, .sourceIPAddress, .requestParameters.bucketName, .resources[0].ARN] | @csv'  
"\"2023-11-29T08:24:07Z\",\"191.101.31.57\",\"papa-noel\",\"arn:aws:s3:::papa-noel/NPoleScripts/.git/description\""
"\"2023-11-29T08:24:07Z\",\"191.101.31.57\",\"papa-noel\",\"arn:aws:s3:::papa-noel/NPoleScripts/.git/COMMIT_EDITMSG\""
"\"2023-11-29T08:24:07Z\",\"191.101.31.57\",\"papa-noel\",\"arn:aws:s3:::papa-noel/NPoleScripts/.git/hooks/applypatch-msg.sample\""
"\"2023-11-29T08:24:07Z\",\"191.101.31.57\",\"papa-noel\",\"arn:aws:s3:::papa-noel/NPoleScripts/.git/HEAD\""
"\"2023-11-29T08:24:08Z\",\"191.101.31.57\",\"papa-noel\",\"arn:aws:s3:::papa-noel/NPoleScripts/.git/hooks/pre-applypatch.sample\""
"\"2023-11-29T08:24:07Z\",\"191.101.31.57\",\"papa-noel\",\"arn:aws:s3:::papa-noel/NPoleScripts/.git/config\""

{% endhighlight %}

| **Answer for #9** | `arn:aws:s3:::papa-noel` |

## Congratulations

You've have pwned OpTinselTrace-2