---
layout: post
date: 2023-12-26
platform: "HTB"
title:  "OpTinselTrace-1"
difficulty: "Easy"
scenario: "An elf named \"Elfin\" has been acting rather suspiciously lately. He's been working at odd hours and seems to be bypassing some of Santa's security protocols. Santa's network of intelligence elves has told Santa that the Grinch got a little bit too tipsy on egg nog and made mention of an insider elf! Santa is very busy with his naughty and nice list, so he’s put you in charge of figuring this one out. Please audit Elfin’s workstation and email communications."
question_1: "What is the name of the email client that Elfin is using?"
question_2: "What is the email the threat is using?"
question_3: "When does the threat actor reach out to Elfin?"
question_4: "What is the name of Elfins boss?"
question_5: "What is the title of the email in which Elfin first mentions his access to Santas special files?"
question_6: "The threat actor changes their name, what is the new name + the date of the first email Elfin receives with it?"
question_7: "What is the name of the bar that Elfin offers to meet the threat actor at?"
question_8: "When does Elfin offer to send the secret files to the actor?"
question_9: "What is the search string for the first suspicious google search from Elfin? (Format: string)"
question_10: "What is the name of the author who wrote the article from the CIA field manual?"
question_11: "What is the name of Santas secret file that Elfin sent to the actor?"
question_12: "According to the filesystem, what is the exact CreationTime of the secret file on Elfins host?"
question_13: "What is the full directory name that Elfin stored the file in?"
question_14: "Which country is Elfin trying to flee to after he exfiltrates the file?"
question_15: "What is the email address of the apology letter the user (elfin) wrote out but didn’t send?"
question_16: "The head elf PixelPeppermint has requested any passwords of Elfins to assist in the investigation down the line. What’s the windows password of Elfin’s host?"
---
{% include scenario.html %}

# Questions

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
11. [{{ page.question_11}}](#question-11)
12. [{{ page.question_12}}](#question-12)
13. [{{ page.question_13}}](#question-13)
14. [{{ page.question_14}}](#question-14)
15. [{{ page.question_15}}](#question-15)
16. [{{ page.question_16}}](#question-16)

# Discussion
We have read the scenario, and the tasks we are looking to answer. There are some points of information that we can pull from this, that can assist us in our further analysis.
- The insider threat may be Elfin
- Some of the information is stored in emails
- A threat actor, maybe the Grinch, has communicated with our insider threat
- The insider threat has access to valuable information that needs to be exfiltrated

Some of the keywords here are "Elfin", "Grinch", "Santa", "Special" or "Secret", "Bar" and "Country".

It may not be all the relevant information that we can deduce, but limiting the information that we look for is crucial when sifting through mountains of data.

# Answering the tasks
First, we need to grab the `optinseltrace1.zip` file, and unzip it, then extract the `elfidence_collection.7z` which contains two folders named `LiveResponse` and `TriageData`.
The `TriageData` is a dump of usually important files from the `C:` drive, and the `LiveResponse` contains various sources of volatile information when the live response was requested. Such as running processes and caches.

## Question 1
{% include item.html type="question" id="1" question=page.question_1 %}

There are plenty of ways to deduce this, but if we check the `C:\Users\` directory, we find a single user called `Elfin`. Most applications on Windows store their application data in the users `AppData` folder, in either the `Roaming` or `Local` folders (sometimes in both).

If we check the `C:\Users\Elfin\AppData\Roaming` directory we find a `eM Client` folder. A quick search online reveals [eM Client - The Best Email Client for Windows and Mac](https://www.emclient.com/).


While browsing the directory, we also stumble upon the `C:\Users\Elfin\AppData\Roaming\top-secret` directory, and likely related to the keywords we are looking for - this is very interesting, so lets make a note of that and come back to that later.

{% include item.html type="answer" id="1" description=page.question_1 answer="eM Client" %}

## Question 2
{% include item.html type="question" id="2" question=page.question_2 %}

In order to determine this, we have different approaches - either figuring out how the information is stored for `eM Client` or see if we can load up Elfins profile in our own `eM Client`.
If we copy the `C:\Users\Elfin\AppData\Roaming\eM Client` folder into our own `%AppData%\` directory, we can load up the client on a windows machine.
Another option would be viewing the SQLite databases stored in the `eM Client` folder with a SQLite tool such as [SQLiteViewer](https://sqliteviewer.app/).

Once done, we can open the application and head to Sent emails - this is likely where we will find communication between Elfin and the TA.

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_1.png)

Upon further inspection, we can find some mail correspondance with someone named "Grinch Grincher", which matches our keywords and our scenario. They are using a very subtle email address.

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_2.png)

{% include item.html type="answer" id="2" description=page.question_2 answer="definitelynotthegrinch@gmail.com" %}

## Question 3
{% include item.html type="question" id="3" question=page.question_3 %}

We need to determine when the first contact from the Grinch is done to Elfin, so if we drill down the dialogue we saw before we can find what looks like the first message.
At least it seems like an initial dialogue, coming from the Grinch posing as Wendy.

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_3.png)

Keep in mind that timestamps are always submitted as UTC, and your operating system may have an offset - in this case, it does not.

{% include item.html type="answer" id="3" description=page.question_3 answer="2023-11-27 17:27:26" %}

## Question 4
{% include item.html type="question" id="4" question=page.question_4 %}

If we look at the conversation occuring after the first conversation with the Grinch, we find a message with Elfin talking with someone he refers to as "boss".

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_4.png)

{% include item.html type="answer" id="4" description=page.question_4 answer="elfuttin bigelf" %}

## Question 5
{% include item.html type="question" id="5" question=page.question_5 %}

Let's search the email client for something `special`. Seems like there is some dialogue with the subject "work". 

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_5.png)

But we might need to check if the client removes information such as replies, forwards and what not. Alt-click and select properties shows us the following:

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_6.png)

{% include item.html type="answer" id="5" description=page.question_5 answer="Re: work" %}

## Question 6
{% include item.html type="question" id="6" question=page.question_6 %}

If we search the client for the email used by the TA, we can see the dialogues in the message pane. It then seems like we have a change in display name between two different conversations.

If we view it, we also see that Elfin notices the name change.

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_7.png)

{% include item.html type="answer" id="6" description=page.question_6 answer="wendy elflower, 2023-11-28 10:00:21" %}

## Question 7
{% include item.html type="question" id="7" question=page.question_7 %}

Viewing the same conversation, we can see a reference to a bar.

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_8.png)

{% include item.html type="answer" id="7" description=page.question_7 answer="SnowGlobe" %}

## Question 8
{% include item.html type="question" id="8" question=page.question_8 %}

We've kept our search query, and can look a bit at the other dialogue - some of the last dialogue contains a message from Elfin suggesting to send some of the special files to the TA. However, the timestamps are missing the seconds - we can use Alt-Click and View Message Source to show the full timestamp.

Timezones are never a fun thing - but we are only missing the seconds to get our answer.

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_9.png)

{% include item.html type="answer" id="8" description=page.question_8 answer="2023-11-28 16:56:13" %}

## Question 9
{% include item.html type="question" id="9" question=page.question_9 %}

Now we need to answer a question that is outside the scope of the email client. As mentioned earlier, applications store information in the AppData directories and from that we can guess the used browser. Searching the `C:\Users\Elfin\AppData\Local` directory, we see there is a `Google` folder. Again, there are other ways to determine this, such as information from the LiveResponse output.

If we copy the `C:\Users\Elfin\AppData\Local\Google` folder into our own `%LocalAppData%\` directory, we can load up Google Chrome on a windows machine.
Another option would be viewing the SQLite databases stored in the `Google` folder with a SQLite tool such as [SQLiteViewer](https://sqliteviewer.app/).

Chrome has a neat little about page for searches called `chrome://history/`. If we scroll down a bit we find a change of heart from our dear Elfin.

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_10.png)

{% include item.html type="answer" id="9" description=page.question_9 answer="how to get around work security" %}

## Question 10
{% include item.html type="question" id="10" question=page.question_10 %}

Let's check the history in Chrome again, there is a history item for the CIA field manual:

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_11.png)

We'll open the link
![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_12.png)

{% include item.html type="answer" id="10" description=page.question_10 answer="Joost Minnaar" %}

## Question 11
{% include item.html type="question" id="11" question=page.question_11 %}

We already made note of the `top-secret` directory in #1, this is one place to look - or we can check the email client for attached files:
![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_13.png)

or 

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_14.png)

Either way

{% include item.html type="answer" id="11" description=page.question_11 answer="santa_deliveries.zip" %}

## Question 12
{% include item.html type="question" id="12" question=page.question_12 %}

Now we can pull some information from the master file table or the `$MFT`. This is a file that keeps track of files on the NTFS filesystem, and we can view that with a tool like [MFTExplorer or MFTCmd](https://ericzimmerman.github.io/#!index.md) from Eric Zimmerman.

MFTExplorer can take some time to load up depending on the size of the `$MFT`, and MFTCmd can dump a list of files into a csv we can view.

{% highlight powershell %}
MFTECmd.exe -f "$MFT" --csv MFT
MFTECmd version 1.2.2.1

.. TRUNCATED ...

\elfidence_collection\TriageData\C\$MFT: FILE records found: 343.607 (Free records: 193) File size: 335,8MB
Path to MFT doesn't exist. Creating...
        CSV output will be saved to MFT\20231226203702_MFTECmd_$MFT_Output.csv
{% endhighlight %}

Once we have the CSV created, we can read the creation time of the file.

{% highlight powershell %}
Import-Csv -Path MFT\20231226203702_MFTECmd_`$MFT_Output.csv | ? { $_.FileName -eq 'santa_deliveries.zip'}

... TRUNCATED ...

ParentPath            : .\Users\Elfin\AppData\Roaming\top-secret
FileName              : santa_deliveries.zip
Extension             : .zip
FileSize              : 12767

... TRUNCATED ...

Created0x10           : 2023-11-28 17.01.29.2753913
Created0x30           :
LastModified0x10      : 2023-11-28 17.01.29.2753913
LastModified0x30      :
LastRecordChange0x10  : 2023-11-28 17.01.30.4785440
LastRecordChange0x30  : 2023-11-28 17.01.29.2910585
LastAccess0x10        : 2023-11-28 17.01.41.9645954
LastAccess0x30        : 2023-11-28 17.01.29.2753913

... TRUNCATED ...

{% endhighlight %}

The timestamp mentioned in `Created0x10` is the creation time we are looking for according to [Kroll](https://www.kroll.com/en/insights/publications/cyber/anti-forensic-tactics/detecting-analyzing-timestomping-with-kape)

{% include item.html type="answer" id="12" description=page.question_12 answer="2023-11-28 17:01:29" %}

## Question 13
{% include item.html type="question" id="13" question=page.question_13 %}

We have already found the files in #12 and #13, so there is no need to make this complicated.

{% include item.html type="answer" id="13" description=page.question_13 answer="C:\users\Elfin\Appdata\Roaming\top-secret" %}

## Question 14
{% include item.html type="question" id="14" question=page.question_14 %}

It would seem obvious if Elfin were searching for some travel destinations in Chrome, so let's head back to the `chrome://history` tab once again.

In here, we see some searches that would relate to Elfins travel plans

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_15.png)

{% include item.html type="answer" id="14" description=page.question_14 answer="Greece" %}

## Question 15
{% include item.html type="question" id="15" question=page.question_15 %}

Once again we head back into the email client, and look for something that is written but not sent - most likely drafts.

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_16.png)

{% include item.html type="answer" id="15" description=page.question_15 answer="Santa.claus@gmail.com" %}

## Question 16
{% include item.html type="question" id="16" question=page.question_16 %}

With the standard triage done, we also receive the SYSTEM and SAM registry hives in our `elfidence_collection` directory, they are stored in the `C:\Windows\system32\config` path.

We can use [Mimikatz](https://github.com/ParrotSec/mimikatz) to extract the users NTLM hash or use `impacket-secretsdump`. Then we can crack it with [HashCat](https://hashcat.net/hashcat/).

#### Impacket

{% highlight bash %}
impacket-secretsdump -system SYSTEM -sam SAM LOCAL

[*] Target system bootKey: 0x1679d0a0bee2b5804325deeddb0ec9fe
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:95199bba413194e567908de6220d677e:::
Elfin:1001:aad3b435b51404eeaad3b435b51404ee:529848fe56902d9595be4a608f9fbe89:::
[*] Cleaning up...

{% endhighlight %}

#### Mimikatz

{% highlight bash %}
mimikatz # lsadump::sam /system:".C\Windows\system32\config\SYSTEM" /sam:".\C\Windows\system32\config\SAM"

... TRUNCATED ...

RID  : 000003e9 (1001)
User : Elfin
  Hash NTLM: 529848fe56902d9595be4a608f9fbe89

... TRUNCATED ...

mimikatz #
{% endhighlight %}

Once we have the hash, we can check the hash against a service, or crack it ourselves.
___
#### Quick Solution

We can utilize [ntlm.pw](https://ntlm.pw) to check the NTLM
{% highlight bash %}
curl https://ntlm.pw/529848fe56902d9595be4a608f9fbe89
Santaknowskungfu
{% endhighlight %}

If ntlm.pw does not know the hash, we can attempt to crack it ourselves.

____
#### Slow Solution

Save the hash to a file and have it processed with HashCat.

{% highlight powershell %}
.\hashcat.exe -m 1000 elfin_ntlm.txt rockyou.txt
hashcat (v6.2.5) starting

... TRUNCATED ...

529848fe56902d9595be4a608f9fbe89:Santaknowskungfu

... TRUNCATED ....
{% endhighlight %}

{% include item.html type="answer" id="16" description=page.question_16 answer="Santaknowskungfu" %}