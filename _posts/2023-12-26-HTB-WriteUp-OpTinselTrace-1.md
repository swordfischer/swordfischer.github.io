---
layout: post
title:  "Sherlocks - OpTinselTrace-1"
category: HTB
---
{% include htb_sherlock.html title="OpTinselTrace-1" difficulty="Easy" scenario="An elf named \"Elfin\" has been acting rather suspiciously lately. He's been working at odd hours and seems to be bypassing some of Santa's security protocols. Santa's network of intelligence elves has told Santa that the Grinch got a little bit too tipsy on egg nog and made mention of an insider elf! Santa is very busy with his naughty and nice list, so he’s put you in charge of figuring this one out. Please audit Elfin’s workstation and email communications."  %}

# Tasks
1. [What is the name of the email client that Elfin is using?](#1-what-is-the-name-of-the-email-client-that-elfin-is-using)
2. [What is the email the threat is using?](#2-what-is-the-email-the-threat-is-using)
3. [When does the threat actor reach out to Elfin?](#3-when-does-the-threat-actor-reach-out-to-elfin)
4. [What is the name of Elfins boss?](#4-what-is-the-name-of-elfins-boss)
5. [What is the title of the email in which Elfin first mentions his access to Santas special files?](#5-what-is-the-title-of-the-email-in-which-elfin-first-mentions-his-access-to-santas-special-files)
6. [The threat actor changes their name, what is the new name + the date of the first email Elfin receives with it?](#6-the-threat-actor-changes-their-name-what-is-the-new-name--the-date-of-the-first-email-elfin-receives-with-it)
7. [What is the name of the bar that Elfin offers to meet the threat actor at?](#7-what-is-the-name-of-the-bar-that-elfin-offers-to-meet-the-threat-actor-at)
8. [When does Elfin offer to send the secret files to the actor?](#8-when-does-elfin-offer-to-send-the-secret-files-to-the-actor)
9. [What is the search string for the first suspicious google search from Elfin? (Format: string)](#9-what-is-the-search-string-for-the-first-suspicious-google-search-from-elfin-format-string)
10. [What is the name of the author who wrote the article from the CIA field manual?](#10-what-is-the-name-of-the-author-who-wrote-the-article-from-the-cia-field-manual)
11. [What is the name of Santas secret file that Elfin sent to the actor?](#11-what-is-the-name-of-santas-secret-file-that-elfin-sent-to-the-actor)
12. [According to the filesystem, what is the exact CreationTime of the secret file on Elfins host?](#12-according-to-the-filesystem-what-is-the-exact-creationtime-of-the-secret-file-on-elfins-host)
13. [What is the full directory name that Elfin stored the file in?](#13-what-is-the-full-directory-name-that-elfin-stored-the-file-in)
14. [Which country is Elfin trying to flee to after he exfiltrates the file?](#14-which-country-is-elfin-trying-to-flee-to-after-he-exfiltrates-the-file)
15. [What is the email address of the apology letter the user (elfin) wrote out but didn’t send?](#15-what-is-the-email-address-of-the-apology-letter-the-user-elfin-wrote-out-but-didnt-send)
16. [The head elf PixelPeppermint has requested any passwords of Elfins to assist in the investigation down the line. What’s the windows password of Elfin’s host?](#16-the-head-elf-pixelpeppermint-has-requested-any-passwords-of-elfins-to-assist-in-the-investigation-down-the-line-whats-the-windows-password-of-elfins-host)

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

### 1. What is the name of the email client that Elfin is using?

There are plenty of ways to deduce this, but if we check the `C:\Users\` directory, we find a single user called `Elfin`. Most applications on Windows store their application data in the users `AppData` folder, in either the `Roaming` or `Local` folders (sometimes in both).

If we check the `C:\Users\Elfin\AppData\Roaming` directory we find a `eM Client` folder. A quick search online reveals [eM Client - The Best Email Client for Windows and Mac](https://www.emclient.com/).


While browsing the directory, we also stumble upon the `C:\Users\Elfin\AppData\Roaming\top-secret` directory, and likely related to the keywords we are looking for - this is very interesting, so lets make a note of that and come back to that later.

| **Answer for #1** | `eM Client` |

### 2. What is the email the threat is using?

In order to determine this, we have different approaches - either figuring out how the information is stored for `eM Client` or see if we can load up Elfins profile in our own `eM Client`.
If we copy the `C:\Users\Elfin\AppData\Roaming\eM Client` folder into our own `%AppData%\` directory, we can load up the client on a windows machine.
Another option would be viewing the SQLite databases stored in the `eM Client` folder with a SQLite tool such as [SQLiteViewer](https://sqliteviewer.app/).

Once done, we can open the application and head to Sent emails - this is likely where we will find communication between Elfin and the TA.

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_1.png)

Upon further inspection, we can find some mail correspondance with someone named "Grinch Grincher", which matches our keywords and our scenario. They are using a very subtle email address.

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_2.png)

| **Answer for #2** | `definitelynotthegrinch@gmail.com` |

### 3. When does the threat actor reach out to Elfin?

We need to determine when the first contact from the Grinch is done to Elfin, so if we drill down the dialogue we saw before we can find what looks like the first message.
At least it seems like an initial dialogue, coming from the Grinch posing as Wendy.

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_3.png)

Keep in mind that timestamps are always submitted as UTC, and your operating system may have an offset - in this case, it does not.

| **Answer for #3** | `2023-11-27 17:27:26` |

### 4. What is the name of Elfins boss?

If we look at the conversation occuring after the first conversation with the Grinch, we find a message with Elfin talking with someone he refers to as "boss".

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_4.png)

| **Answer for #4** | `elfuttin bigelf` |

### 5. What is the title of the email in which Elfin first mentions his access to Santas special files?

Let's search the email client for something `special`. Seems like there is some dialogue with the subject "work". 

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_5.png)

But we might need to check if the client removes information such as replies, forwards and what not. Alt-click and select properties shows us the following:

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_6.png)

| **Answer for #5** | `Re: work` |

### 6. The threat actor changes their name, what is the new name + the date of the first email Elfin receives with it?

If we search the client for the email used by the TA, we can see the dialogues in the message pane. It then seems like we have a change in display name between two different conversations.

If we view it, we also see that Elfin notices the name change.

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_7.png)

| **Answer for #6** | `wendy elflower, 2023-11-28 10:00:21` |

### 7. What is the name of the bar that Elfin offers to meet the threat actor at?

Viewing the same conversation, we can see a reference to a bar.

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_8.png)

| **Answer for #7** | `SnowGlobe` |

### 8. When does Elfin offer to send the secret files to the actor?

We've kept our search query, and can look a bit at the other dialogue - some of the last dialogue contains a message from Elfin suggesting to send some of the special files to the TA. However, the timestamps are missing the seconds - we can use Alt-Click and View Message Source to show the full timestamp.

Timezones are never a fun thing - but we are only missing the seconds to get our answer.

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_9.png)

| **Answer for #8** | `2023-11-28 16:56:13` |

### 9. What is the search string for the first suspicious google search from Elfin? (Format: string)

Now we need to answer a question that is outside the scope of the email client. As mentioned earlier, applications store information in the AppData directories and from that we can guess the used browser. Searching the `C:\Users\Elfin\AppData\Local` directory, we see there is a `Google` folder. Again, there are other ways to determine this, such as information from the LiveResponse output.

If we copy the `C:\Users\Elfin\AppData\Local\Google` folder into our own `%LocalAppData%\` directory, we can load up Google Chrome on a windows machine.
Another option would be viewing the SQLite databases stored in the `Google` folder with a SQLite tool such as [SQLiteViewer](https://sqliteviewer.app/).

Chrome has a neat little about page for searches called `chrome://history/`. If we scroll down a bit we find a change of heart from our dear Elfin.

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_10.png)

| **Answer for #9** | `how to get around work security` | 

### 10. What is the name of the author who wrote the article from the CIA field manual?

Let's check the history in Chrome again, there is a history item for the CIA field manual:

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_11.png)

We'll open the link
![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_12.png)

| **Answer for #10** | `Joost Minnaar` |

### 11. What is the name of Santas secret file that Elfin sent to the actor?

We already made note of the `top-secret` directory in #1, this is one place to look - or we can check the email client for attached files:
![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_13.png)

or 

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_14.png)

Either way

| **Answer for #11** | `santa_deliveries.zip` |

### 12. According to the filesystem, what is the exact CreationTime of the secret file on Elfins host?

Now we can pull some information from the master file table or the `$MFT`. This is a file that keeps track of files on the NTFS filesystem, and we can view that with a tool like [MFTExplorer or MFTCmd](https://ericzimmerman.github.io/#!index.md) from Eric Zimmerman.

MFTExplorer can take some time to load up depending on the size of the `$MFT`, and MFTCmd can dump a list of files into a csv we can view.

{% highlight powershell %}
PS > & MFTECmd.exe -f "$MFT" --csv MFT
MFTECmd version 1.2.2.1

.. TRUNCATED ...

\elfidence_collection\TriageData\C\$MFT: FILE records found: 343.607 (Free records: 193) File size: 335,8MB
Path to MFT doesn't exist. Creating...
        CSV output will be saved to MFT\20231226203702_MFTECmd_$MFT_Output.csv
{% endhighlight %}

Once we have the CSV created, we can read the creation time of the file.

{% highlight powershell %}
PS > Import-Csv -Path MFT\20231226203702_MFTECmd_`$MFT_Output.csv | ? { $_.FileName -eq 'santa_deliveries.zip'}

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

| **Answer for #12** | `2023-11-28 17:01:29` |

### 13. What is the full directory name that Elfin stored the file in?

We have already found the files in #12 and #13, so there is no need to make this complicated.

| **Answer for #13** | `C:\users\Elfin\Appdata\Roaming\top-secret` |

### 14. Which country is Elfin trying to flee to after he exfiltrates the file?

It would seem obvious if Elfin were searching for some travel destinations in Chrome, so let's head back to the `chrome://history` tab once again.

In here, we see some searches that would relate to Elfins travel plans

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_15.png)

| **Answer for #14** | `Greece` |

### 15. What is the email address of the apology letter the user (elfin) wrote out but didn’t send?

Once again we head back into the email client, and look for something that is written but not sent - most likely drafts.

![eM Client](/img/htb/sherlock/optinseltrace-1/emclient_16.png)

| **Answer for #15** | `Santa.claus@gmail.com` |

### 16. The head elf PixelPeppermint has requested any passwords of Elfins to assist in the investigation down the line. What’s the windows password of Elfin’s host?

With the standard triage done, we also receive the SYSTEM and SAM registry hives in our `elfidence_collection` directory, they are stored in the `C:\Windows\system32\config` path.
We can use [Mimikatz](https://github.com/ParrotSec/mimikatz) to extract the users NTLM hash, so we can crack it with [HashCat](https://hashcat.net/hashcat/).

{% highlight bash %}
mimikatz # lsadump::sam /system:".\elfidence_collection\TriageData\C\Windows\system32\config\SYSTEM" /sam:".\elfidence_collection\TriageData\C\Windows\system32\config\SAM"

... TRUNCATED ...

RID  : 000003e9 (1001)
User : Elfin
  Hash NTLM: 529848fe56902d9595be4a608f9fbe89

... TRUNCATED ...

mimikatz #
{% endhighlight %}

Let us save the hash to a file and have it processed with HashCat.

{% highlight powershell %}
.\hashcat.exe -m 1000 elfin_ntlm.txt rockyou.txt
hashcat (v6.2.5) starting

... TRUNCATED ...

529848fe56902d9595be4a608f9fbe89:Santaknowskungfu

... TRUNCATED ....
{% endhighlight %}

| **Answer for #5** | `Santaknowskungfu` |

## Congratulations

You've have pwned OpTinselTrace-1