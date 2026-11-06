# Sherlock Scenario

Susan works at the Research Lab in Forela International Hospital. A Microsoft Defender alert was received from her computer, and she also mentioned that while extracting a document from the received file, she received tons of errors, but the document opened just fine. According to the latest threat intel feeds, WinRAR is being exploited in the wild to gain initial access into networks, and WinRAR is one of the Software programs the staff uses. You are a threat intelligence analyst with some background in DFIR. You have been provided a lightweight triage image to kick off the investigation while the SOC team sweeps the environment to find other attack indicators.

# Setup

For this case, HackTheBox provides us with a with a `romcom.zip` file, inside we found the `2025-09-02T083211_pathology_department_incidentalert.vhdx` which stands for `Microsoft Disk Image Extended .VHDX` is a file format that stores a virtual disk inside a file and is used by Hyper-V.

It got key features as:
- `Storage Capacity:` can support sizes up to `64TB`.
- `Data Protection:` includes features that protect against data corruption, especially during power failures.
- `File Type:` can contain partitions and file systems, similar to a physical hard drive.

Once we got the .VHDX file, we need to check if the availability of the disk under our system by listing with this command:

```bash
└─$ lsblk  
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS  
sda      8:0    0   50G  0 disk    
├─sda1   8:1    0 47.4G  0 part /  
├─sda2   8:2    0    1K  0 part    
└─sda5   8:5    0  2.6G  0 part [SWAP]  
sr0     11:0    1 1024M  0 rom
```

Its time to extract the virtual disk image using network block device module, `qemu-nbd`, but we didn't see any nbd disk inside of the lsblk command, so we need to check whether nbd block is loaded.

```bash
lsmod | grep nbd
```

No result is shown, so we need to load it with:

```bash
sudo modprobe nbd max_part=8 && lsmod | grep nbd
```

now we can see the nbd disk with "lsblk":

```bash
└─$ lsblk              
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS  
sda      8:0    0   50G  0 disk    
├─sda1   8:1    0 47.4G  0 part /  
├─sda2   8:2    0    1K  0 part    
└─sda5   8:5    0  2.6G  0 part [SWAP]  
sr0     11:0    1 1024M  0 rom     
nbd0    43:0    0    0B  0 disk    
nbd1    43:16   0    0B  0 disk    
nbd2    43:32   0    0B  0 disk    
nbd3    43:48   0    0B  0 disk    
nbd4    43:64   0    0B  0 disk    
nbd5    43:80   0    0B  0 disk    
nbd6    43:96   0    0B  0 disk    
nbd7    43:112  0    0B  0 disk    
nbd8    43:128  0    0B  0 disk    
nbd9    43:144  0    0B  0 disk    
nbd10   43:160  0    0B  0 disk    
nbd11   43:176  0    0B  0 disk    
nbd12   43:192  0    0B  0 disk    
nbd13   43:208  0    0B  0 disk    
nbd14   43:224  0    0B  0 disk    
nbd15   43:240  0    0B  0 disk
```


Finally, we are going to mount the evidence .vhdx file into nbd0:

```bash
sudo qemu-nbd --connect=/dev/nbd0 2025-09-02T083211_pathology_department_incidentalert.vhdx
```

If you don't get the command `qumu-nbd` on your system, you need to install `quemu-utils`

Now we see the partition under nbd0, named "nbd0p1":
```bash
└─$ lsblk  
NAME     MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS  
sda        8:0    0    50G  0 disk    
├─sda1     8:1    0  47.4G  0 part /  
├─sda2     8:2    0     1K  0 part    
└─sda5     8:5    0   2.6G  0 part [SWAP]  
sr0       11:0    1  1024M  0 rom     
nbd0      43:0    0   507M  0 disk    
└─nbd0p1  43:1    0 506.9M  0 part
```

So let's mount the data from nbd0p1 to `/mnt/romcom`:

```bash
└─$ sudo mkdir /mnt/romcom

└─$ sudo mount -o ro /dev/nbd0p1 /mnt/romcom
```

in this case I explain what the flags do, just in case:
- `o`: list of mount options
- `ro`: mount the filesystem read-only

Once this setup done, we can go to the `/mnt/romcom` directory to see the content of it.

# Investigation, questions & answers

For this part I'm going to cd into the directory and list its content:

```bash
cd /mnt/romcom && ls

└─$ ls      
2025-09-02T08_32_11_5202830_CopyLog.csv   C  'System Volume Information'
```

The content of `2025-09-02T08_32_11_5202830_CopyLog.csv` is:

![Image from CopyLog.csv](https://github.com/Gianluccani/Writeups/edit/main/HTB/sherlocks/RomCom/Pasted image 20261106081616.png)

This is a file which recorded the timestamp to fech the Data and Files. 
The `System Volume Information is the database file`, the most import part is the file inside `C`.

Now that explained, I'm going to answer the questions that this sherlock challenge provides us, in this case, there are some questions that are more about searching on the web that on the virtual disk itself.

1. What is the CVE assigned to the WinRAR vulnerability exploited by the RomCom threat group in 2025?
`Answers:` `CVE-2025-8088`, This is a heavy one, is a high-severity `path traversal vulnerability` in the Windows version of WinRAR that can allow attackers to write files outside the intended extraction folder and potentially lead to arbitrary code execution.

2. What is the nature of this vulnerability?
`Answers:` `Path Traversal`, Path traversal is a web security vulnerability that allows attackers to access files and directories outside the intended directories by manipulating variables that reference file paths.

3.  What is the name of the archive file under Susan's documents folder that exploits the vulnerability upon opening the archive file?
`Explanation:`  IMPORTANT IN THIS CASE IN LINUX WE NEED TO DOWNLOAD A NEW TOOL BECAUSE `MFTECmd` ISN'T AVAILABLE ON LINUX, for this time we download `analyzeMFT`.
First, setup a `python virtual environment(venv):`

```bash
python -m venv venv
source venv/bin/activate

# and now we install the tool!

pip install analyzeMFT
```

Now let's run the tool:

```bash
analyzemft -f /mnt/romcom/C/\$MFT -o mft_output.csv --csv
```

Now the output is going to be on a `.csv` format. The parser threw a few non-fatal validation warnings on corrupted/oversized attribute records but completed succesfully. There is a lot of information to go through, but we know that the `CVE` exploits `RAR` files, so lets filter for `.rar` entries:

```bash
grep -ia "\.rar" mft_output.csv
```

This is a ton of information that we need to go through so we add another grep for searching the date `2025-09`

Buried among unrelated Windows component filenames containing "rar" as a substring (like `..rarydialog.appxmain...`), two MFT records for the same file stood out: both dated 2025-09-02, matching the incident window.

```java
117118,Valid,In Use,File,2,117117,0,Pathology-Department-Research-Records.rar,,2025-09-02T08:13:41.753Z,2025-09-02T14:54:54.000Z,2025-09-02T08:13:50.534Z,2025-09-02T14:54:54.000Z,2025-09-02T08:13:50.440Z,2025-0  
9-02T08:13:50.440Z,2025-09-02T08:13:50.440Z,2025-09-02T08:13:50.440Z,,,,,True,False,True,False,False,True,False,False,False,False,False,False,False,[],None,,None,"{'name': '', 'non_resident': True, 'content_siz  
e': None, 'start_vcn': 0, 'last_vcn': 2135}",None,None,None,None,None,None,None,,,,  
117119,Valid,In Use,File,2,104964,0,Pathology-Department-Research-Records.rar,,2025-09-02T08:13:50.519Z,2025-09-02T14:54:54.000Z,2025-09-02T08:14:18.873Z,2025-09-02T08:14:04.980Z,2025-09-02T08:13:50.519Z,2025-0  
9-02T08:13:50.519Z,2025-09-02T08:13:50.519Z,2025-09-02T08:13:50.519Z,89cda794-87d3-11f0-b406-000c293ec6d8,00000080-0048-0000-0100-000000000100,00000000-0000-0005-5708-000000000000,00000040-0000-0000-0080-850000  
000000,True,False,True,False,False,True,False,False,False,False,False,False,False,[],None,,None,"{'name': '', 'non_resident': True, 'content_size': None, 'start_vcn': 1407374883553280, 'last_vcn': 2135}",None,N  
one,None,None,None,None,None,,,,
```

This is the records that I'm talking about.

**Answer**: `Pathology-Department-Research-Records.rar`.

4. When was the archive file created on the disk?
`Explanation:` For this I rely on the USN Journal, and this tool on github for the parsing of the file, that reads the raw USN record structure directly. [[https://github.com/PoorBillionaire/USN-Journal-Parser/blob/master/usnparser/usn.py]]
Using this command:
```python
└─$ python3 usn_parser.py -f /mnt/romcom/C/\$Extend/\$J -o output.txt

# Then filtering the output with grep...

└─$ cat output.txt | grep "Pathology-Department-Research-Records.rar"  
2025-09-02 08:13:50.440310 | Pathology-Department-Research-Records.rar | ARCHIVE | FILE_CREATE  
2025-09-02 08:13:50.440310 | Pathology-Department-Research-Records.rar | ARCHIVE | DATA_EXTEND FILE_CREATE  
2025-09-02 08:13:50.456015 | Pathology-Department-Research-Records.rar | ARCHIVE | DATA_EXTEND FILE_CREATE CLOSE  
2025-09-02 08:13:50.456015 | Pathology-Department-Research-Records.rar | ARCHIVE | BASIC_INFO_CHANGE  
2025-09-02 08:13:50.456015 | Pathology-Department-Research-Records.rar | ARCHIVE | BASIC_INFO_CHANGE CLOSE  
2025-09-02 08:13:50.519083 | Pathology-Department-Research-Records.rar | ARCHIVE | FILE_CREATE  
2025-09-02 08:13:50.519083 | Pathology-Department-Research-Records.rar | ARCHIVE | FILE_CREATE CLOSE  
2025-09-02 08:13:50.519083 | Pathology-Department-Research-Records.rar | ARCHIVE | DATA_EXTEND  
2025-09-02 08:13:50.519083 | Pathology-Department-Research-Records.rar | ARCHIVE | DATA_OVERWRITE DATA_EXTEND  
2025-09-02 08:13:50.534927 | Pathology-Department-Research-Records.rar | ARCHIVE | DATA_OVERWRITE DATA_EXTEND BASIC_INFO_CHANGE  
2025-09-02 08:13:50.534927 | Pathology-Department-Research-Records.rar | ARCHIVE | DATA_OVERWRITE DATA_EXTEND BASIC_INFO_CHANGE CLOSE  
2025-09-02 08:14:04.980743 | Pathology-Department-Research-Records.rar | ARCHIVE | OBJECT_ID_CHANGE  
2025-09-02 08:14:04.980743 | Pathology-Department-Research-Records.rar | ARCHIVE | OBJECT_ID_CHANGE CLOSE

```

**answer**: `2025-09-02 08:13:50`. 


5. When was the archive file opened?
`Answer`: `2025-09-02 08:14:04`, this was found from the output from above.

6. What is the name of the decoy document extracted from the archive file, meant to appear legitimate and distract the user?
`Explanation`: I first checked the USN Journal for any document-extension `FILE_CREATE` events in the same window as the archive's opening, but nothing showed up there — likely because WinRAR's internal Webview preview doesn't always generate the same journal footprint as a normal extraction. So I went back to the MFT and filtered broadly for common document extensions:
```bash
└─$ grep -iaE "\.(docx|doc|pdf|xlsx|xls|pptx)" mft_output.csv


117403,Valid,In Use,File,2,104964,0,Genotyping_Results_B57_Positive.pdf,,2025-09-02T08:14:18.793Z,2025-09-02T08:14:18.793Z,2025-09-02T08:15:05.406Z,2025-09-02T08:15:05.356Z,2025-09-02T08:14:18.793Z,2025-09-02T0  
8:14:18.793Z,2025-09-02T08:14:18.793Z,2025-09-02T08:14:18.793Z,89cda7c0-87d3-11f0-b406-000c293ec6d8,00000080-0048-0000-0100-000000000400,00000000-0000-0000-1600-000000000000,00000040-0000-0004-0070-010000000000  
,True,False,True,False,False,True,False,False,False,False,False,False,False,[],None,,None,"{'name': '', 'non_resident': True, 'content_size': None, 'start_vcn': 0, 'last_vcn': 22}",None,None,None,None,None,None  
,None,,,,
```

`Answer:`Genotyping_Results_B57_Positive.pdf

7. What is the name and path of the actual backdoor executable dropped by the archive file?
`Answer`: Since this CVE abuses Alternate Data Streams for path traversal, the exploit writes multiple files in the same burst as the decoy document — some inside the intended folder, some escaping it entirely. The USN Journal burst above (Task 6) already showed `ApbxHelper.exe` and a shortcut named `Display Settings.lnk` created within milliseconds of the decoy PDF. Neither name matches anything a legitimate WinRAR extraction should produce.

To find where `ApbxHelper.exe` actually landed, I looked up its parent record number in the MFT, then manually walked the parent-record chain one grep at a time — each record pointing to its own parent, until I reached the volume root:

```bash
grep -ia "ApbxHelper.exe" mft_output.csv | cut -d',' -f1-9
grep -a "^104988," mft_output.csv | cut -d',' -f1-9
grep -a "^104966," mft_output.csv | cut -d',' -f1-9
grep -a "^104955," mft_output.csv | cut -d',' -f1-9
grep -a "^2066," mft_output.csv | cut -d',' -f1-9
```

Combining the outputs we got the `answer`:

```powershell
C:\Users\Susan\Appdata\Local\ApbxHelper.exe
```

8. The exploit also drops a file to facilitate the persistence and execution of the backdoor. What is the path and name of this file?

`Answer`: The second file I'd spotted in the same ADS write burst, `Display Settings.lnk`, was the obvious candidate — a shortcut with an innocuous name is a common way to hide a persistence mechanism in plain sight. I resolved its full path the same way, walking the MFT parent chain:

```bash
└─$ grep -ia "Display Settings.lnk" mft_output.csv | cut -d',' -f1-9                
117404,Valid,In Use,File,2,115462,0,Display Settings.lnk,
```

followed by the same repeated parent lookups.

```bash
└─$ cat output.txt | awk -F'\t' '$1 >= "2025-09-02 08:14:18" && $1 <= "2025-09-02 08:14:25"'  
2025-09-02 08:14:18.793692 | Genotyping_Results_B57_Positive.pdf | ARCHIVE | FILE_CREATE  
2025-09-02 08:14:18.793692 | Genotyping_Results_B57_Positive.pdf | ARCHIVE | DATA_EXTEND FILE_CREATE  
2025-09-02 08:14:18.793692 | Genotyping_Results_B57_Positive.pdf | ARCHIVE | DATA_EXTEND FILE_CREATE CL  
OSE  
2025-09-02 08:14:18.856899 | Display Settings.lnk | ARCHIVE | FILE_CREATE  
2025-09-02 08:14:18.856899 | Display Settings.lnk | ARCHIVE | DATA_EXTEND FILE_CREATE  
2025-09-02 08:14:18.856899 | Display Settings.lnk | ARCHIVE | DATA_EXTEND FILE_CREATE CLOSE  
2025-09-02 08:14:18.856899 | ApbxHelper.exe | ARCHIVE | FILE_CREATE  
2025-09-02 08:14:18.873028 | ApbxHelper.exe | ARCHIVE | DATA_EXTEND FILE_CREATE  
2025-09-02 08:14:18.873028 | ApbxHelper.exe | ARCHIVE | DATA_EXTEND FILE_CREATE CLOSE  
2025-09-02 08:14:19.886515 | Windows.Data.Pdf.dll | ARCHIVE | CLOSE
```

This time the chain resolved as `Startup` → `Programs` → `Start Menu` → `Windows` → `Microsoft` → `Roaming` → `AppData` → `susan` → `Users` — landing squarely in the Windows Startup folder, which auto-executes anything placed there at every user login.

`Answer:` C:\Users\Susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Display Settings.lnk.

9. What is the associated MITRE Technique ID discussed in the previous question?
`Answer`:  `T1547.009`  .lnk is a modified shortcut file, uses to be a backdoor and appear for everytime startup.

https://attack.mitre.org/techniques/T1547/009/

10. When was the decoy document opened by the end user, thinking it to be a legitimate document?
`Answer & Explanation`: 2025-09-02 08:15:05, Using the same logic as Task 5, I searched the USN Journal for the decoy PDF's own Recent Items LNK file and its `FILE_CREATE` event:

```bash
└─$ cat output.txt |grep "Genotyping"  
2025-09-02 08:14:18.793692 | Genotyping_Results_B57_Positive.pdf | ARCHIVE | FILE_CREATE  
2025-09-02 08:14:18.793692 | Genotyping_Results_B57_Positive.pdf | ARCHIVE | DATA_EXTEND FILE_CREATE  
2025-09-02 08:14:18.793692 | Genotyping_Results_B57_Positive.pdf | ARCHIVE | DATA_EXTEND FILE_CREATE CL  
OSE  
2025-09-02 08:15:05.356670 | Genotyping_Results_B57_Positive.pdf | ARCHIVE | OBJECT_ID_CHANGE  
2025-09-02 08:15:05.356670 | Genotyping_Results_B57_Positive.pdf | ARCHIVE | OBJECT_ID_CHANGE CLOSE  
2025-09-02 08:15:05.612444 | Genotyping_Results_B57_Positive.lnk | ARCHIVE | FILE_CREATE  
2025-09-02 08:15:05.613440 | Genotyping_Results_B57_Positive.lnk | ARCHIVE | DATA_EXTEND FILE_CREATE  
2025-09-02 08:15:05.613440 | Genotyping_Results_B57_Positive.lnk | ARCHIVE | DATA_EXTEND FILE_CREATE CL  
OSE
```

`Genotyping_Results_B57_Positive.lnk` was created about 47 seconds after the PDF itself was extracted — the moment Susan actually opened the decoy, completing the deception described in the scenario.
