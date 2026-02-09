# Oracle — Under The Wire (Walk-through)

**Published:** 2025-08-14


Walk through of the wargame Oracle at underthewire.tech

## Oracle1:

> The password for oracle2 is the timezone in which this system is set to.

For this level, we use the utility `Get-TimeZone`

![Image](https://miro.medium.com/v2/resize:fit:1050/1*qrJ_rfs869dQvAgaif-C8A.png)

## Oracle2:

> The password for oracle3 is the last five digits of the MD5 hash, from the hashes of files on the desktop that appears twice.

For this, we need to compute the hash of all the files and then group them by hashes.

Command for this:

```powershell
(Get-ChildItem . | Get-FileHash -Algorithm MD5 ).Hash| Group-Object
```


Explanation:

*   `Get-ChildItem .` → Lists all items (files & folders) in the current directory.
*   `|` **(pipe)** → Passes the items to the next command.
*   `Get-FileHash -Algorithm MD5` → Calculates the MD5 hash for each file.
*   `.Hash` → Extracts only the `Hash` property from the hash objects.
*   `| Group-Object` → Groups identical hash values together to find duplicates.

Extract the last five digits, when you enter them, make sure they are in lowercase

## Oracle3:

> The password for oracle4 is the date that the system logs were last wiped as depicted in the event logs on the desktop.

For this level, we can use the utility `Get-WinEvent`

`Get-WinEvent` is a powershell utility to view `.evtx`files

```powershell
Get-WinEvent -Path .\Oracle3_Security.evtx
```

![Image](https://miro.medium.com/v2/resize:fit:1050/1*b9PL7XjOtQxZtWpuFiSOXw.png)

At the end of the eventlog file, we see the time that the audit log was last cleared.

## Oracle4:

> The password for oracle5 is the name of the GPO that was last created **PLUS** the name of the file on the user’s desktop.

GPO stands for Group Policies. For this level we will use the Utility `Get-GPO`

Command:

```powershell
Get-GPO -All | Sort CreationTime
```

This returns the list of all GPO’s set and then pipes them to the Sort utility which sorts them by CreationTime.

The DisplayName attribute shows the name, which combined with the **file in the user’s desktop** is the password for the next level.

## Oracle5:

> The password for oracle6 is the name of the GPO that contains a description of “I\_AM\_GROOT” **PLUS** the name of the file on the user’s desktop.

Command:

```powershell
Get-GPO -All | Where-Object {$_.Description -eq "I_AM_GROOT"}
```

![Image](https://miro.medium.com/v2/resize:fit:1050/1*zjrSihDVybCTCx1gbMHIBw.png)

Combine the name of the GPO with the name of the file in desktop directory, thats the password.

## Oracle6:

> The password for oracle7 is the name of the OU that doesn’t have a GPO linked to it **PLUS** the name of the file on the user’s desktop.

Command used:

```powershell
Get-ADOrganizationalUnit -Filter * -Property LinkedGroupPolicyObjects | Where-Object {-not $_.LinkedGroupPolicyObjects}

```
![Image](https://miro.medium.com/v2/resize:fit:1050/1*WK-47wmkDpCJLtjHbx-Z-w.png)

Explanation of command:

*   `Get-ADOrganizationalUnit -Filter * -Property LinkedGroupPolicyObjects` → Gets all OUs and includes the `LinkedGroupPolicyObjects` property.
*   `|` **(pipe)** → Sends the OU objects to the next command.
*   `Where-Object { -not $_.LinkedGroupPolicyObjects }` → Filters only OUs with no linked Group Policy Objects (null or empty property).

Combine the OU name with the file in the Desktop directory, thats the password for the next level.

## Oracle7:

> The password for oracle8 is the name of the domain that a trust is built with **PLUS** the name of the file on the user’s desktop.

For this, we can use the utility: `Get-ADTrust` . This command shows the trusted domains.

```powershell
Get-ADTrust -Filter *| Select-Object Name
```

![Image](https://miro.medium.com/v2/resize:fit:1050/1*euJjexxV0IHmU9A9CWR-CQ.png)

Explanation:

*   `Get-ADTrust -Filter *` → Retrieves all Active Directory trust relationships for the current domain.
*   `|` **(pipe)** → Passes the trust objects to the next command.
*   `Select-Object Name` → Displays only the `Name` property (trusted domain name).

Combine the name with the name of the file in Desktop dir.

## Oracle8:

> The password for oracle9 is the name of the file in the GET Request from [www.guardian.galaxy.com](http://www.guardian.galaxy.com) within the log file on the desktop.

For this, we can use the `findstr` utility in powershell.


Searching for the whole domain didn’t work, but searching `guardian` worked.

![Image](https://miro.medium.com/v2/resize:fit:1050/1*h12Ys2BWQQlAcH4ItR1NYg.png)

## Oracle9:

> The password for oracle10 is the computer name of the DNS record of the mail server listed in the UnderTheWire.tech zone **PLUS** the name of the file on the user’s desktop

`Get-DnsServerResouceRecord` utility in powershell Gets resource records from a specified DNS zone.

We use it to find the hostname of the DNS record of the email server listed in the UnderTheWire.tech zone.

![Image](https://miro.medium.com/v2/resize:fit:1050/1*nwUCZuZJlMuSk3J9N4nXQw.png)

Explanation Of command:

*   `Get-DnsServerResourceRecord -ZoneName "underthewire.tech"` → Retrieves all DNS records from the zone `underthewire.tech`.
*   `|` → Pipes the results to the next command.
*   `Where-Object { … }` → Filters the records based on a condition.
*   `**$_.RecordType -eq "MX"**` → Keeps only records where the `RecordType` equals `"MX"` (mail exchange records).

Append the name of the file in the Desktop dir to the hostname found in order to find the password.

## Oracle10:

> The password for oracle11 is the .biz site the user has previously navigated to.

We query the registry for this information.

```powershell
Get-ItemProperty 'HKCU:\Software\Microsoft\Internet Explorer\TypedURLs'
```

![Image](https://miro.medium.com/v2/resize:fit:1050/1*Fnd4QM-EMemHLQK5aNZalg.png)

## Oracle11:

> The password for oracle12 is the drive letter associated with the mapped drive that this user has.

**HKCU/Network:** This subkey stores details of **mapped network drives** for that specific user.

```powershell
Get-ChildItem HKCU:\Network
```

This gives the name of the drive, which is the password for the next level.

## Oracle12:

> The password for oracle13 is the IP of the system that this user has previously established a remote desktop with.

The information related to initiated remote connections is stored in `‘HKCU:\SOFTWARE\Microsoft\Terminal Server Client’`

![Image](https://miro.medium.com/v2/resize:fit:1050/1*5nmLoabk7nS67y_O28cv-w.png)

## Oracle13:

> The password for oracle14 is the name of the user who created the Galaxy security group as depicted in the event logs on the desktop **PLUS** the name of the text file on the user’s desktop.

When a security group is made in AD, the event is logged on the **Domain Controller** in the **Security** log as:

*   **Event ID:** **4727**

Working with this information, we can filter for events that match this ID.

![Image](https://miro.medium.com/v2/resize:fit:1050/1*gxJdBVdlhEdWZPKXk_uk7Q.png)

Explanation:

*   `Get-WinEvent -Path .\security.evtx` → Opens and reads the specified Event Log file (`security.evtx`).
*   `| Where-Object {$_.Id -eq 4727}` → Filters events so only those with Event ID **4727** (security-enabled global group created) are selected.
*   `.Message` → Displays only the **Message** field of each matching event.

Append the name of the text file in the user’s Desktop to the name of the user found. That is the password for the next level.

## Oracle14:

> The password for oracle15 is the name of the user who added the user Bereet to the Galaxy security group as depicted in the event logs on the desktop **PLUS** the name of the text file on the user’s desktop.

The Event ID for a user added to a security group is 4732 when the group is a local group, and 4728 when it’s a global group.

Checked for both and found the answer with `4728`

![Image](https://miro.medium.com/v2/resize:fit:1050/1*e2ZQYkZd84jzFufbkFDQFw.png)

Combine this with the name of the file in the user’s directory.

## Oracle15:

![Image](https://miro.medium.com/v2/resize:fit:1050/1*GJNqpBsEZveKhC26TvO7gg.png)