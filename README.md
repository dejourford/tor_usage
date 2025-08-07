# Threat Hunt Report: Unauthorized TOR Usage
<div align=center>
<img src="images/hero.png" alt="hero image" width=1000/><br />
</div>

## Technology Utilized

* Windows 10 Virtual Machine (Microsoft Azure)

* Microsoft Defender for Endpoint

* Kusto Query Language (KQL)

* Tor Browser


---

## MDE Tables Referenced:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---



## Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect anyTOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

## High-Level TOR related IoC (Indicators of Compromise) Disocvery Plan:

* Check `DeviceFileEvents` for any `tor(.exe)` or `firefox(.exe)` file events

* Check `DeviceProcessEvents` for any signs of installation or usage

* Check `DeviceNetworkEvents` for any signs of outgoing connections over known TOR ports 

## Steps Taken





Step 1) Searched `DeviceFileEvents` 

Searched the DeviceFileEvents table for ANY file that had the string "tor" in it and discovered the user "a-dford" downloaded a tor installer, renamed it, and then did something that resulted in other tor-related files to be created on the desktop. The user then deleted the downloaded tor installer and created a file named "tor_shopping_list.txt". These events began at: 2025-08-07T04:05:30.6764524Z. The SHA256 of the downloaded installer is: `6d38a13c6a5865b373ef1e1ffcd31b3f359abe896571d27fa666ce71c486a40d`.
```
DeviceFileEvents
| where DeviceName == "deej-ford"
| where InitiatingProcessAccountName == "a-dford"
| where Timestamp >= datetime(2025-08-07T04:05:30.6764524Z)
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<hr>


Step 2) Searched `DeviceProcessEvents`

Searched the DeviceProcessEvents table for ANY command line process that contained the downloaded tor installer "tor-browser-windows-x86_64-portable-14.5.5.5.exe" but no result were returned. Since the file was renamed, I searched for any command line process with the matching SHA256, and an entry with the file name of "file.exe" was populated. It shows that the user executed the "file.exe" with the `/S` argument to trigger a silent install.

```
DeviceProcessEvents
| where DeviceName == "deej-ford"
| where InitiatingProcessAccountName == "a-dford"
| where Timestamp >= datetime(2025-08-07T04:05:30.6764524Z)
| where SHA256 == "6d38a13c6a5865b373ef1e1ffcd31b3f359abe896571d27fa666ce71c486a40d"
```
<hr>

Step 3) Searched `DeviceNetworkEvents`

Searched the DeviceNetworkEvents table for InitiatingProcessFileNames of "tor.exe" or "firefox.exe" to check for TOR browser usage and results populated confirming TOR browser usage. At 2025-08-07T04:25:49.7262415Z, user "a-dford" on the device "deej-ford", used tor.exe to establish connection to several URLs over ports 443 and 9001.

```
DeviceNetworkEvents
| where DeviceName == "deej-ford"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemoteUrl != ""
| project Timestamp, InitiatingProcessAccountName, DeviceName, InitiatingProcessFileName, RemotePort, RemoteUrl
| order by Timestamp desc
```

<hr>


## Chronological Events

1. Test

2. Test

3. Test

## Summary



## Response

TOR usage was...

