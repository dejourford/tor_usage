# Threat Hunt Report: Unauthorized TOR Usage
<div align=center>
<img src="images/hero.png" alt="hero image" width=1000/><br />
</div>

## Technology Utilized

* Windows 10 Virtual Machine (Microsoft Azure)

* Microsoft Defender for Endpoint

* Kusto Query Language (KQL)

* Tor Browser

<hr>


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

*Check `DeviceFileEvents` for any `tor(.exe)` or `firefox(.exe)` file events

*Check `DeviceProcessEvents` for any signs of installation or usage

*Check `DeviceNetworkEvents` for any signs of outgoing connections over known TOR ports 

## Steps Taken

1. Test

2. Test

3. Test


## Chronological Events

1. Test

2. Test

3. Test

## Summary



## Response

TOR usage was...

