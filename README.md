# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/fousseyni-berthe/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for files containing the string “tor” and identified activity indicating that the user “employee” downloaded and interacted with the Tor Browser. A file named “tor-shopping-list.txt.txt” was observed on the desktop, with a creation at 2026-05-02T22:13:30.4563521Z. The related Tor activity began at 2026-05-02T22:08:29.5698282Z..

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "fouss-threathun"
| where InitiatingProcessAccountName =="employee"
| where Timestamp >= datetime(2026-05-02T22:08:29.5698282Z)
| where FileName contains "tor"
| project Timestamp, ActionType, DeviceName, FileName, FolderPath, Account = InitiatingProcessAccountName
| order by Timestamp desc
```
<img width="738" height="291" alt="image" src="https://github.com/user-attachments/assets/fc89abaf-ae89-45c0-b141-768e350c0dfb" />
---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any ProcessCommandLine that contained the string "tor-browser-windows-x86_64-portable-15.0.11". Based on the logs returned, at 2026-05-02T22:09:56.127332Z, an employee on the "fouss-threathun" device ran the file tor-browser-windows-x86_64-portable-15.0.11.exe from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "fouss-threathun"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.11"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256, ActionType
| order by Timestamp desc

```
<img width="906" height="79" alt="image" src="https://github.com/user-attachments/assets/30752ef6-708f-4460-a655-dee558b17beb" />
---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2026-05-02T22:10:32.1716218Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "fouss-threathun"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, FolderPath, SHA256, ActionType 
| order by Timestamp desc
```
<img width="874" height="415" alt="image" src="https://github.com/user-attachments/assets/087921f3-17f2-418d-9bff-53a0c01284bf" />
---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-05-02T22:10:39.4767681Z`, an employee on the "fouss-threathun" device successfully established a connection from the internal IP address `10.3.0.25 ` to the remote IP address `171.25.193.36 ` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "fouss-threathun"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9050", "9051", "9001", "9030", "9150", "80", "443")
| project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName, LocalIP, RemoteIP, RemotePort, InitiatingProcessFileName, RemoteUrl
| order by Timestamp desc

```
<img width="876" height="317" alt="image" src="https://github.com/user-attachments/assets/54bf926e-97ca-475d-a46d-b57641f16689" />
---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-05-02T22:08:29.5698282Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.11.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-15.0.11.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-05-02T22:09:56.127332Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-15.0.11.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.11.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-15.0.11.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-05-02T22:10:32.1716218Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-05-02T22:10:39.4767681Z`
- **Event:** A network connection to IP `171.25.193.36` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-05-02T22:11:01.341069Z` - Local connection to `127.0.0.1` on port `9150`.
  - `2026-05-02T22:11:37.3113391Z` - Connected to `45.58.190.74` on port `443`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-05-02T22:13:30.4563521Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt.txt`

---

## Summary

The user "employee" on the "fouss-threathun" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `fouss-threathun` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
