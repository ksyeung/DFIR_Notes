| Sysmon Event ID  | Name/Tag                                | Description                                                                                                                                             | Source                                      |
|------|-----------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------|
| 1    | Process Create                          | Provides process GUID, terminal session ID, process integrity level, current directory, parent-child relationship, hashes, and detailed command line args. | Microsoft-Windows-Sysmon/Operational        |
| 2    | File creation time                      |                                                                                                                                                         | Microsoft-Windows-Sysmon/Operational        |
| 3    | Network connection detected             | Provides detailed network connection information, including source and destination IPs, initiation status, process path (image), ports, and protocols.    | Microsoft-Windows-Sysmon/Operational        |
| 4    | Sysmon service state change             | Cannot be filtered                                                                                                                                      | Microsoft-Windows-Sysmon/Operational        |
| 5    | Process terminated                      |                                                                                                                                                         | Microsoft-Windows-Sysmon/Operational        |
| 6    | Driver Loaded                           | Provides driver name, image loaded path, and detailed signature information.                                                                             | Microsoft-Windows-Sysmon/Operational        |
| 7    | Image loaded                            | Captures DLL load events with detailed information, including image path, process ID, signature information, and hashes.                                  | Microsoft-Windows-Sysmon/Operational        |
| 8    | CreateRemoteThread detected             | Records thread creation in remote processes with source and target thread details, including process and thread IDs, and start address.                   | Microsoft-Windows-Sysmon/Operational        |
| 9    | RawAccessRead detected                  |                                                                                                                                                         | Microsoft-Windows-Sysmon/Operational        |
| 10   | Process accessed                        | Captures process handle operations with detailed information about source and target processes, call trace, and granted access rights.                    | Microsoft-Windows-Sysmon/Operational        |
| 11   | File created                            | Logs file creation events with process path (image), process ID, and target filenames.                                                                    | Microsoft-Windows-Sysmon/Operational        |
| 12   | Registry object added or deleted        | Provides registry key creation and deletion events with detailed information about affected keys and values.                                              | Microsoft-Windows-Sysmon/Operational        |
| 13   | Registry value set                      | Provides registry value changes with detailed information about affected keys and values.                                                                 | Microsoft-Windows-Sysmon/Operational        |
| 14   | Registry object renamed                 | Logs file stream creation events with process path (image), hashes, and associated target file information.                                               | Microsoft-Windows-Sysmon/Operational        |
| 15   | File stream created                     |                                                                                                                                                         | Microsoft-Windows-Sysmon/Operational        |
| 16   | Sysmon configuration change             | Cannot be filtered                                                                                                                                      | Microsoft-Windows-Sysmon/Operational        |
| 17   | Named pipe created                      | Captures named pipe creation events with process path (image), pipe name, execution process ID, and process ID.                                           | Microsoft-Windows-Sysmon/Operational        |
| 18   | Named pipe connected                    | Logs named pipe connection events with detailed information about process path (image), pipe name, connection status, and process ID.                     | Microsoft-Windows-Sysmon/Operational        |
| 19   | WMI filter                              |                                                                                                                                                         | Microsoft-Windows-Sysmon/Operational        |
| 20   | WMI consumer                            |                                                                                                                                                         | Microsoft-Windows-Sysmon/Operational        |
| 21   | WMI consumer filter                     |                                                                                                                                                         | Microsoft-Windows-Sysmon/Operational        |
| 22   | DNS query                               | Logs DNS query events with process path (image), process ID, query type, and queried domain.                                                             | Microsoft-Windows-Sysmon/Operational        |
| 23   | File Delete archived                    |                                                                                                                                                         | Microsoft-Windows-Sysmon/Operational        |
| 24   | New content in the clipboard            |                                                                                                                                                         | Microsoft-Windows-Sysmon/Operational        |
| 25   | Process image change                    |                                                                                                                                                         | Microsoft-Windows-Sysmon/Operational        |
| 26   | File Delete logged                      |                                                                                                                                                         | Microsoft-Windows-Sysmon/Operational        |
| 27   | File Block Executable                   |                                                                                                                                                         | Microsoft-Windows-Sysmon/Operational        |
| 28   | File Block Shredding                    |                                                                                                                                                         | Microsoft-Windows-Sysmon/Operational        |
| 29   | File Executable Detected                |                                                                                                                                                         | Microsoft-Windows-Sysmon/Operational        |


| Event ID | Event                                                                                                                                    | Event Log                                     |
|----------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| 1102     | The audit log (security) was cleared.                                                                                                     | Security                                     |
| 4624     | Successful logon event                                                                                                                    | Security                                     |
| 4625     | Unsuccessful logon event                                                                                                                  | Security                                     |
| 4627     | Shows documentation of the user's group membership at the time of logon                                                                   | Security                                     |
| 4634     | Account session terminated (logged off, or closed RDP session by clicking corner X).                                                      | Security                                     |
| 4647     | User initiated logoff. All 4647 events have a corresponding 4634, but not all 4634 will have a corresponding 4647 because a session can be terminated without logoff. | Security                                     |
| 4648     | Logon was attempted with explicit credentials.                                                                                            | Security                                     |
| 4656     | Handle Manipulation: 1st event in the “Accessing an object” chain. Logged when an attempt is made regardless of success/failure.           | Security                                     |
| 4657     | A registry value was modified.                                                                                                            | Security                                     |
| 4658     | Handle Manipulation: Logged when closing the handle to the object (when access ends).                                                     | Security                                     |
| 4660     | Logged when an object is deleted.                                                                                                         | Security                                     |
| 4662     | Directory Service Access: An operation was performed on an object.                                                                        | Security                                     |
| 4663     | Logged when the access attempt (4656) is successful.                                                                                      | Security                                     |
| 4670     | Permissions on an object were changed.                                                                                                    | Security                                     |
| 4672     | Special privileges assigned to new logon.                                                                                                 | Security                                     |
| 4673     | A privileged service was called.                                                                                                          | Security                                     |
| 4674     | An operation was attempted on a privileged object.                                                                                        | Security                                     |
| 4688     | Process creation tracking, with command line information and executable path.                                                             | Security                                     |
| 4689     | Process exit termination (if event enabled).                                                                                              | Security                                     |
| 4690     | Handle Manipulation: An attempt was made to duplicate a handle to an object.                                                              | Security                                     |
| 4696     | A primary token was assigned to process.                                                                                                  | Security                                     |
| 4697     | Generated when a service is installed.                                                                                                    | Security                                     |
| 4698     | A scheduled task was created (if audited).                                                                                                | Security                                     |
| 4699     | A scheduled task was deleted.                                                                                                             | Security                                     |
| 4700     | Scheduled task was enabled.                                                                                                               | Security                                     |
| 4718     | The Windows Filtering Platform has detected a DoS attack.                                                                                 | Security                                     |
| 4720     | A user account was created.                                                                                                               | Security                                     |
| 4722     | A user account was enabled.                                                                                                               | Security                                     |
| 4724     | An attempt was made to reset an account's password.                                                                                       | Security                                     |
| 4726     | User acct deleted.                                                                                                                        | Security                                     |
| 4728     | Member added to a security-enabled global group.                                                                                          | Security                                     |
| 4732     | Member added to a security-enabled local group.                                                                                           | Security                                     |
| 4768     | A Kerberos authentication ticket (TGT) was requested.                                                                                     | Security                                     |
| 4769     | A Kerberos service ticket was requested.                                                                                                  | Security                                     |
| 4770     | A Kerberos service ticket was renewed.                                                                                                    | Security                                     |
| 4771     | Kerberos pre-auth failed.                                                                                                                 | Security                                     |
| 4772     | A Kerberos authentication ticket request failed.                                                                                          | Security                                     |
| 4773     | A Kerberos service ticket request failed.                                                                                                 | Security                                     |
| 4774     | An account was mapped for logon.                                                                                                          | Security                                     |
| 4775     | An account could not be mapped for logon.                                                                                                 | Security                                     |
| 4776     | The domain controller attempted to validate the credentials for an account.                                                               | Security                                     |
| 4777     | The domain controller failed to validate the credentials.                                                                                 | Security                                     |
| 4778     | RDP session reconnected.                                                                                                                  | Security                                     |
| 4779     | RDP session disconnected.                                                                                                                 | Security                                     |
| 4798     | A user's local group membership was enumerated.                                                                                           | Security                                     |
| 4799     | A security-enabled local group membership was enumerated.                                                                                 | Security                                     |
| 4820     | A kerberos ticket granting ticket was denied.                                                                                             | Security                                     |
| 4821     | A Kerberos service ticket was denied because the user, device, or both does not meet the access control restrictions.                      | Security                                     |
| 4822     | NTLM authentication failed because the account was a member of the Protected User group.                                                  | Security                                     |
| 4823     | NTLM authentication failed because access control restrictions are required.                                                              | Security                                     |
| 4824     | Kerberos pre-auth using DES or RC4 failed because the account was a member of the Protected User group.                                    | Security                                     |
| 4876     | Certificate Services backup started.                                                                                                      | Security                                     |
| 4877     | Certificate Services backup completed.                                                                                                    | Security                                     |
| 4886     | Certificate Services received a certificate request.                                                                                      | Security                                     |
| 4887     | Certificate Services approved a certificate request.                                                                                      | Security                                     |
| 4896     | Certificate Services loaded a template.                                                                                                   | Security                                     |
| 4899     | A Certificate Services template was updated.                                                                                              | Security                                     |
| 4900     | Certificate Services template security was updated.                                                                                       | Security                                     |
| 5039     | A registry key was virtualised.                                                                                                           | Security                                     |
| 5136     | Directory Service Changes: a directory service object was modified.                                                                       | Security                                     |
| 5137     | Directory Service Changes: a directory service object was created.                                                                        | Security                                     |
| 5138     | Directory Service Changes: A directory service object was undeleted.                                                                      | Security                                     |
| 5139     | Directory Service Changes: A directory service object was moved.                                                                          | Security                                     |
| 5140     | File Share: A network share object was accessed.                                                                                           | Security                                     |
| 5141     | Directory Service Changes: a directory service object was deleted.                                                                        | Security                                     |
| 5142     | File Share: A network share object was added.                                                                                             | Security                                     |
| 5143     | File Share: A network share object was modified.                                                                                          | Security                                     |
| 5144     | File Share: A network share object was deleted.                                                                                           | Security                                     |
| 5145     | Detailed File Share: A network share object was checked to see whether client can be granted desired access to individual files.           | Security                                     |
| 5168     | File Share: SPN check for SMB/SMB2 failed.                                                                                                | Security                                     |
| 5169     | Directory Service Access: A directory service object was modified.                                                                        | Security                                     |
| 5712     | A Remote Procedure Call was attempted.                                                                                                    | Security                                     |
| 5889     | The DoS attack has subsided and normal processing is resumed.                                                                             | Security                                     |
| 5888     | An object in the COM+ Catalog was modified.                                                                                               | Security                                     |
| 5889     | An object was deleted from the COM+ Catalog.                                                                                              | Security                                     |
| 5890     | An object was added to the COM+ Catalog.                                                                                                  | Security                                     |
| 41       | Kernel power error.                                                                                                                       | System                                       |
| 104      | The log file was cleared (Will show System, Application, and other non-Security logs cleared).                                             | System                                       |
| 1074     | Shutdown type (power off, shutdown, restart).                                                                                             | System                                       |
| 6005     | Event log service start (can be used for startup time).                                                                                    | System                                       |
| 6006     | Event log service stop (shutdown time).                                                                                                   | System                                       |
| 6008     | Unexpected shutdown (e.g. hardware failure).                                                                                              | System                                       |
| 7009     | A timeout was reached (x milliseconds) while waiting for the y service to connect.                                                        | System                                       |
| 7034     | When a service crashes (from e.g. process injection).                                                                                     | System                                       |
| 7035     | Generated when the OS sends a start/stop signal to the service. Includes the service name and path of the executable that runs the service. | System                                       |
| 7036     | Generated when a service is actually started/stopped.                                                                                     | System                                       |
| 7040     | When a service's start type is changed (e.g. auto, manual, automatic-delayed, disabled).                                                   | System                                       |
| 7045     | A new service was installed in the system.                                                                                                | System                                       |
| 8001     | Successful connection to a wireless network.                                                                                              | System                                       |
| 8003     | Successful disconnect from a wireless network.                                                                                            | System                                       |
| 20001    | Created each time a new device is connected to the system.                                                                                 | System                                       |
| 100      | Task Scheduler started the x instance of the y task for user z.                                                                            | Microsoft-Windows-TaskScheduler/Operational  |
| 102      | Task Scheduler successfully finished the x instance of the y task for user z.                                                              | Microsoft-Windows-TaskScheduler/Operational  |
| 106      | The user x registered the Task Scheduler task y.                                                                                           | Microsoft-Windows-TaskScheduler/Operational  |
| 140      | Scheduled task updated.                                                                                                                   | Microsoft-Windows-TaskScheduler/Operational  |
| 141      | User x deleted Task Scheduler task y.                                                                                                      | Microsoft-Windows-TaskScheduler/Operational  |
| 200, 201 | Scheduled task executed/completed.                                                                                                        | Microsoft-Windows-TaskScheduler/Operational  |
| 1116     | The antimalware platform detected malware or other potentially unwanted software.                                                          | Microsoft-Windows-Windows Defender/Operational |
| 1117     | The antimalware platform performed an action to protect your system from malware or other potentially unwanted software.                    | Microsoft-Windows-Windows Defender/Operational |
| 1118     | Remediation Action Failed: Defender attempted and failed to take action on a detected threat.                                              | Microsoft-Windows-Windows Defender/Operational |
| 1119     | Remediation Failure: Defender failed to remediate the detected threat. Provides information about the threat, attempted action, and cause of failure​ | Microsoft-Windows-Windows Defender/Operational |
| 21       | Remote Desktop Services: Session logon succeeded.                                                                                         | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational |
| 22       | Remote Desktop Services: Shell start notification received.                                                                                | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational |
| 23       | Remote Desktop Services: Session logoff succeeded.                                                                                         | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational |
| 24       | Remote Desktop Services: Session has been disconnected.                                                                                    | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational |
| 25       | Remote Desktop Services: Session reconnection succeeded.                                                                                   | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational |
| 41       | Logon username.                                                                                                                            | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational |
| 261      | Listener RDP-Tcp received a connection.                                                                                                    | Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational |
| 1149     | Remote Desktop Services: User authentication succeeded, includes source IP address and logon username.                                      | Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational |
| 1024     | Outbound RDP connection attempts, includes username, destination hostname, and IP address, even if a session doesn't complete connection.   | Microsoft-Windows-TerminalServices-RDPClient/Operational |
| 1029     | Base64(SHA256(Username)) is = HASH.                                                                                                        | Microsoft-Windows-TerminalServices-RDPClient/Operational |
| 1102     | Outbound RDP connection attempts, includes username, destination hostname, and IP address, even if a session doesn't complete connection.   | Microsoft-Windows-TerminalServices-RDPClient/Operational |
| 98       | Successful RDP connections.                                                                                                                | Microsoft-Windows-RemoteDesktopServices-RdpCoreTS |
| 131      | Indicates an RDP connection was attempted, usually includes the client's IP address, server hostname or IP address, user credentials.       | Microsoft-Windows-RemoteDesktopServices-RdpCoreTS |
| 5857     | Indicates time of wmiprvse.exe exec and path to provider DLLs.                                                                              | Microsoft-Windows-WMI-Activity/Operational |
| 5858     | Records query errors, includes hostname (labeled ClientMachine) and username.                                                              | Microsoft-Windows-WMI-Activity/Operational |
| 5859     | Registration of temporary event consumers, typically used for persistence but can be used for remote execution.                            | Microsoft-Windows-WMI-Activity/Operational |
| 5860     | WMI event filter registered, includes the WMI namespace, notification query, the owner of the query, PID of the process that registered.    | Microsoft-Windows-WMI-Activity/Operational |
| 5861     | Registration of permanent event consumers, includes full consumer info.                                                                    | Microsoft-Windows-WMI-Activity/Operational |
| 6        | WSMan session init (session created, destination hostname or IP, current logged-on username).                                               | Microsoft-Windows-WinRM/Operational |
| 8,15,16,33 | WSMan session de-init (closing of WSMan session, current logged-on username).                                                             | Microsoft-Windows-WinRM/Operational |
| 91       | Session creation.                                                                                                                          | Microsoft-Windows-WinRM/Operational |
| 168      | Records the authenticating user.                                                                                                           | Microsoft-Windows-WinRM/Operational |
| 4103     | Module logging and pipeline output.                                                                                                         | Microsoft-Windows-PowerShell/Operational |
| 4104     | Records PowerShell execution with Script Block logging.                                                                                     | Microsoft-Windows-PowerShell/Operational |
| 4105     | Script start.                                                                                                                               | Microsoft-Windows-PowerShell/Operational |
| 4106     | Script stop.                                                                                                                                | Microsoft-Windows-PowerShell/Operational |
| 8193     | Session created.                                                                                                                            | Microsoft-Windows-PowerShell/Operational |
| 8194     | Session created.                                                                                                                            | Microsoft-Windows-PowerShell/Operational |
| 8197     | Connect (session closed).                                                                                                                   | Microsoft-Windows-PowerShell/Operational |
| 40691    | Records the local init of powershell.exe and associated user account.                                                                       | Microsoft-Windows-PowerShell/Operational |
| 40692    | Records the local init of powershell.exe and associated user account.                                                                       | Microsoft-Windows-PowerShell/Operational |
| 53504    | Records the authenticating user.                                                                                                            | Microsoft-Windows-PowerShell/Operational |
| 400/403  | "ServerRemoteHost" indicates start/end of Remoting session. Part of older PS log.                                                           | Windows PowerShell.evtx                    |
| 600      | Indicates that providers like WSMan start to perform a PS activity.                                                                         | Windows PowerShell.evtx                    |
| 800      | Includes partial script code.                                                                                                               | Windows PowerShell.evtx                    |
| 1000     | Application error.                                                                                                                          | Application                                |
| 1001     | This can occur when applications crash, installations fail, or other critical errors happen.                                                | Application                                |
| 1002     | Application hang.                                                                                                                           | Application                                |
| 1033     | Generated when an application is installed or uninstalled.                                                                                  | Application                                |
| 1034     | Windows Installer removed an application.                                                                                                   | Application                                |
| 11707    | Windows Installer installed an application.                                                                                                 | Application                                |
| 11708    | Windows Installer product installation failed.                                                                                              | Application                                |
| 11724    | Generated when an application is uninstalled.                                                                                               | Application                                |
| 300      | Captures alerts generated by Microsoft Office during user interaction.                                                                      | OAlerts.evtx                               |


| Logon Type | Description                                 |
|------------|---------------------------------------------|
| 2          | Console                                     |
| 3          | Network (e.g. file share)                   |
| 4          | Batch (Scheduled Tasks)                     |
| 5          | Windows Services                            |
| 7          | Screen Lock/Unlock                          |
| 8          | Network (Cleartext Logon)                   |
| 9          | Alternate Credentials Specified (RunAs)     |
| 10         | Remote Interactive (RDP)                    |
| 11         | Cached Credentials (e.g. Offline DC)        |
| 12         | Cached Remote Interactive (RDP, similar to Type 10) |
| 13         | Cached Unlock (Similar to Type 7)           |
