Interesting registry locations:

| Keys Most Accessed in Open Source Credential Theft Tools |
|----------------------------------------------------------|
| HKLM\SOFTWARE\RealVNC\WinVNC4                            |
| HKCU\Software\SimonTatham\PuTTY\Sessions                 |
| HKCU\Software\ORL\WinVNC3\Password                       |
| HKLM\SYSTEM\CurrentControlSet\Services\SNMP              |
| HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer       |
| HKLM\SYSTEM\CurrentControlSet\Services\SNMP              |
| HKCU\Software\TightVNC\Server                            |
| HKCU\Software\OpenSSH\Agent\Keys                         |
| HKLM\SYSTEM\CurrentControlSet\Control\LSA                |
| HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\wDigest\UseLogonCredential |
| HKLM\SOFTWARE\RealVNC\vncserver                          |
| HKLM\SOFTWARE\RealVNC\WinVNC4\Password                   |
| HKLM\SOFTWARE\RealVNC                                    |
| HKCU\Software\PremiumSoft\Navicat\Servers                |
| HKLM\SYSTEM                                              |
| HKLM\SAM                                                 |
| HKCU\Software\PremiumSoft\NavicatMONGODB\Servers         |
| HKCU\Software\PremiumSoft\NavicatMSSQL\Servers           |
| HKCU\Software\PremiumSoft\NavicatPG\Servers              |
| HKCU\Software\PremiumSoft\NavicatSQLite\Servers          |
| HKCU\Software\PremiumSoft\NavicatMARIADB\Servers         |
| HKCU\Software\PremiumSoft\NavicatOra\Servers             |
| HKLM\Software\TigerVNC\WinVNC4                           |


| Registry Location | Notes |
|--------------------|-------|
| HKLM\SYSTEM\CurrentControlSet\Services\EventLog\ | Registry path for this default location |
| HKLM, HKEY_USERS | SAM, SECURITY, SOFTWARE, SYSTEM, and DEFAULT hives on a live system |
| SOFTWARE\Microsoft\Windows NT\CurrentVersion | OS version, service pack, build number, release ID, installation type, installation date |
| System\ControlSet001\Services\Tcpip\Parameters\Hostname | Host name |
| System\ControlSet001\Control\ComputerName\ComputerName | Computer name |
| System\Select\Current | Indicates which ControlSet is in use |
| System\ControlSet001\Control\TimeZoneInformation\Bias | Difference between set local time and UTC in minutes, stored as 32b unsigned (RegExplorer can decode with Data Interpreter) |
| System\ControlSet001\Control\TimeZoneInformation\TimeZoneKeyName | TZ name of the local system |
| “Last Write Time” field in the registry | Available only through export or with RegExplorer |
| System\ControlSet001\Control\Windows\ShutdownTime | Last shutdown time (encoded with Windows FILETIME timestamp, use Data Interpreter to decode) |
| HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power\Fast Startup\HiberbootEnabled | Fast Startup (enabled: 1) |
| SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards | Physical network cards connected to the system, organized by subkey. Each card is assigned a unique number, with associated GUID and adapter name. |
| SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces | List of available interfaces (physical or virtual). Subkeys are named after GUIDs of physical network cards |
| SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{4D36E968-E325-11CE-BFC1-08002BE10318} | Example interface. Interesting keys: “EnableDHCP” (enabled: 1, indicates DHCP-assigned IP), “DhcpIPAddress” contains IP issued by DHCP server if assigned, “LeaseObtainedTime” shows when the DHCP IP address was assigned, “DhcpNetworkHint” is a unique identifier (presented in hex) for each wireless network SSID, used to streamline connection to a previously accessed wireless network |
| SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged | Network Location Awareness: subkeys each represent a connection signature (record). The “ProfileGuid” value contains the GUID associated with a connection. “Description” describes the network, “FirstNetwork” is the SSID, “DefaultGatewayMac” contains WAP MAC address. |
| SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles | Contains subkeys (profiles), one for each connection. “ProfileName”, “Description”, “DateCreated” (first time system connected to this network, encoded, can decode with RegExplorer), “NameType” indicates connection type (0x47 wireless, 0x6 wired, 0x17 broadband) |
| SYSTEM >Applications and Services > Microsoft > Windows > WLAN-AutoConfig | |
| SYSTEM\ControlSet001\Services\LanmanServer\Shares | Shared folders, Value “Users”, data “CATimeout”, “CSCFlags”, “MaxUses”, “Path”, “Permissions”, “Remark”, “ShareName”, “Type” |
| [root]\$Extend\$UsnJrnl, [root]\$MFT, [root]\$LogFile, [root]\$I30 | $UsnJrnl file location, stores data for days on a busy system |
| SOFTWARE\Microsoft\Office\15.0\<Office App>\[File\|Place] MRU | MSOffice MRU list |
| SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\* | Windows shell dialog box MRU list |
| Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs | Explorer files MRU |
| Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\ | Entries executed with “run” dialog MRU |
| Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths | Entries manually typed in Windows Explorer location bar |
| HKLM\SYSTEM\ControlSet001\Enum\USB | Subkeys for each USB device named after the device's vendor ID (VID) and product ID (PID) |
| HKLM\SYSTEM\ControlSet001\Enum\USBSTOR | Stores information about USB data drives |
| HKLM\SYSTEM\ControlSet001\Enum\SWD\WPDBUSENUM | Similar information to HKLM\..\[USB\|USBSTOR] plus FriendlyName |
| HKLM\SYSTEM\ControlSet001\Control\DeviceClasses | Has a trace for any connected device, not only USB. Includes printers, Firewire, Bluetooth, and webcams |
| HKLM\SYSTEM\MountedDevices | Contains the assigned letter and volume GUID for each connected device |
| SOFTWARE\Microsoft\Windows Portable Devices\Devices | |
| SOFTWARE\Microsoft\Windows Search\VolumeInfoCache | |
| Amcache: Root\InventoryDevicePnp | |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2 | Includes a list of used device GUIDs from a user perspective |
| Microsoft\Windows Search\VolumeInfoCache | Volume GUID, volume letter, serial number |
| HKLM\SYSTEM\Select | Has the currently loaded ControlSet under the key value "current" |
| SOFTWARE\Microsoft\Windows\CurrentVersion\Run SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce | AutoRuns locations |
| NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist | UserAssist, which stores info about programs frequently run by a specific user, the last time they were run, and how many times. |
| HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache | AppCompatCache/ShimCache allows older apps to run on newer systems. If supported, stored here. |
| ControlSet001\Services\bam\State\UserSettings | Background Activity Monitor information, provides info about executables that've been run, last execution datetime, full path. Subkeys named after user SID under which the app runs. |
| HKLM\SYSTEM\CurrentControlSet\Services | Services |
| %AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup | Autostart persistence location |
