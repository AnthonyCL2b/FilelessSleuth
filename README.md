# <b>FilelessSleuth</b>

## <b>Description :</b>

This program aims to detect fileless malware on a target machine.

## <b>Context of creation</b>

This project is being undertaken as part of a Master of Science (MSc) thesis in Cyber Security on the topic of fileless malware. Although all the work is being carried out by myself, it is also being supervised by the academic faculty of the University of Kent.

## <b>Fileless Malwares ?</b>

Fileless malware represents a sophisticated and ever-evolving cyber threat in the realm of cybersecurity. Unlike conventional malware that relies on malicious files, fileless malware operates by leveraging inherent system tools and exploiting vulnerabilities within legitimate software. Its ingenious strategy involves concealing its presence within a computer's volatile memory, evading detection by conventional antivirus solutions. By circumventing traditional file-based analysis, fileless malware evades leaving any discernible traces on the hard drive, making its identification and removal considerably challenging. This stealthy characteristic grants fileless malware a higher probability of successfully executing malicious activities, such as data exfiltration, remote access, or lateral movement within a network, all while remaining undetected. Addressing the threat posed by fileless malware necessitates advanced security measures, encompassing proactive monitoring, behavior analysis, and robust endpoint security solutions capable of effectively detecting and neutralizing these elusive threats.

## <b>How do they operate?</b>

Fileless malware employs various sophisticated techniques to execute malicious activities on victims' systems without leaving traces on the file system. One such method is through the exploitation of legitimate Windows Management Instrumentation (WMI) functionalities. 

By utilizing WMI, fileless malware can execute arbitrary commands, access system information, and even persistently maintain control over compromised systems. Another method employed by fileless malware is the leveraging of PowerShell, a powerful scripting language and automation framework present in Windows environments. This allows attackers to execute malicious PowerShell commands directly in memory, bypassing traditional security measures. Additionally, fileless malware may exploit vulnerabilities in legitimate applications or abuse built-in system utilities like Windows Registry, Scheduled Tasks, or even macro-enabled documents to establish persistence and carry out its malicious intentions.

## <b>How to detect them?</b>

1. <b>Behavioural analysis:</b> Monitor system activity and detect suspicious behaviour such as abnormal process execution, unusual memory usage or unexpected network traffic.
2. <b>Anomaly Detection:</b> Use machine learning algorithms to identify unusual patterns and behaviours that could indicate the presence of fileless malware.
3. <b>User and Entity Behaviour Analysis (UEBA):</b> Monitor user behaviour and build baseline profiles to detect abnormal activity that may indicate fileless malware.
4. <b>System Event Monitoring:</b> Monitor system events such as registry changes, unusual command line executions, or system configuration changes for activity potentially related to fileless malware.
5. <b>Threat intelligence feeds:</b> Leverage threat intelligence feeds and indicators of compromise (IOCs) to identify known fileless malware techniques and patterns.
6. <b>Endpoint Security Solutions:</b> Deploy advanced endpoint security solutions that can detect fileless malware by monitoring and analysing system behaviour in real time.
7. <b>Memory Forensics:</b> Perform in-depth analysis of system memory to detect suspicious or anomalous behaviour associated with fileless malware.
8. <b>Security Information and Event Management Systems (SIEM):</b> Use SIEM systems to collect, correlate and analyse logs from various sources to identify fileless malware patterns and indicators.