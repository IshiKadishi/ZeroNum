ZeroNum
========
ZeroNum is a tool designed to enumerate target machines comprehensively by scanning all ports, identifying open services, and performing detailed follow-up checks and interactions. Once data on open ports such as FTP, RPC, and SMB are collected, the tool offers advanced capabilities to detect anonymous or default login options, connect where possible, and further enumerate these services.

Project Motivation:
-------------------
This project serves as a cornerstone of my learning journey into network security and protocol analysis. I aim to build a robust understanding of how various network protocols operate by developing custom solutions for interacting with these protocols, such as SMB, without relying on external utilities like smbclient. Through this process, I am enhancing both my Python programming skills and practical security expertise.

Key Features (Planned and Implemented):
---------------------------------------
- Port Scanning: Enumerates all ports on a target machine.
- Service Detection: Identifies and saves data on open services like FTP, RPC, SMB, etc.
- Login Checks: Performs checks for anonymous or default logins where applicable.
- Custom Protocol Interaction: Enables connections to open services for direct enumeration, with a focus on understanding and interacting with protocols like SMB through custom code.
- Output Formats: Data is saved in formats like JSON, TXT, and ZIP for flexible usage.

Learning Objectives:
--------------------
- Deepen my understanding of network protocols by implementing custom communication mechanisms.
- Develop a tool that not only enumerates services but also explores and interacts with them to uncover potential vulnerabilities.

Future Goals:
-------------
- Expanding protocol support for enumeration (e.g., FTP, RPC, HTTP).
- Optimizing the tool for performance and flexibility in real-world use cases.
