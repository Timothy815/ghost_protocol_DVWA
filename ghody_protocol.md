#/Users/timothykoerner/.pyenv/shims/python3

🕵️ Project: Ghost Protocol

Gamified Cybersecurity Curriculum for High School Students

1. The Concept

"Operation: Ghost Protocol" is a narrative-driven cybersecurity learning platform designed to replace traditional, dry "recipe-style" labs with an immersive spy thriller experience.

Instead of reading a PDF manual and following steps A through Z, students act as Field Agents for a shadow organization. They interface with a "Command & Control" (C2) Dashboard that guides them through hacking a corrupt corporate entity (the Target).

The "Sticky" Philosophy

Inspired by the engagement mechanics found in video games and the "stickiness" concepts of Malcolm Gladwell, this project aims to:
	
Establish Context: Every technical action (e.g., SQL Injection) is framed as a critical mission objective (e.g., "Stealing the Database").

Provide Agency: Students feel like they are discovering vulnerabilities rather than being told where to click.

Visual Competence: The interface looks and sounds like a hacker terminal, making students feel cool and competent immediately.

2. Technical Architecture

The system relies on a Cyber Range architecture running entirely on local Docker containers.

A. The Dashboard (ghost_protocol.html)

Role: The "Game Client" and Mission Control.

Tech Stack: Single-file HTML5, Tailwind CSS, Alpine.js.

Features:
	
Mission Log: Tracks progress through 8 distinct operations.

XP & Rank System: Gamifies progress from "Script Kiddie" to "State Actor."

Tactical Intel: Provides hints and tool recommendations without giving away the answer.

Audio SFX: Immersive sound effects for typing, access granted/denied.

B. The Target (ghost_target)

Container: vulnerables/web-dvwa (Damn Vulnerable Web App).

Role: The "Enemy" server.

Configuration: Modified via environment variables to allow iframe embedding, creating a seamless "Heads Up Display" effect within the Dashboard.

C. The Attack Platform (ghost_terminal)

Container: kalilinux/kali-rolling.

Role: The "Weapon."

Technology: Uses GoTTY to render a real bash root shell inside the web browser.

Tools Installed: Nmap, Hydra, SQLMap, Curl, Python3.

Network: Connected via a private Docker bridge network to the Target.

3. Mission Campaign Map

The curriculum maps standard OWASP Top 10 vulnerabilities to narrative plot points.

Operation

Code Name

Vulnerability

Narrative Objective

OP-001

The Gatekeeper

Brute Force

Breach the administrative login portal using a dictionary attack.

OP-002

The Pipeline

Command Injection

Exploit a ping utility to map the internal server filesystem.

OP-003

The Imposter

CSRF

Tricking the admin into changing their password via a malicious link.

OP-004

The Archive

File Inclusion (LFI)

Traversing directory paths to steal the /etc/passwd file.

OP-005

The Heist

SQL Injection

Dumping the entire backend database to steal user credentials.

OP-006

Viral Signal

XSS (Stored)

Planting a persistent script to track users visiting the Guestbook.

OP-007

The Trojan

File Upload

Uploading a PHP reverse shell disguised as an image.

OP-008

Ghost in the Machine

Privilege Escalation

Gaining root access to the underlying container (The Final Exam).

4. Deployment Instructions

Prerequisites

Docker Desktop installed.

Git installed.

Setup Steps

Create Project Folder:
Create a folder named ghost_protocol.

Add Files:
Place ghost_protocol.html, docker-compose.yml, and Dockerfile inside.

Build the Range:
Open a terminal in the folder and run:
	
docker-compose up --build


Engage:
	
Students open ghost_protocol.html in their web browser.

Target Tab: Loads DVWA.

Terminal Tab: Loads the root Kali shell.

5. Teacher's Note

The system is designed to be modular. You can edit the missions array inside ghost_protocol.html to:
	
Change the flags (answers).

Rewrite the narrative.

Add new missions targeting different containers (e.g., Juice Shop).

Project created for 11th/12th Grade Cybersecurity Curriculum.