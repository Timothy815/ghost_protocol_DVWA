# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Operation Ghost Protocol** is a gamified cybersecurity lab platform designed for high school students. It's a narrative-driven CTF (Capture The Flag) experience where students act as field agents hacking a vulnerable target company.

The system uses Docker containers to run:
- **DVWA (Damn Vulnerable Web App)** - The attack target
- **Kali Linux with GoTTY** - The attack platform (web-based terminal)
- **ghost_protocol.html** - The interactive C2 dashboard that ties everything together

## Key Architecture

### Three-Container System
1. **Ghost Target (DVWA Container)**
   - Image: `vulnerables/web-dvwa`
   - Port: 80
   - Contains 8 vulnerable web applications mapped to mission objectives
   - Environment variable `PHP_X_FRAME_OPTIONS=allow` enables iframe embedding in the dashboard

2. **Ghost Terminal (Kali Container)**
   - Base: `kalilinux/kali-rolling`
   - Port: 8080
   - Uses GoTTY to expose a web-based root bash shell
   - Pre-installed tools: nmap, hydra, sqlmap, curl, python3, jq, git, vim, net-tools
   - Network: Connected via Docker bridge network `cyber-range` to reach the target

3. **C2 Dashboard (ghost_protocol.html)**
   - Single-file HTML5 application with Alpine.js and Tailwind CSS
   - Three main views: Missions, Terminal (live GoTTY iframe), Target (live DVWA iframe)
   - Features: Mission tracking, XP/rank system, tactical intel hints, audio SFX, flag submission

### Mission Structure
Eight operations teaching OWASP Top 10 vulnerabilities:
- OP-001: The Gatekeeper (Brute Force)
- OP-002: The Pipeline (Command Injection)
- OP-003: The Imposter (CSRF)
- OP-004: The Archive (File Inclusion/LFI)
- OP-005: The Heist (SQL Injection)
- OP-006: Viral Signal (XSS Stored)
- OP-007: The Trojan (File Upload)
- OP-008: Ghost in the Machine (Full Compromise/Privilege Escalation)

Each mission has:
- `code`: Operation code (OP-###)
- `title`: Narrative mission name
- `type`: Vulnerability type
- `briefing`: Story context and objective
- `hint`: Technical guidance (shown after unlocking tactical intel)
- `tool`: Recommended tool
- `flag`: Correct answer for validation
- `unlocked`: Whether mission is accessible
- `completed`: Progress tracking

## Common Development Commands

### Launch the Lab
```bash
docker-compose up --build
```

### Open the Dashboard
```bash
open ghost_protocol.html
```
Then navigate to:
- **Missions Tab**: Main interface with mission list and flag submission
- **Terminal Tab**: Web-based Kali shell at http://localhost:8080
- **Target Tab**: DVWA at http://localhost:80

### Modify Missions
Edit the `missions` array in the `gameEngine()` function inside ghost_protocol.html (around line 262). Each mission object contains the fields listed above. Changes take effect immediately after refreshing the browser.

### Stop Containers
```bash
docker-compose down
```

### Clean Up Containers and Images
```bash
docker-compose down -v
docker system prune -a
```

## Customization

The system is designed to be modular. You can:
- **Change flags**: Edit the `flag` property in any mission object
- **Rewrite narrative**: Update `briefing`, `title`, and `hint` text
- **Add new missions**: Insert new mission objects into the `missions` array
- **Add different targets**: Modify docker-compose.yml to use different vulnerable containers (OWASP Juice Shop, WebGoat, etc.)
- **Configure tools**: The Dockerfile installs tools at runtime; add more with additional `RUN apt-get install` commands

## Technical Implementation Details

### Dashboard State Management
- Uses Alpine.js for reactive state and view switching
- `gameEngine()` manages game state, mission progression, XP/rank calculations
- Missions unlock sequentially as previous ones complete
- Intel decryption (hint unlock) is a simple state toggle; can be enhanced with actual crypto

### Audio System
Web Audio API used for two SFX types:
- `access`: Ascending square wave (flag correct)
- `denied`: Descending sawtooth wave (flag incorrect)

### Networking
- Docker bridge network `cyber-range` allows containers to communicate by hostname
- GoTTY exposes the Kali bash shell via web socket on port 8080
- DVWA is accessible to both the dashboard iframe and the Kali terminal

### File Structure
- `ghost_protocol.html`: All dashboard UI, logic, and styling in one file
- `docker-compose.yml`: Service definitions and networking
- `Dockerfile.txt`: Kali container build configuration (install tools and GoTTY)
- `Project Generator .py`: Script to bundle files into a distributable zip
- `ghody_protocol.md`: Project documentation and teacher notes

## Important Notes for Modifications

- Keep the `cyber-range` bridge network name consistent across services
- The `PHP_X_FRAME_OPTIONS=allow` environment variable is critical for iframe embedding
- GoTTY is started with `--permit-write` flag to allow terminal interaction
- The flag submission system is case-sensitive; consider updating the `submitFlag()` method if you need case-insensitive matching
- Audio context requires user interaction to play (hence the "Initialize Uplink" button)
