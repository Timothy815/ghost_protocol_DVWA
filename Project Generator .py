import zipfile
import os

def create_project_zip():
    # File 1: ghost_protocol.html (The C2 Dashboard with 8 Missions)
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GHOST PROTOCOL // C2 DASHBOARD</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;800&family=Share+Tech+Mono&display=swap" rel="stylesheet">
    <style>
        /* --- AESTHETICS --- */
        :root {
            --bg-color: #050505;
            --terminal-green: #00ff41;
            --dim-green: #008f11;
            --alert-red: #ff3333;
            --kali-blue: #23a3ff;
        }
        
        body {
            background-color: var(--bg-color);
            color: #ccc;
            font-family: 'JetBrains Mono', monospace;
            overflow: hidden;
            height: 100vh;
        }

        /* CRT Effects */
        .crt::before {
            content: " ";
            display: block;
            position: absolute;
            top: 0; left: 0; bottom: 0; right: 0;
            background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.06), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.06));
            z-index: 50;
            background-size: 100% 2px, 3px 100%;
            pointer-events: none;
        }

        /* Scrollbars */
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #000; }
        ::-webkit-scrollbar-thumb { background: #333; }
        ::-webkit-scrollbar-thumb:hover { background: var(--dim-green); }

        /* HUD Borders */
        .hud-border {
            border: 1px solid #1f2937;
            position: relative;
        }
        .hud-border::after {
            content: ''; position: absolute; bottom: 0; right: 0;
            width: 8px; height: 8px; border-bottom: 2px solid var(--terminal-green); border-right: 2px solid var(--terminal-green);
        }
        .hud-border::before {
            content: ''; position: absolute; top: 0; left: 0;
            width: 8px; height: 8px; border-top: 2px solid var(--terminal-green); border-left: 2px solid var(--terminal-green);
        }
    </style>
</head>
<body class="crt" x-data="gameEngine()">

    <!-- INTRO SPLASH -->
    <div x-show="!gameStarted" class="fixed inset-0 z-[100] bg-black flex flex-col items-center justify-center text-center p-4">
        <h1 class="text-7xl md:text-9xl font-black text-green-500 mb-2 tracking-tighter" style="font-family: 'Share Tech Mono'; text-shadow: 0 0 20px rgba(0,255,0,0.5);">GHOST<br>PROTOCOL</h1>
        <div class="w-64 h-1 bg-green-900 mb-8 overflow-hidden rounded">
            <div class="h-full bg-green-500 animate-[loading_2s_ease-in-out]"></div>
        </div>
        <button @click="initSystem()" class="group relative px-8 py-4 bg-transparent border border-green-600 text-green-500 font-bold uppercase tracking-widest hover:bg-green-500 hover:text-black transition-all">
            <span class="absolute inset-0 w-full h-full bg-green-500/10 opacity-0 group-hover:opacity-100 transition-opacity"></span>
            Initialize Uplink
        </button>
        <p class="mt-6 text-xs text-gray-600 font-mono">SECURE CONNECTION // ENCRYPTED // T.L.P. RED</p>
    </div>

    <!-- MAIN DASHBOARD -->
    <div x-show="gameStarted" class="flex flex-col h-screen" x-cloak>
        
        <!-- TOP NAV -->
        <header class="h-14 bg-gray-900 border-b border-gray-800 flex items-center justify-between px-4 z-40 shrink-0">
            <div class="flex items-center gap-6">
                <span class="text-green-500 font-bold tracking-widest text-lg" style="font-family: 'Share Tech Mono'">GHOST PROTOCOL</span>
                <nav class="hidden md:flex gap-1">
                    <button @click="view = 'missions'" :class="view === 'missions' ? 'bg-green-900/30 text-green-400 border-green-600' : 'text-gray-500 border-transparent hover:text-gray-300'" class="px-4 py-1 border-b-2 text-sm font-mono transition-colors">MISSIONS</button>
                    <button @click="view = 'terminal'" :class="view === 'terminal' ? 'bg-blue-900/20 text-blue-400 border-blue-600' : 'text-gray-500 border-transparent hover:text-gray-300'" class="px-4 py-1 border-b-2 text-sm font-mono transition-colors">TERMINAL (LIVE)</button>
                    <button @click="view = 'target'" :class="view === 'target' ? 'bg-red-900/20 text-red-400 border-red-600' : 'text-gray-500 border-transparent hover:text-gray-300'" class="px-4 py-1 border-b-2 text-sm font-mono transition-colors">TARGET (DVWA)</button>
                </nav>
            </div>
            <div class="flex items-center gap-4 font-mono text-xs md:text-sm">
                <div class="px-3 py-1 bg-gray-800 rounded border border-gray-700">
                    <span class="text-gray-400">XP:</span> <span class="text-white font-bold" x-text="xp"></span>
                </div>
                <div class="px-3 py-1 bg-gray-800 rounded border border-gray-700">
                    <span class="text-gray-400">RANK:</span> <span class="text-yellow-500 font-bold" x-text="rank"></span>
                </div>
            </div>
        </header>

        <!-- MAIN CONTENT AREA -->
        <div class="flex-1 overflow-hidden relative">

            <!-- VIEW: MISSIONS -->
            <div x-show="view === 'missions'" class="h-full flex flex-col md:flex-row">
                
                <!-- Mission List Sidebar -->
                <div class="w-full md:w-72 bg-black border-r border-gray-800 overflow-y-auto">
                    <div class="p-3 text-xs font-bold text-gray-500 uppercase tracking-wider sticky top-0 bg-black z-10 border-b border-gray-800">Operation Log</div>
                    <template x-for="(mission, idx) in missions" :key="idx">
                        <div @click="loadMission(idx)" 
                             class="p-4 border-b border-gray-900 cursor-pointer transition-all hover:bg-gray-900 group"
                             :class="{'bg-gray-900 border-l-2 border-l-green-500': currentMissionIdx === idx, 'opacity-40 pointer-events-none': !mission.unlocked}">
                            <div class="flex justify-between items-center mb-1">
                                <span class="text-xs font-mono" :class="mission.completed ? 'text-green-500' : 'text-gray-500'" x-text="mission.code"></span>
                                <span x-show="!mission.unlocked" class="text-[10px] text-red-500">LOCKED</span>
                                <span x-show="mission.completed" class="text-[10px] text-green-500">✓ DONE</span>
                            </div>
                            <h3 class="text-sm font-bold text-gray-200 group-hover:text-green-400" x-text="mission.title"></h3>
                        </div>
                    </template>
                </div>

                <!-- Mission Details -->
                <div class="flex-1 bg-gray-900/50 p-6 overflow-y-auto relative">
                    <!-- Background Grid -->
                    <div class="absolute inset-0" style="background-image: radial-gradient(#1f2937 1px, transparent 1px); background-size: 20px 20px; opacity: 0.1; pointer-events: none;"></div>

                    <div class="max-w-4xl mx-auto relative z-10 space-y-6">
                        
                        <!-- Header -->
                        <div class="hud-border bg-black/80 p-6 backdrop-blur">
                            <h2 class="text-3xl text-white font-bold mb-2" x-text="currentMission.title"></h2>
                            <div class="flex gap-2 mb-4">
                                <span class="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded font-mono" x-text="currentMission.type"></span>
                                <span class="text-xs bg-red-900/30 text-red-400 border border-red-900 px-2 py-1 rounded font-mono uppercase">Clearance: Top Secret</span>
                            </div>
                            <div class="text-green-400/90 font-mono text-sm leading-relaxed" x-html="currentMission.briefing"></div>
                        </div>

                        <!-- Two Column Layout -->
                        <div class="grid md:grid-cols-2 gap-6">
                            
                            <!-- Tactical Intel (Hints) -->
                            <div class="bg-gray-900 border border-gray-700 p-5 flex flex-col">
                                <h3 class="text-sm font-bold text-gray-400 uppercase tracking-widest mb-4 border-b border-gray-800 pb-2">Tactical Intel</h3>
                                
                                <div x-show="!intelUnlocked" class="flex-1 flex flex-col items-center justify-center text-center py-8">
                                    <div class="text-4xl mb-2">🔒</div>
                                    <p class="text-sm text-gray-500 mb-4">Intel Encrypted</p>
                                    <button @click="solveMinigame()" class="px-4 py-2 bg-green-900/20 border border-green-600 text-green-500 text-xs hover:bg-green-500 hover:text-black transition">
                                        DECRYPT INTEL
                                    </button>
                                </div>

                                <div x-show="intelUnlocked" class="space-y-4 animate-[fadeIn_0.5s]">
                                    <div class="bg-black p-3 border-l-2 border-blue-500 text-sm font-mono text-blue-300">
                                        <strong class="block text-blue-400 mb-1">RECOMMENDED TOOL:</strong>
                                        <span x-text="currentMission.tool"></span>
                                    </div>
                                    <div class="bg-black p-3 border-l-2 border-yellow-500 text-sm font-mono text-gray-300">
                                        <strong class="block text-yellow-500 mb-1">ATTACK VECTOR:</strong>
                                        <p x-html="currentMission.hint"></p>
                                    </div>
                                    <button @click="view = 'terminal'" class="w-full py-2 bg-gray-800 hover:bg-gray-700 text-xs text-gray-400 border border-gray-600 mt-2 text-left px-4">
                                        > LAUNCH KALI TERMINAL
                                    </button>
                                </div>
                            </div>

                            <!-- Flag Submission -->
                            <div class="bg-black border-2 border-green-800 p-6 flex flex-col justify-center shadow-[0_0_20px_rgba(0,255,0,0.1)]">
                                <label class="text-xs text-green-700 uppercase font-bold mb-2">Exfiltrated Data (Flag)</label>
                                <div class="relative">
                                    <span class="absolute left-3 top-3 text-green-600 font-mono">></span>
                                    <input type="text" x-model="flagInput" @keyup.enter="submitFlag()" 
                                           class="w-full bg-gray-900 border border-gray-700 text-white p-3 pl-8 font-mono focus:border-green-500 focus:outline-none focus:ring-1 focus:ring-green-500 mb-2"
                                           placeholder="flag{...}">
                                </div>
                                <button @click="submitFlag()" class="bg-green-600 hover:bg-green-500 text-black font-bold py-2 uppercase tracking-widest transition shadow-lg shadow-green-900/50">
                                    Transmit
                                </button>
                                <p class="h-4 mt-2 text-xs font-mono text-center" :class="msgType === 'error' ? 'text-red-500' : 'text-green-400'" x-text="msg"></p>
                            </div>

                        </div>
                    </div>
                </div>
            </div>

            <!-- VIEW: REAL KALI TERMINAL (GoTTY) -->
            <div x-show="view === 'terminal'" class="h-full bg-black flex flex-col">
                <div class="bg-[#101010] p-2 flex justify-between items-center border-b border-gray-800">
                    <span class="text-xs text-gray-500 font-mono">CONNECTION: <span class="text-green-500">ESTABLISHED (PORT 8080)</span></span>
                    <span class="text-xs text-blue-500 font-mono">ROOT@KALI</span>
                </div>
                <!-- 
                   CONNECTS TO LOCALHOST:8080 (The Kali Docker Container)
                   Requires Docker container running GoTTY
                -->
                <iframe src="http://localhost:8080" class="w-full h-full border-none bg-black"></iframe>
            </div>

            <!-- VIEW: TARGET (DVWA) -->
            <div x-show="view === 'target'" class="h-full bg-gray-900 flex flex-col">
                <div class="bg-gray-800 p-2 flex gap-4 items-center border-b border-black">
                    <input type="text" value="http://localhost:80/dvwa/login.php" class="bg-black text-gray-400 text-xs px-2 py-1 rounded w-96 font-mono" readonly>
                    <span class="text-xs text-yellow-600">⚠ Ensure DVWA container is running on Port 80</span>
                </div>
                <!-- 
                   CONNECTS TO LOCALHOST:80 (The DVWA Container)
                -->
                <iframe src="http://localhost:80" class="w-full h-full bg-white"></iframe>
            </div>

        </div>
    </div>

    <!-- LOGIC CORE -->
    <script>
        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        function playSfx(type) {
            if (audioCtx.state === 'suspended') audioCtx.resume();
            const osc = audioCtx.createOscillator();
            const gain = audioCtx.createGain();
            osc.connect(gain);
            gain.connect(audioCtx.destination);
            
            const now = audioCtx.currentTime;
            if (type === 'access') {
                osc.type = 'square';
                osc.frequency.setValueAtTime(440, now);
                osc.frequency.linearRampToValueAtTime(880, now + 0.1);
                gain.gain.setValueAtTime(0.1, now);
                gain.gain.exponentialRampToValueAtTime(0.01, now + 0.5);
                osc.start(); osc.stop(now + 0.5);
            } else if (type === 'denied') {
                osc.type = 'sawtooth';
                osc.frequency.setValueAtTime(150, now);
                osc.frequency.linearRampToValueAtTime(100, now + 0.2);
                gain.gain.setValueAtTime(0.2, now);
                gain.gain.exponentialRampToValueAtTime(0.01, now + 0.3);
                osc.start(); osc.stop(now + 0.3);
            }
        }

        document.addEventListener('alpine:init', () => {
            Alpine.data('gameEngine', () => ({
                gameStarted: false,
                view: 'missions', // missions, terminal, target
                currentMissionIdx: 0,
                xp: 0,
                rank: 'SCRIPT KIDDIE',
                intelUnlocked: false,
                flagInput: '',
                msg: '',
                msgType: '',
                
                missions: [
                    {
                        code: "OP-001",
                        title: "The Gatekeeper",
                        type: "Brute Force",
                        briefing: "Target uses a weak password policy. We need to breach the admin portal. <br>Intercept the login request and launch a dictionary attack.",
                        hint: "Use <strong>Hydra</strong> in the terminal. <br><code>hydra -l admin -P /usr/share/wordlists/rockyou.txt [IP] http-get-form ...</code>",
                        tool: "Hydra / Burp Suite",
                        flag: "password", 
                        unlocked: true,
                        completed: false
                    },
                    {
                        code: "OP-002",
                        title: "The Pipeline",
                        type: "Command Injection",
                        briefing: "Internal ping utility discovered. It executes shell commands directly. <br>Escape the ping command to list directory contents.",
                        hint: "Append a semicolon <code>;</code> or pipe <code>|</code> followed by a system command like <code>ls</code> or <code>whoami</code>.",
                        tool: "Browser / Curl",
                        flag: "flag{pipeline_master}", 
                        unlocked: false,
                        completed: false
                    },
                    {
                        code: "OP-003",
                        title: "The Imposter",
                        type: "CSRF",
                        briefing: "Target admin clicks links blindly. Create a malicious link that changes their password without them knowing.",
                        hint: "Construct a URL that triggers the 'Change Password' action. Example: <code>/vulnerabilities/csrf/?password_new=hacked...</code>",
                        tool: "HTML / Social Engineering",
                        flag: "flag{csrf_success}",
                        unlocked: false,
                        completed: false
                    },
                    {
                        code: "OP-004",
                        title: "The Archive",
                        type: "File Inclusion (LFI)",
                        briefing: "Web app loads pages via a PHP parameter. <br>Traverse the directory structure to steal <code>/etc/passwd</code>.",
                        hint: "Use directory traversal dot-dot-slash: <code>../../../../etc/passwd</code>. <br>Try using <code>curl</code> in the terminal.",
                        tool: "Browser / Curl",
                        flag: "root:x:0:0",
                        unlocked: false,
                        completed: false
                    },
                    {
                        code: "OP-005",
                        title: "The Heist",
                        type: "SQL Injection",
                        briefing: "User ID input is not sanitized. Break the query syntax to dump the entire database.",
                        hint: "Use <strong>SQLMap</strong> in the terminal: <br><code>sqlmap -u 'http://ghost_target/dvwa/...' --dbs</code>",
                        tool: "SQLMap / Manual SQL",
                        flag: "flag{db_dumped}",
                        unlocked: false,
                        completed: false
                    },
                    {
                        code: "OP-006",
                        title: "Viral Signal",
                        type: "XSS (Stored)",
                        briefing: "The Guestbook does not filter scripts. Plant a persistent payload that alerts the cookie of anyone who views it.",
                        hint: "Payload: <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code>",
                        tool: "JavaScript",
                        flag: "flag{xss_persistence}",
                        unlocked: false,
                        completed: false
                    },
                    {
                        code: "OP-007",
                        title: "The Trojan",
                        type: "File Upload",
                        briefing: "Upload form allows image files. Bypass the filter to upload a PHP reverse shell.",
                        hint: "Upload a file named <code>shell.php</code> containing <code>&lt;?php system($_GET['cmd']); ?&gt;</code>.",
                        tool: "Weevely / Metasploit",
                        flag: "flag{shell_uploaded}",
                        unlocked: false,
                        completed: false
                    },
                    {
                        code: "OP-008",
                        title: "Ghost in the Machine",
                        type: "Full Compromise",
                        briefing: "Combine previous vectors to gain root access to the Docker container.",
                        hint: "There are no rules. Get root.",
                        tool: "ALL AVAILABLE",
                        flag: "flag{root_access_granted}",
                        unlocked: false,
                        completed: false
                    }
                ],

                get currentMission() { return this.missions[this.currentMissionIdx]; },

                initSystem() {
                    playSfx('access');
                    this.gameStarted = true;
                },

                loadMission(idx) {
                    this.currentMissionIdx = idx;
                    this.intelUnlocked = this.missions[idx].completed;
                    this.flagInput = '';
                    this.msg = '';
                },

                solveMinigame() {
                    playSfx('access');
                    this.intelUnlocked = true;
                },

                submitFlag() {
                    if (this.flagInput.trim() === this.currentMission.flag) {
                        playSfx('access');
                        this.missions[this.currentMissionIdx].completed = true;
                        this.msg = "DATA CONFIRMED. MISSION COMPLETE.";
                        this.msgType = "success";
                        this.xp += 500;
                        this.checkRank();
                        if (this.currentMissionIdx + 1 < this.missions.length) {
                            this.missions[this.currentMissionIdx + 1].unlocked = true;
                        }
                    } else {
                        playSfx('denied');
                        this.msg = "INVALID HASH. ACCESS DENIED.";
                        this.msgType = "error";
                    }
                },

                checkRank() {
                    if (this.xp >= 4000) this.rank = "STATE ACTOR";
                    else if (this.xp >= 3000) this.rank = "BLACK HAT";
                    else if (this.xp >= 2000) this.rank = "GREY HAT";
                    else if (this.xp >= 1000) this.rank = "SCRIPT KIDDIE";
                }
            }));
        });
    </script>
</body>
</html>"""

    # File 2: docker-compose.yml
    docker_compose_content = """version: '3'

services:
  # 1. The Target Machine
  dvwa:
    image: vulnerables/web-dvwa
    container_name: ghost_target
    ports:
      - "80:80"
    environment:
      # CRITICAL: Allow iframe embedding for the dashboard
      - PHP_X_FRAME_OPTIONS=allow
    networks:
      - cyber-range

  # 2. The Attack Machine (Terminal)
  kali:
    build: .
    container_name: ghost_terminal
    ports:
      - "8080:8080"
    networks:
      - cyber-range
    tty: true

networks:
  cyber-range:
    driver: bridge"""

    # File 3: Dockerfile
    dockerfile_content = """# Use the official rolling Kali image
FROM kalilinux/kali-rolling

# Non-interactive installation to prevent hanging
ENV DEBIAN_FRONTEND=noninteractive

# 1. Install Core Tools (Nmap, SQLMap, Hydra, Curl, etc.)
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    vim \
    net-tools \
    iputils-ping \
    nmap \
    hydra \
    sqlmap \
    python3 \
    jq \
    && rm -rf /var/lib/apt/lists/*

# 2. Install GoTTY (The Web-Terminal Bridge)
RUN wget https://github.com/yudai/gotty/releases/download/v1.0.1/gotty_linux_amd64.tar.gz \
    && tar -xvf gotty_linux_amd64.tar.gz \
    && mv gotty /usr/local/bin/ \
    && chmod +x /usr/local/bin/gotty \
    && rm gotty_linux_amd64.tar.gz

# 3. Setup the Shell
WORKDIR /root
SHELL ["/bin/bash", "-c"]

# 4. Expose the Web Terminal Port
EXPOSE 8080

# 5. Start GoTTY
CMD ["gotty", "-w", "--permit-write", "--address", "0.0.0.0", "--port", "8080", "/bin/bash"]"""

    # File 4: README.md
    readme_content = """# Operation Ghost Protocol

Welcome to the Cyber-Range. This project spins up a local CTF environment with a story-driven dashboard.

## Setup Instructions

1.  **Prerequisites:** Ensure you have Docker and Docker Compose installed.
2.  **Initialize:**
    ```bash
    git init
    git add .
    git commit -m "Initial commit"
    ```
3.  **Launch:**
    ```bash
    docker-compose up --build
    ```
4.  **Play:**
    * Open `ghost_protocol.html` in your browser.
    * **Target Tab:** Connects to DVWA on `http://localhost:80`.
    * **Terminal Tab:** Connects to Kali on `http://localhost:8080`.

## Troubleshooting
* **Port Conflicts:** Ensure ports 80 and 8080 are free.
* **Iframe Issues:** If the Target tab is blank, ensure your browser isn't blocking mixed content or local file access.
"""

    # Create