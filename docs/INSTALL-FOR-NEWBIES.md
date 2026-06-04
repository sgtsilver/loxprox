**Language:** [Deutsch](INSTALL-FOR-NEWBIES.de.md) · English

# Installation for Linux Newbies

**You own a Loxone Miniserver but don't know much about Linux? No problem. We won't judge, and we won't gatekeep — just follow along.**

Everybody starts somewhere. If you can follow a recipe, you can do this. You will copy and paste a handful of commands, type in a few of your own numbers, and at the end your Miniserver will sit behind a proper security gateway instead of being exposed to the whole internet. No prior Linux experience required. Take your time. There are no stupid questions here.

> If a word looks scary, jump to the **[Plain-language glossary](#plain-language-glossary)** at the bottom — every bit of jargon is translated there.

---

## What you'll end up with

A small, always-on computer (a virtual machine or a Raspberry Pi) that sits **between the internet and your Miniserver**. The outside world talks to the gateway; the gateway inspects everything and only passes safe traffic to your Miniserver. Your phone app keeps working exactly as before — it just connects to the gateway instead of straight to the Miniserver.

```
Internet  →  your router  →  LoxProx gateway  →  your Loxone Miniserver
                              (firewall, rate limits,
                               attack detection, HTTPS)
```

## What you'll need

- **A little computer to run it on.** Three easy options — pick whichever you already have (details in [Step 1](#step-1-get-a-little-computer-for-it)):
  - a **virtual machine** on a Proxmox/home-server box, or
  - a **Raspberry Pi 3, 4, or 5** (with 64-bit Raspberry Pi OS), or
  - any **old mini-PC or laptop** you can wipe and install Debian on.
- **Your Miniserver's details** — we have a tool that finds these for you, so don't worry if you don't know them yet.
- **About 30–45 minutes** and your beverage of choice. (If that beverage is alcoholic, maybe save the round for *after* you're done — you'll want a clear head while you rewire how your home talks to the internet.)
- That's it. You do **not** need to be a programmer.

A note on size: 1 CPU and **1 GB of RAM** is the minimum; **2 CPU / 2 GB** is comfortable. About 5 GB of disk.

> ⚠️ **One rule:** use a real virtual machine or a real Pi — **not** an "LXC container." Some of the protections quietly don't work inside a container, and you'd think you were protected when you weren't. If that sentence meant nothing to you, perfect — it means you're not using one. Carry on.

---

## Step 1 — Get a little computer for it

You just need *something* running **Debian 12** (a popular, free, rock-solid version of Linux). Choose the path that matches what you have:

- **You have a Proxmox or other home server →** create a new VM, give it 1–2 CPUs, 1–2 GB RAM, ~5 GB disk, and install Debian 12 on it. (Proxmox even has a "Debian 12" template.)
- **You have a Raspberry Pi →** flash **64-bit Raspberry Pi OS Lite** to the SD card with the official [Raspberry Pi Imager](https://www.raspberrypi.com/software/). A Pi 3/4/5 is plenty.
- **You have an old PC/laptop →** download Debian 12 from [debian.org](https://www.debian.org/distrib/), write it to a USB stick, and install it. The Debian installer holds your hand the whole way.

When you install, just accept the defaults. The only thing to remember: **write down the username and password you create.**

> Don't have any of these? A Raspberry Pi 4 is the cheapest, friendliest way in, and it sips power.

## Step 2 — Get to the "terminal"

The **terminal** (also called the "command line" or "shell") is just a text box where you type commands. It looks intimidating in movies; in reality it's a very patient assistant that does exactly what you tell it.

Two ways to reach it:

- **On a Pi / mini-PC with a screen and keyboard:** log in right there. The black screen *is* the terminal.
- **From your normal computer, over the network (recommended):** use **SSH**. On a Mac or Linux machine, open the Terminal app and type (replace the example address with your machine's address — your router's device list shows it):
  ```bash
  ssh yourusername@192.168.1.50
  ```
  On Windows, install [the free "Windows Terminal"](https://aka.ms/terminal) or use [PuTTY](https://www.putty.org/) and connect to the same address. The first time it asks "are you sure?" — type `yes`.

You're in when you see a line ending in `$` waiting for you. That's the assistant saying "ready."

## Step 3 — Become the administrator

A few commands need administrator rights. On Linux that's called **`sudo`** (think "do this as the boss"). You'll just put the word `sudo` in front of certain commands, and it'll ask for your password the first time. The password won't show as you type — that's normal, not broken. Press Enter.

## Step 4 — Download LoxProx

Copy-paste these lines one at a time (press Enter after each). The first installs the `git` download tool; the second downloads LoxProx; the third steps into its folder.

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/sgtsilver/loxprox.git
cd loxprox
```

If `git clone` says the folder already exists, you've already downloaded it — just `cd loxprox` and carry on.

## Step 5 — Find your Miniserver automatically

LoxProx ships a scanner that finds your Miniserver and prints everything you need to know about it:

```bash
chmod +x detect-loxone.sh
./detect-loxone.sh
```

(`chmod +x` just means "allow this script to run.") It will print your Miniserver's **IP address**, firmware version, and the exact values to use in the next step. **Keep that output on screen** — you'll copy a couple of numbers from it.

## Step 6 — Give the gateway a fixed address

So the gateway always keeps the same address, run:

```bash
sudo ./set-static-ip.sh
```

It asks a couple of friendly questions and sets things up. If you're not sure of an answer, the suggested default in brackets is almost always right — just press Enter.

## Step 7 — Tell LoxProx about your setup

LoxProx reads its settings from one small file. Start from the example:

```bash
sudo mkdir -p /etc/loxprox
sudo cp deploy.conf.example /etc/loxprox/deploy.conf
sudo nano /etc/loxprox/deploy.conf
```

`nano` is a beginner-friendly text editor that opens right in the terminal. Fill in the handful of values at the top — mostly the numbers `detect-loxone.sh` printed for you:

- `LOXONE_IP` — your Miniserver's address (from Step 5).
- `GATEWAY_IP` — this gateway's own address (from Step 6).
- `LAN_SUBNET` — your home network range (the scanner suggests it; usually something like `192.168.1.0/24`).
- `SSH_ALLOWED_SUBNETS` — who's allowed to log in to the gateway; your home network is fine to start.
- `DISCORD_WEBHOOK` *(optional)* — paste a Discord webhook URL here to get phone alerts. Skip it for now if you like.

Every value has a comment above it explaining what it does. When you're done: press **Ctrl+O** then **Enter** to save, then **Ctrl+X** to exit. (Stuck on a value? The full [Configuration Guide](../CONFIGURATION-GUIDE.md) explains every single one.)

## Step 8 — Run the installer

This is the big moment. One command does everything — installs the firewall, the proxy, the attack detection, and hardens the machine:

```bash
sudo bash deploy.sh
```

It prints what it's doing as it goes (green is good). It's **safe to run again** if anything hiccups — it just picks up where it left off.

**The one moment to pay attention to — your SSH key.** Partway through, the installer wants to lock down remote logins so attackers can't brute-force a password. To avoid accidentally locking *you* out, it pauses and offers a menu. The easy, safe choices:

- Already log in with an SSH key? Choose **keep it** and you're done.
- Not sure what an SSH key is? Choose the **`[K]` keep password login** option for now — you stay in, and the gateway puts a friendly reminder in front of you until you set a key up later. Nothing breaks.

You will **not** get locked out by following the menu. When in doubt, pick the option that keeps you logged in.

## Step 9 — Check that it all worked

```bash
sudo ./test-gateway.sh
```

This runs 50+ checks and prints a tidy pass/fail report. Lots of green ticks means you're protected. If something's red, the line usually tells you exactly what to do.

## Step 10 — Point your world at the gateway

Two small changes outside the terminal:

1. **On your router:** forward incoming port **1080** to the gateway's address (instead of forwarding it to the Miniserver directly). If you had a forward pointing at the Miniserver before, point it at the gateway now.
2. **In the Loxone app:** change the Miniserver's connection address to the **gateway's** address on port **1080**. Everything else in the app stays the same.

That's it — you're done. Your Miniserver now answers the internet only through a gateway that's watching its back.

## Optional — turn on HTTPS (encryption)

Want the padlock and encrypted traffic? LoxProx can do automatic HTTPS. It needs a public domain name and one extra router setting, so it's off by default. When you're ready, follow the friendly [TLS Setup guide](TLS-SETUP.md) — it walks you through it the same gentle way.

---

## Uh oh — something looks broken

Breathe. Almost nothing here is permanent, and you can re-run things safely.

- **The installer stopped with a red error.** Read the last few red lines — they usually name the problem. Fix it and just run `sudo bash deploy.sh` again.
- **You think you locked yourself out over SSH.** You almost certainly didn't (the installer is built to prevent it). Log in at the machine's own screen/keyboard if you can, and re-run the installer.
- **The app can't connect.** Double-check Step 10: the router forwards port 1080 to the *gateway*, and the app points at the *gateway's* address on port 1080. If you turned on HTTPS, the app address must start with `https://` (see the TLS guide).
- **Still stuck?** [Open an issue on GitHub](https://github.com/sgtsilver/loxprox/issues) and describe what you did and what you saw. Paste the error text. **No question is too basic** — that's literally what the tracker is for.

You did a real systems-administration task today. That's not nothing. Welcome in.

---

## Plain-language glossary

| Word | What it actually means |
|------|------------------------|
| **Terminal / shell / command line** | A text box where you type commands. A patient assistant. |
| **Linux** | A free operating system, like Windows or macOS but built for servers. |
| **Debian** | One popular, very stable flavour of Linux. The one we use. |
| **VM (virtual machine)** | A pretend computer running inside a real one. Acts like its own machine. |
| **Raspberry Pi** | A tiny, cheap real computer the size of a deck of cards. |
| **SSH** | A secure way to use one computer's terminal from another over the network. |
| **`sudo`** | "Do this as the administrator." Put it in front of commands that need extra rights. |
| **root** | The administrator account — the boss with full control. |
| **IP address** | A computer's address on the network, like `192.168.1.50`. |
| **Port** | A numbered "door" on a computer. LoxProx listens on door `1080`. |
| **Subnet / `/24`** | A range of addresses on your home network, e.g. `192.168.1.0/24`. |
| **Firewall** | A guard that blocks unwanted network traffic. |
| **Proxy / gateway** | A middleman that passes traffic through after checking it. That's LoxProx. |
| **`nano`** | A simple text editor that runs in the terminal. Ctrl+O saves, Ctrl+X exits. |
| **`git` / clone** | A tool to download (and update) code from GitHub. |
| **HTTPS / TLS** | Encryption — the padlock in your browser. Optional here, recommended. |
| **CrowdSec / nftables / AppArmor** | The security tools LoxProx sets up for you. You don't configure them by hand. |

Want the deeper, more technical version once you're comfortable? See the main [README](../README.en.md) and the [Configuration Guide](../CONFIGURATION-GUIDE.md).
