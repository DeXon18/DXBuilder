## 🌟 Introduction

**DXBuilder**, now completely overhauled and reborn.
After months of silent development (no apologies — this was intentional 😉), **DXBuilder** is now a much more complete, flexible, and robust solution — **one script fits all**. And yes, this is just the beginning of something even bigger.

You can now use it on **ANY Windows 11 release** (not tied to a specific build), **ANY language**, and **ANY architecture** (x64, ARM64). This is made possible thanks to PowerShell’s advanced scripting capabilities — a massive leap from the old batch-based tools.

This script automates the creation of a streamlined, debloated Windows 11 image — conceptually inspired by tiny10/tiny11, but rewritten from the ground up by **DeXon**.
It uses **DISM’s recovery compression** for significantly smaller ISO sizes, and **zero external utilities** — except for `oscdimg.exe` (from Windows ADK or downloaded directly from Microsoft), which is only used to generate the final bootable ISO.

Also included is a **corrected and validated `autounattend.xml`** that:
- ✅ Bypasses Microsoft Account during OOBE.
- ✅ Installs Windows in `/compact` mode to save disk space.
- ✅ Prevents reinstallation of bloatware like Teams, Copilot, and Outlook.

> 🎯 **It’s open-source — so feel free to add, remove, or break anything you want!**
> Feedback, bug reports, and feature requests are not just welcome — they’re encouraged.

And for the very first time… introducing **DXBuilder Core** (coming soon)!
A nuclear-grade script designed for rapid development or testing environments. Strips Windows down to the bare metal — no fluff, no mercy.
⚠️ **Warning:** Not suitable for daily use. No serviceability. No updates. No languages. Just raw, minimal Windows 11 — perfect for VMs or disposable environments.

---

## ⚠️ Script Versions

- **✅ `DXBuilder.ps1`** — The standard script.
  Removes bloatware but keeps the system **fully serviceable**. You can install updates, language packs, and features after installation.
  **Recommended for daily use, real hardware, or production VMs.**

- **⚠️ `DXBuilder_Core.ps1`** — *(Coming Soon)* The “nuclear” option.
  Removes **everything non-essential**, including WinSxS, WinRE, and disables Windows Update.
  You **cannot** add languages, updates, or features after creation.
  **Only recommended for testing, development, or ephemeral VMs.**

---

## 📥 Instructions

1.  **Download Windows 11** from:
    ▶️ [Microsoft Official Site](https://www.microsoft.com/software-download/windows11)
    ▶️ Or use [Rufus](https://github.com/pbatard/rufus) for more flexible ISO options.

2.  **Mount the ISO** using Windows Explorer (double-click the file).

3.  **Open PowerShell 5.1 (or 7+) as Administrator**.

4.  **Temporarily change execution policy** (safe, session-only):
    ```powershell
    Set-ExecutionPolicy Bypass -Scope Process
    ```
    ✅ Using `-Scope Process` keeps your system policy intact — changes last only for this session.

5.  **Run the script:**
    ```powershell
    C:\path\to\DXBuilder.ps1 -ISO <letter> -SCRATCH <letter>
    # Example: .\DXBuilder.ps1 -ISO E -SCRATCH D
    ```
    💡 Run `Get-Help .\DXBuilder.ps1 -Full` to see all options — including `-InteractiveApps` for custom app removal!

6.  **Select:**
    *   The drive letter of your mounted ISO (just the letter, no colon).
    *   The Windows SKU/index you want to modify (Home, Pro, etc.).

7.  Sit back, relax, and let the magic happen ☕

When finished, your new ISO will be waiting in the script’s folder:
- 📦 **`DXBuilder.iso`**
- ✅ Includes SHA256 checksum for verification.

---

## 🗑️ What Gets Removed?

| Standard (`DXBuilder.ps1`) | Core (`DXBuilder_Core.ps1`) |
| :--- | :--- |
| • Clipchamp | • Everything from Standard + |
| • Bing News, Weather, Sports | • Windows Component Store (WinSxS) |
| • Xbox Apps & Game Bar | • Windows Recovery (WinRE) |
| • Microsoft Teams & Copilot | • Windows Update (permanently broken) |
| • Get Help, Get Started, Tips | • Defender (disabled, can be re-enabled) |
| • Office Hub, Sticky Notes, Solitaire | • ❗ No post-install features/languages |
| • Paint 3D, 3D Viewer, Mixed Reality | |
| • OneDrive & Edge (fully removed) | |
| • Telemetry services & scheduled tasks | |
| • Sponsored apps & cloud content | |

> ⚠️ In **DXBuilder Core**: You cannot add back features, languages, or updates. Ever.
>
> During image creation, you’ll be asked if you want to enable **.NET 3.5 support**!

---

## ⚠️ Known Issues
- Some Edge remnants may appear in Settings — but the app itself is fully deleted.
- You may need to update Winget manually via Microsoft Store before installing apps.
- Outlook and Dev Home may reappear after updates — we’re fighting back aggressively with registry and task blocking.
- On ARM64, you might see a harmless error when removing OneDrive (file doesn’t exist on ARM — script handles it gracefully).

---

## 🚀 Features Implemented (as of v1.0 — 2025-07-09)
- ✅ Telemetry fully disabled (since day one).
- ✅ Ad & sponsored content suppression (aggressively blocked via registry).
- ✅ Automatic architecture & language detection.
- ✅ Interactive app selection menu (`-InteractiveApps` flag).
- ✅ SHA256 checksum generation for your ISO.
- ✅ Corrected `autounattend.xml` (no more silent OOBE failures!).
- ✅ Full error handling & automatic cleanup.
- ✅ Changelog & versioning built-in.

---

## 🔮 Features to be Implemented
🧩 Modular components — choose your “de-bloat level”.
🎨 GUI version (WPF or WinUI — yes, it’s coming).
🌐 Direct WIM/ESD processing (no ISO mounting needed).
🔄 Post-install script injection (run your own `setup.cmd`).
📦 Optional driver injection during build.
🧪 DXBuilder Core release (target: August 2025).

---

## ❤️ Support the Project
If DXBuilder saved you time, frustration, or disk space — consider supporting the project!
Your donations help me dedicate more time to building tools like this — no corporate sponsors, no ads, just pure passion.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/V7V21LFSBP) | 💰 **PayPal**

---

## 📜 License
**MIT** — Do whatever you want. Modify it, redistribute it, even sell it (just give credit where it’s due 😉).

---

## 💬 Feedback?
Found a bug? Have a killer feature idea?
➡️ **Open an Issue on GitHub**

Thanks for trying **DXBuilder**!
*Crafted with ❤️ by DeXon — Inspired by tiny11, but built my way.*
