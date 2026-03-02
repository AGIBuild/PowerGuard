# PowerGuard

PowerGuard is a Windows tray application that blocks shutdown, restart, and logoff operations.

It is designed for local desktop and virtual desktop scenarios (including RDS/AVD-like environments) where session continuity is important.

## Overview

- Runtime type: Windows Forms tray app (`WinExe`)
- Target framework: `net10.0-windows10.0.22000.0`
- Single-instance behavior via global mutex
- Requires administrator privilege (configured in `app.manifest`)

## Core Features

- Blocks shutdown/restart/logoff using multiple defensive layers
- Registers a system shutdown block reason for OS-level visibility
- Handles local and remote session-related Windows messages
- Periodically refreshes block state and registration for stability
- Records blocked attempts and shows history from the tray menu
- Writes runtime logs to the local app data directory

## How It Works

After startup, the app runs as a background process with a hidden window and a tray icon.

The hidden window receives session and shutdown messages, then coordinates with `ShutdownBlocker` to deny end-session requests, attempt shutdown abort when possible, and keep protection active.

## Run Locally

Run from the `src` directory:

```powershell
dotnet build
dotnet run
```

After launch:

- Tray text: `PowerGuard - Active`
- Right-click tray icon actions:
  - Show Attempts
  - Open Log Folder
  - Exit

## Log Location

Runtime logs are written to:

`%LocalAppData%\PowerGuard`

## Project Structure

```text
PowerGuard/
├─ design/                 # Design assets (icons, etc.)
├─ src/
│  ├─ Program.cs           # Entry point and single-instance guard
│  ├─ MainForm.cs          # Hidden window, tray UI, message routing
│  ├─ ShutdownBlocker.cs   # Core blocking implementation
│  ├─ app.manifest         # Admin privilege and OS compatibility
│  └─ PowerGuard.csproj    # Build and target configuration
└─ tools/
```

## Notes

- The project is designed with session protection as a priority.
- Exiting the app disables protection until it is started again.