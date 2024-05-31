import queue
import threading
import os
import urllib.request

"""
The script check all the fylesistem of a given jooimla version and 
target a joomla website of the same version to map all the accessible path of it using the "queue" module

- Download "joomla_x.x.x" from the official website and extrat it in "./joomla_x.x.x"
- Configure also a joomla server on localhost with this guide:
    - https://assorted-estimate-5f8.notion.site/Joomla-setup-LAMP-Stack-82cdbe75b0794fa99f6f920db3acb6e9?pvs=74 
    - Start it: sudo systemctl start apache2  
"""

# Any Joomla_x.x.x website
target = "http://127.0.0.1:4242"

# The downloaded Joomla_x.x.x filesystem
directory = "src/05_WEB_HACKERY/joomla_5.0.1"

# File extensions to ignore
filters = [".jpg", ".gif", ".png", ".css"]

# Change the current working directory to the one with the joomla files
os.chdir(directory)

# Queue for storing paths to test
web_paths = queue.Queue()

# Walk through the directory, and add the paths to the queue
for r, d, f in os.walk("."):
    for file in f:
        remote_path = f"{r}/{file}"
        if remote_path.startswith("."):
            remote_path = remote_path[1:]
        if os.path.splitext(file)[1] not in filters:
            web_paths.put(remote_path)


# Function to test each path in the queue
def test_remote():  # sourcery skip: use-contextlib-suppress
    while not web_paths.empty():
        path = web_paths.get()
        url = f"{target}{path}"
        request = urllib.request.Request(url)
        try:
            response = urllib.request.urlopen(request)
            content = response.read()
            print(f"[{response.code}] => {path}")
            response.close()
        except urllib.error.HTTPError as error:
            # Error handling for failed requests
            pass


# Start
test_remote()
