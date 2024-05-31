import urllib.request
import threading
import queue

"""
In a lot of cases there are configuration files, leftover development files, debugging scripts, and 
other security breadcrumbs that can provide sensitive information or expose functionality that
the software developer did not intend.

The tool will accept wordlists from common brute forcers such as:
- SVNDigger https://www.invicti.com/blog/web-security/svn-digger-better-lists-for-forced-browsing/

It will then attempt to discover directories and files that are reachable on the target web server.

NOTE: it’s useful to react to the output because, you may have to filter out more HTTP error codes in order to clean it up
"""

# User-Agent header is set to something innocuous
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:19.0) Gecko/20100101 Firefox/19.0"
}

target_url = "http://testphp.vulnweb.com"  # if you set up joomla on local in the previous project user http://127.0.0.1:4242
wordlist_path = "src/05_WEB_HACKERY/SVNDigger/all.txt"


def build_wordlist(wordlist_path):
    """
    Builds a Queue containing words from a wordlist file.

    Args:
        wordlist_path (str): Path to the wordlist file.

    Returns:
        Queue: A Queue containing words from the wordlist file.
    """
    # Open the wordlist file
    with open(wordlist_path, "rb") as fd:
        raw_words = fd.readlines()

    words = queue.Queue()
    # Iterate over each line in the wordlist file
    for word in raw_words:
        word = word.decode("utf-8").rstrip()
        # remove trailing newline
        words.put(word)
    return words


def build_attempt_list(wordlist_path):
    """
    Builds an attempt list based on words from a wordlist file.

    Args:
        wordlist_path (str): Path to the wordlist file.

    Returns:
        list: A list of attempts generated from the words in the wordlist file.
    """
    # Build the word queue
    word_queue = build_wordlist(wordlist_path)

    attempt_list = []
    while not word_queue.empty():
        attempt = word_queue.get()
        # check to see if there is a file extension or is a directory
        if "." not in attempt:
            attempt_list.append(f"/{attempt}/")
        else:
            attempt_list.append(f"/{attempt}")
    return attempt_list


def bruter(wordlist_path, target_url):
    """
    Performs URL brute force attacks using a wordlist on a target URL.

    Args:
        wordlist_path (str): Path to the wordlist file.
        target_url (str): The URL to target for the brute force attack.

    Returns:
        None
    """
    # build the list of url locations to attempt
    attempt_list = build_attempt_list(wordlist_path)

    for brute in attempt_list:
        # URL encode the brute force attempt
        # Ecample: url = f"{"http://example.com"}{urllib.parse.quote("directory with space")}" = "http://example.com/directory%20with%20space"
        url = f"{target_url}{urllib.parse.quote(brute)}"

        try:
            request = urllib.request.Request(url, headers=HEADERS)
            response = urllib.request.urlopen(request)
            # Print response code and URL
            if len(response.read()):
                print(f"[{response.code}] => {url}")

        except urllib.error.URLError as e:
            # Print error message along with response code and URL if is not a 404
            if hasattr(e, "code") and e.code != 404:
                print(f"!!! {e.code} => {url}")


# Start the brute-forcing
bruter(wordlist_path, target_url)
