import urllib.request as urllib2

# Fetching a raw page (no client-side language as JS is executed)
body = urllib2.urlopen("http://www.google.com")
print(f"\n{body.read()[:400]}...\n")

# Constructing the request object with custom headers
url = "http://www.google.com"
headers = {"User-Agent": "Googlebot"}

request = urllib2.Request(url, headers=headers)
response = urllib2.urlopen(request)

print(f"{response.read()[:400]}...\n")
response.close()
