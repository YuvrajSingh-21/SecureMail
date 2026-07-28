import os
import re

d = "/home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/templates"

files = [
    "public_contact.html",
    "public_about.html",
    "public_support.html",
    "public_privacy.html",
    "public_terms.html",
    "public_disclosure.html",
    "public_cookie.html",
]

for f in files:
    path = os.path.join(d, f)
    with open(path, "r") as fh:
        c = fh.read()
    
    # Hero spacing
    c = c.replace('px-6 pt-20 pb-32', 'px-6 pt-16 pb-20')
    
    # Hero heading size
    c = c.replace('text-4xl md:text-6xl', 'text-4xl md:text-5xl')
    
    # Section heading size
    c = c.replace('text-3xl md:text-5xl', 'text-3xl md:text-4xl')
    
    with open(path, "w") as fh:
        fh.write(c)

print("Global scale refined")
