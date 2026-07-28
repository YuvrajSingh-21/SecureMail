import os
import re

d = "/home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/templates"
f_contact = os.path.join(d, "public_contact.html")

with open(f_contact, "r") as f:
    content = f.read()

# Pattern for cards in public_contact.html
pattern = r'<div class="bg-white/5 backdrop-blur-lg border border-white/10 hover:bg-white/10 transition-all duration-300 group p-6 rounded-3xl text-center">\s*<div class="w-14 h-14 mx-auto rounded-2xl bg-([a-z]+)-500/20 flex items-center justify-center mb-6 group-hover:scale-110 transition shadow-lg text-[a-z]+-400"><i data-lucide="([^"]+)"><\/i><\/div>\s*<h3 class="text-white font-bold mb-2">([^<]+)<\/h3>\s*<p class="text-sm text-gray-400">([^<]+)<\/p>\s*<\/div>'

def replacer(m):
    color = m.group(1)
    icon = m.group(2)
    title = m.group(3)
    text = m.group(4)
    
    return f'{{% include "components/public_card.html" with center_text=True center_icon=True color="{color}" icon="{icon}" title="{title}" text="{text}" %}}'

new_content = re.sub(pattern, replacer, content)

with open(f_contact, "w") as f:
    f.write(new_content)

print("public_contact.html refactored to use public_card component.")
