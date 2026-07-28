import os
import re

d = "/home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/templates"
f_index = os.path.join(d, "index.html")

with open(f_index, "r") as f:
    content = f.read()

# Pattern for cards in index.html
pattern = r'<div class="bg-white/5 backdrop-blur-lg border border-white/10 rounded-3xl p-8 hover:bg-white/10 transition-all duration-300 group animate-slide-up delay-(\d+) hover:-translate-y-2">\s*<div class="w-14 h-14 rounded-2xl bg-([a-z]+)-500/20 flex items-center justify-center mb-6 group-hover:scale-110 transition shadow-lg">\s*<i data-lucide="([^"]+)" class="w-7 h-7 text-[a-z]+-400"><\/i>\s*<\/div>\s*<h3 class="text-white font-black text-xl mb-3 tracking-tight">([^<]+)<\/h3>\s*<p class="text-gray-300 text-sm font-medium leading-relaxed">([^<]+)<\/p>\s*<\/div>'

def replacer(m):
    delay = m.group(1)
    color = m.group(2)
    icon = m.group(3)
    title = m.group(4)
    text = m.group(5)
    
    return f'{{% include "components/public_card.html" with delay="{delay}" hover_up=True color="{color}" icon="{icon}" title="{title}" text="{text}" %}}'

new_content = re.sub(pattern, replacer, content)

with open(f_index, "w") as f:
    f.write(new_content)

print("index.html refactored to use public_card component.")
