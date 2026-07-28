import os
import re

d = "/home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/templates"
f_about = os.path.join(d, "public_about.html")

with open(f_about, "r") as f:
    content = f.read()

# Pattern for Mission & Vision cards
p1 = r'<div class="bg-white/5 backdrop-blur-lg border border-white/10 hover:bg-white/10 transition-all duration-300 group p-8 rounded-3xl border-([a-z]+)-500/30">\s*<div class="w-14 h-14 mx-auto rounded-2xl bg-[a-z]+-500/20 flex items-center justify-center mb-6 group-hover:scale-110 transition shadow-lg text-[a-z]+-400"><i data-lucide="([^"]+)"><\/i><\/div>\s*<h2 class="text-white font-black text-xl mb-3 tracking-tight">([^<]+)<\/h2>\s*<p class="text-gray-400 leading-relaxed">([^<]+)<\/p>\s*<\/div>'
def rep1(m):
    color, icon, title, text = m.group(1), m.group(2), m.group(3), m.group(4)
    # the original had border-color-500/30, we can pass it as extra_classes
    return f'{{% include "components/public_card.html" with center_text=True center_icon=True color="{color}" icon="{icon}" title="{title}" text="{text}" extra_classes="border-{color}-500/30" %}}'
content = re.sub(p1, rep1, content)

# Pattern for Core Pillars cards
p2 = r'<div class="bg-white/5 backdrop-blur-lg border border-white/10 hover:bg-white/10 transition-all duration-300 group p-6 rounded-3xl">\s*<i data-lucide="([^"]+)" class="text-([a-z]+)-400 mb-4 w-8 h-8"><\/i>\s*<h4 class="text-lg font-bold text-white mb-2">([^<]+)<\/h4>\s*<p class="text-sm text-gray-400">([^<]+)<\/p>\s*<\/div>'
def rep2(m):
    icon, color, title, text = m.group(1), m.group(2), m.group(3), m.group(4)
    return f'{{% include "components/public_card.html" with color="{color}" icon="{icon}" title="{title}" text="{text}" %}}'
content = re.sub(p2, rep2, content)

with open(f_about, "w") as f:
    f.write(content)

print("public_about.html refactored.")
