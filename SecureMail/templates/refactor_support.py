import os
import re

d = "/home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/templates"
f_support = os.path.join(d, "public_support.html")

with open(f_support, "r") as f:
    c = f.read()

# Fix icon wrappers to match w-14 h-14 rounded-2xl bg-{color}-500/20 ... text-{color}-400
# Pattern: w-12 h-12 bg-([a-z]+)-500/10 rounded-3xl flex items-center justify-center mb-4 text-([a-z]+)-400 group-hover:scale-110 transition-transform
# Exception for the white one: w-12 h-12 bg-white/10 rounded-3xl ... text-white
p1 = r'w-12 h-12 bg-([a-z]+)-500/10 rounded-3xl flex items-center justify-center mb-4 text-[a-z]+-400 group-hover:scale-110 transition-transform'
c = re.sub(p1, r'w-14 h-14 rounded-2xl bg-\1-500/20 flex items-center justify-center mb-6 group-hover:scale-110 transition shadow-lg text-\1-400', c)

p2 = r'w-12 h-12 bg-white/10 rounded-3xl flex items-center justify-center mb-4 text-white group-hover:scale-110 transition-transform'
c = re.sub(p2, 'w-14 h-14 rounded-2xl bg-white/10 flex items-center justify-center mb-6 group-hover:scale-110 transition shadow-lg text-white', c)

# Ensure container is max-w-7xl
c = c.replace('class="max-w-6xl mx-auto px-6 pt-20 pb-32"', 'class="max-w-7xl mx-auto px-6 pt-20 pb-32"')

with open(f_support, "w") as f:
    f.write(c)

print("public_support.html refactored.")
