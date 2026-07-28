import os
import re

d = "/home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/templates"

# 1. Update public_contact.html inputs
f_contact = os.path.join(d, "public_contact.html")
with open(f_contact, "r") as f:
    c = f.read()

old_input_class = r'bg-white/5 border border-white/10 rounded-2xl px-4 py-3 text-white focus:outline-none focus:border-blue-500 focus:bg-white/10 transition-all placeholder-gray-500'
new_input_class = 'bg-[#0f172a]/65 backdrop-blur-xl border border-white/[.08] rounded-2xl px-5 py-4 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:bg-[#0f172a]/80 focus:ring-4 focus:ring-blue-500/20 shadow-[inset_0_2px_4px_rgba(0,0,0,0.3)] transition-all duration-300'

c = c.replace(old_input_class, new_input_class)

# The form card itself in contact should also use the premium card style?
# Wait, I already updated `public_card.html`, but the contact form card is manually written in `public_contact.html`!
# Let's fix the contact form card's outer div too!
# Currently: <div class="bg-white/5 backdrop-blur-lg border border-white/10 hover:bg-white/10 transition-all duration-300 group p-8 rounded-3xl">
# Update to match public_card.html:
old_card_class = r'bg-white/5 backdrop-blur-lg border border-white/10 hover:bg-white/10 transition-all duration-300 group p-8 rounded-3xl'
new_card_class = 'bg-white/10 backdrop-blur-2xl border border-white/20 shadow-2xl shadow-black/50 shadow-[inset_0_1px_1px_rgba(255,255,255,0.2)] rounded-3xl p-8'
c = c.replace(old_card_class, new_card_class)

with open(f_contact, "w") as f:
    f.write(c)


# 2. Update public_about.html spacing
f_about = os.path.join(d, "public_about.html")
with open(f_about, "r") as f:
    c = f.read()

# Reduce empty space: space-y-16 -> space-y-12
c = c.replace('space-y-16', 'space-y-12')
# Change gap-12 -> gap-8
c = c.replace('gap-12', 'gap-8')

# The "Why & How We Do It" section and "Roadmap" section are not using `public_card.html`, they are manually written.
# Let's update them to match the new card styling.
c = re.sub(
    r'bg-white/5 backdrop-blur-lg border border-white/10 hover:bg-white/10 transition-all duration-300 group (p-8 md:p-12|p-8) rounded-3xl',
    r'bg-white/10 backdrop-blur-2xl border border-white/20 shadow-2xl shadow-black/50 shadow-[inset_0_1px_1px_rgba(255,255,255,0.2)] hover:bg-white/15 hover:border-white/30 transition-all duration-500 group \1 rounded-3xl',
    c
)

with open(f_about, "w") as f:
    f.write(c)

print("Polished UI")
