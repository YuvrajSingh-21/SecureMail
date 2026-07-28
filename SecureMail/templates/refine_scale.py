import os
import re

d = "/home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/templates"

# 1. Update public_card.html to support variables
f_card = os.path.join(d, "components/public_card.html")
with open(f_card, "r") as f:
    card = f.read()

card = card.replace('p-8', 'p-{{ padding|default:"8" }}')
card = card.replace('w-14 h-14', 'w-{{ icon_size|default:"14" }} h-{{ icon_size|default:"14" }}')
card = card.replace('w-7 h-7', 'w-{{ icon_inner|default:"7" }} h-{{ icon_inner|default:"7" }}')

# Also revert the glassmorphism strictly to landing page's since user said "Use the exact glassmorphism used on the Landing Page... The Landing Page is still the reference."
# But wait, they also said "Increase depth using: backdrop blur...". 
# The card currently is: bg-white/10 backdrop-blur-2xl border border-white/20 shadow-2xl shadow-black/50 shadow-[inset_0_1px_1px_rgba(255,255,255,0.2)]
# Let's keep the depth but make sure the sizing is right.

with open(f_card, "w") as f:
    f.write(card)

# 2. Update public_contact.html
f_contact = os.path.join(d, "public_contact.html")
with open(f_contact, "r") as f:
    contact = f.read()

# Fix sizing in contact page
contact = contact.replace('px-6 pt-20 pb-32', 'px-6 pt-16 pb-20')
contact = contact.replace('text-4xl md:text-6xl', 'text-4xl md:text-5xl')

# Pass padding="6" and icon_size="12" icon_inner="5" to public_card in contact
contact = re.sub(
    r'{% include "components/public_card.html" with center_text=True center_icon=True',
    r'{% include "components/public_card.html" with padding="6" icon_size="12" icon_inner="6" center_text=True center_icon=True',
    contact
)

# Fix contact form inputs with !important modifiers
old_input = r'bg-[#0f172a]/65 backdrop-blur-xl border border-white/\[\.08\] rounded-2xl px-5 py-4 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:bg-\[#0f172a\]/80 focus:ring-4 focus:ring-blue-500/20 shadow-\[inset_0_2px_4px_rgba\(0,0,0,0\.3\)\] transition-all duration-300'
new_input = '!bg-[#0f172a]/65 backdrop-blur-xl !border !border-white/[.08] rounded-2xl px-5 py-4 !text-white !placeholder-white/45 focus:!outline-none focus:!border-blue-500 focus:!bg-[#0f172a]/80 focus:!ring-4 focus:!ring-blue-500/20 shadow-[inset_0_2px_4px_rgba(0,0,0,0.3)] transition-all duration-300'
contact = re.sub(old_input, new_input, contact)

with open(f_contact, "w") as f:
    f.write(contact)


# 3. Update public_about.html
f_about = os.path.join(d, "public_about.html")
with open(f_about, "r") as f:
    about = f.read()

about = about.replace('px-6 pt-20 pb-32', 'px-6 pt-16 pb-24')
about = about.replace('text-4xl md:text-6xl', 'text-4xl md:text-5xl')
about = about.replace('text-3xl md:text-5xl', 'text-3xl md:text-4xl')

# Add padding="6" to Core Pillars cards
about = re.sub(
    r'{% include "components/public_card.html" with color=',
    r'{% include "components/public_card.html" with padding="6" icon_size="12" icon_inner="6" color=',
    about
)

# Shrink the manually written cards padding (Why & How, Roadmap) from p-8 md:p-12 to p-8
about = about.replace('p-8 md:p-12', 'p-8')

with open(f_about, "w") as f:
    f.write(about)

print("Scale and forms refined")
