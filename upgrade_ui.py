import os
import re

d = "/home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/templates"
files = [
    "public_about.html", 
    "public_contact.html", 
    "public_privacy.html", 
    "public_terms.html", 
    "public_disclosure.html", 
    "public_cookie.html", 
    "public_support.html"
]

for f in files:
    p = os.path.join(d, f)
    with open(p, "r") as fh:
        c = fh.read()

    # 1. Update the main container max-width to match landing page
    c = c.replace('class="max-w-4xl mx-auto px-6 pt-20 pb-32"', 'class="max-w-7xl mx-auto px-6 pt-20 pb-32"')
    
    # 2. Update typography hierarchy
    # H1 Hero
    c = re.sub(
        r'class="text-4xl md:text-5xl font-black text-white mb-4"|class="text-5xl md:text-6xl font-black text-white mb-6"',
        'class="text-4xl md:text-6xl font-black text-white leading-tight mb-6"',
        c
    )
    # Subtitle Hero
    c = re.sub(
        r'class="text-lg text-gray-400"|class="text-xl text-gray-400"',
        'class="text-lg text-gray-200 mb-8 max-w-2xl mx-auto font-medium"',
        c
    )
    # H2 Section Titles
    c = c.replace('class="text-3xl font-bold text-white mb-8 text-center"', 'class="text-3xl md:text-5xl font-black text-white mb-12 text-center tracking-tight"')
    c = c.replace('class="text-2xl font-bold text-white mb-4"', 'class="text-white font-black text-xl mb-3 tracking-tight"')

    # 3. Update Glass Cards
    # Landing page card: bg-white/5 backdrop-blur-lg border border-white/10 rounded-3xl p-8 hover:bg-white/10 transition-all duration-300 group
    # We will replace glass-card with the full utility list
    c = re.sub(
        r'class="glass-card ([^"]*)"',
        r'class="bg-white/5 backdrop-blur-lg border border-white/10 hover:bg-white/10 transition-all duration-300 group \1"',
        c
    )
    # Ensure rounded-3xl is present (if it had rounded-2xl or rounded-3xl we can standardize it)
    c = re.sub(r'rounded-2xl', 'rounded-3xl', c)
    # wait, inputs also use rounded-2xl or rounded-xl, I should be careful.
    
    # 4. Update Icon Containers
    # from: w-12 h-12 bg-blue-500/20 text-blue-400 rounded-xl flex items-center justify-center mb-6
    # to: w-14 h-14 rounded-2xl bg-blue-500/20 flex items-center justify-center mb-6 group-hover:scale-110 transition shadow-lg (and text-color on the icon)
    
    # Let's do a regex for the icon containers
    def icon_replacer(match):
        color = match.group(1) # e.g. blue
        return f'w-14 h-14 rounded-2xl bg-{color}-500/20 flex items-center justify-center mb-6 group-hover:scale-110 transition shadow-lg text-{color}-400'
        
    c = re.sub(r'w-12 h-12 (?:mx-auto )?bg-([a-z]+)-500/20 text-[a-z]+-400 rounded-(?:xl|full) flex items-center justify-center mb-(?:4|6)', icon_replacer, c)
    
    # Also fix mx-auto for contact page icons
    c = c.replace('w-14 h-14 rounded-2xl', 'w-14 h-14 mx-auto rounded-2xl') # This might apply to all, which is fine for centered cards

    # 5. Buttons
    c = re.sub(
        r'class="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-4 rounded-xl transition-colors shadow-lg shadow-blue-500/25"',
        'class="w-full px-8 py-4 bg-gradient-to-r from-blue-600 to-cyan-500 hover:from-blue-700 hover:to-cyan-600 text-white rounded-2xl font-black transition transform hover:scale-[1.02] text-center shadow-xl shadow-blue-500/30"',
        c
    )

    # 6. Inputs (Contact Page)
    # bg-gray-800 border border-gray-700 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-blue-500 transition-colors
    c = re.sub(
        r'bg-gray-800 border border-gray-700 rounded-(?:xl|3xl) px-4 py-3 text-white focus:outline-none focus:border-blue-500 transition-colors',
        'bg-white/5 border border-white/10 rounded-2xl px-4 py-3 text-white focus:outline-none focus:border-blue-500 focus:bg-white/10 transition-all placeholder-gray-500',
        c
    )
    
    with open(p, "w") as fh:
        fh.write(c)

print("Upgraded design system")
