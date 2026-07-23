import re

with open('SecureMail/templates/components/sidebar.html', 'r') as f:
    content = f.read()

# Change w-64 to w-[260px] and add ID
content = content.replace('class="w-64 shrink-0', 'id="main-sidebar" class="w-[260px] shrink-0')
content = content.replace('transition-all duration-300"', 'transition-[width] duration-300 ease-in-out z-20"')

# Compose button
content = content.replace(
    '<a href="{% url \'compose\' %}" class="w-full flex items-center justify-center gap-3',
    '<a href="{% url \'compose\' %}" title="Compose" class="w-full flex items-center justify-center gap-3'
)
content = content.replace('Compose\n    </a>', '<span class="sidebar-text transition-opacity duration-300 whitespace-nowrap">Compose</span>\n    </a>')

# Items
nav_items = ['Inbox', 'Starred', 'Important', 'Sent', 'Drafts', 'Spam', 'Trash', 'Overview', 'Analytics', 'Settings', 'About', 'Contact Us']

for item in nav_items:
    # Add title attribute to the a tag
    content = re.sub(
        r'(<a href="[^"]+" class="sidebar-item [^"]+" data-nav="[^"]+")>',
        f'\\1 title="{item}">',
        content
    )
    # Wrap text in sidebar-text
    content = re.sub(
        f'<span class="text-\\[13px\\] font-bold flex-1">{item}</span>',
        f'<span class="sidebar-text text-[13px] font-bold flex-1 whitespace-nowrap transition-opacity duration-300">{item}</span>',
        content
    )
    content = re.sub(
        f'<span class="text-\\[13px\\] font-bold">{item}</span>',
        f'<span class="sidebar-text text-[13px] font-bold whitespace-nowrap transition-opacity duration-300">{item}</span>',
        content
    )

# Badges
content = re.sub(
    r'(<span class="text-\[10px\] px-2 py-0\.5 rounded-full [^"]+ font-bold( or black)?>\{\{ [^\}]+ \}\}<\/span>)',
    r'<span class="sidebar-text">\1</span>',
    content
)
# Wait, some badges have font-black
content = re.sub(
    r'(<span class="text-\[10px\] px-2 py-0\.5 rounded-full [^"]+ font-black">\{\{ [^\}]+ \}\}<\/span>)',
    r'<div class="sidebar-text">\1</div>',
    content
)
content = re.sub(
    r'(<span class="text-\[10px\] px-2 py-0\.5 rounded-full [^"]+ font-bold">\{\{ [^\}]+ \}\}<\/span>)',
    r'<div class="sidebar-text">\1</div>',
    content
)

# Cyber Intelligence text
content = content.replace(
    '<p class="text-[10px] font-black text-gray-400 dark:text-gray-500 uppercase tracking-widest mb-4 px-3">Cyber Intelligence</p>',
    '<p class="sidebar-text text-[10px] font-black text-gray-400 dark:text-gray-500 uppercase tracking-widest mb-4 px-3 whitespace-nowrap transition-opacity duration-300">Cyber Intelligence</p>'
)

# Security Health Widget
content = content.replace(
    '<!-- Security Health Widget -->',
    '<!-- Security Health Widget -->\n    <div class="sidebar-text transition-opacity duration-300">'
)
content = content.replace(
    '</div>\n</aside>',
    '</div>\n    </div>\n</aside>'
)

# Add JS script at the bottom of sidebar.html
js_script = """
<script>
function toggleSidebar() {
    const sidebar = document.getElementById('main-sidebar');
    const isCollapsed = sidebar.classList.contains('w-[72px]');
    
    if (isCollapsed) {
        // Expand
        sidebar.classList.remove('w-[72px]');
        sidebar.classList.add('w-[260px]');
        document.querySelectorAll('.sidebar-text').forEach(el => {
            el.style.display = '';
            setTimeout(() => el.style.opacity = '1', 50);
        });
        localStorage.setItem('sidebarCollapsed', 'false');
    } else {
        // Collapse
        sidebar.classList.remove('w-[260px]');
        sidebar.classList.add('w-[72px]');
        document.querySelectorAll('.sidebar-text').forEach(el => {
            el.style.opacity = '0';
            setTimeout(() => el.style.display = 'none', 300);
        });
        localStorage.setItem('sidebarCollapsed', 'true');
    }
}

// Apply state immediately
(function() {
    if (localStorage.getItem('sidebarCollapsed') === 'true') {
        const sidebar = document.getElementById('main-sidebar');
        sidebar.classList.remove('w-[260px]');
        sidebar.classList.add('w-[72px]');
        document.querySelectorAll('.sidebar-text').forEach(el => {
            el.style.display = 'none';
            el.style.opacity = '0';
        });
    }
})();
</script>
"""
content += js_script

with open('SecureMail/templates/components/sidebar.html', 'w') as f:
    f.write(content)

