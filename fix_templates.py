import os
import re

base_dir = '/home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/templates/'
for root, dirs, files in os.walk(base_dir):
    for file in files:
        if file.endswith('.html'):
            path = os.path.join(root, file)
            with open(path, 'r') as f:
                content = f.read()

            new_content = content
            # Fix double {% {%
            new_content = new_content.replace('{% {%', '{%')
            new_content = new_content.replace('{%{%', '{%')
            
            # Now carefully find any "else %}" or "endif %}" that is NOT preceded by "{%"
            # A safe way is to find all "else %}" and see what precedes it.
            # Actually, let's just use regex to replace anything that looks like:
            # [^%\{\s]\s+else\s*%\} -> add {% 
            # Or simpler:
            new_content = re.sub(r'(?<!\{%)\s*else\s*%\}', ' {% else %}', new_content)
            new_content = re.sub(r'(?<!\{%)\s*endif\s*%\}', ' {% endif %}', new_content)
            new_content = re.sub(r'(?<!\{%)\s*empty\s*%\}', ' {% empty %}', new_content)

            # Wait, if we just run that regex again, it will match `{% else %}` because `(?<!\{%)` looks back strictly at the immediate previous characters.
            # In `{% else %}`, the characters before `else` are `{% `.
            # The negative lookbehind `(?<!\{%)` looks 2 chars back. It does NOT ignore spaces!
            # So `{% else %}` is preceded by ` ` and `%`, so `(?<!\{%)` matches! And it replaces it!
            # We need to use a better regex.
            pass

            # Let's fix this manually using string replacement for safety
            
            # 1. Clean up ALL double braces first
            for _ in range(3):
                new_content = new_content.replace('{% {%', '{%').replace('{%  {%', '{%').replace('{ %', '{%')
            
            # 2. Fix the specific broken classes from earlier dark mode strip
            # The strip left things like: `text-blue-600  else %}text-[var(--sys`
            # We can find `else %}` and ensure it is `{% else %}`
            
            # Split by `else %}`
            parts = new_content.split('else %}')
            if len(parts) > 1:
                rebuilt = parts[0]
                for p in parts[1:]:
                    if not rebuilt.strip().endswith('{%'):
                        rebuilt += '{% else %}' + p
                    else:
                        rebuilt += 'else %}' + p
                new_content = rebuilt
                
            parts = new_content.split('endif %}')
            if len(parts) > 1:
                rebuilt = parts[0]
                for p in parts[1:]:
                    if not rebuilt.strip().endswith('{%'):
                        rebuilt += '{% endif %}' + p
                    else:
                        rebuilt += 'endif %}' + p
                new_content = rebuilt
                
            parts = new_content.split('empty %}')
            if len(parts) > 1:
                rebuilt = parts[0]
                for p in parts[1:]:
                    if not rebuilt.strip().endswith('{%'):
                        rebuilt += '{% empty %}' + p
                    else:
                        rebuilt += 'empty %}' + p
                new_content = rebuilt
                
            # Final cleanup of any `{% {%` that might have resulted
            for _ in range(3):
                new_content = new_content.replace('{% {%', '{%').replace('{%{%', '{%')

            if new_content != content:
                with open(path, 'w') as f:
                    f.write(new_content)

