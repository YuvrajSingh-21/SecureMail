import os
import re

d = "/home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/templates"
for root, dirs, files in os.walk(d):
    for f in files:
        if f.endswith(".html"):
            path = os.path.join(root, f)
            with open(path, "r") as fh:
                c = fh.read()
            
            # Replace {% url "public_name" %} with {% url "name" %}
            c = re.sub(r"{%\s*url\s+['\"]public_([^'\"]+)['\"]\s*%}", r"{% url '\1' %}", c)
            
            with open(path, "w") as fh:
                fh.write(c)
print("Fixed URL names in templates")
