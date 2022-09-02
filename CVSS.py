import sys
import time
from cvss import CVSS3

print('\n\033[30m'+"      ::::::::  :::     :::  ::::::::   ::::::::"+'\033[m')
print('\033[37m'+"    :+:    :+: :+:     :+: :+:    :+: :+:    :+:  "+'\033[m')
print('\033[37m'+"   +:+        +:+     +:+ +:+        +:+          "+'\033[m')
print('\033[37m'+"  +#+        +#+     +:+ +#++:++#++ +#++:++#++    "+'\033[m')
print('\033[37m'+" +#+         +#+   +#+         +#+        +#+     "+'\033[m')
print('\033[37m'+"#+#    #+#   #+#+#+#   #+#    #+# #+#    #+#      "+'\033[m')
print('\033[37m'+"########      ###      ########   ########   𝘷3   "+'\033[m')

def slowprint(s):
	for c in s + '\n':
		sys.stdout.write(c)
		sys.stdout.flush()
		time.sleep(1./30)
        
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

try: 
    # Attack Vector (AV)
    vectorValid = ["N", "A", "L", "P"]
    vector = input('\n\033[31m'+"Attack Vector (AV):"+'\033[m'"\n• Network  (N)\n• Adjacent (A)\n• Local    (L)\n• Physical (P)\n➜ ")
    if vector in vectorValid:
        av = vector

    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Attack Complexity (AC)
    complexityValid = ["L", "H"]
    complexity = input('\n\033[32m'+"Attack Complexity (AC):"+'\033[m'"\n• Low  (L)\n• High (H)\n➜ ")
    if complexity in complexityValid:
        ac = complexity

    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Privileges Required (PR)
    privilegesValid = ["N", "L", "H"]
    privileges = input('\n\033[33m'+"Privileges Required (PR):"+'\033[m'"\n• None (N)\n• Low  (L)\n• High (H)\n➜ ")
    if privileges in privilegesValid:
        pr = privileges

    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # User Interaction (UI)
    interactionValid = ["N", "R"]
    interaction = input('\n\033[35m'+"User Interaction (UI):"+'\033[m'"\n• None     (N)\n• Required (R)\n➜ ")
    if interaction in interactionValid:
        ui = interaction

    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Scope (S)
    scopeValid = ["U", "C"]
    scope = input('\n\033[36m'+"Scope (S):"+'\033[m'"\n• Unchanged (U)\n• Changed   (C)\n➜ ")
    if scope in scopeValid:
        s = scope

    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Confidentiality (C), Integrity (I), Availability (A)
    ciaValid = ["N", "L", "H"]

    c = input('\n\033[34m'+"Confidentiality (C):"+'\033[m'"\n• None (N)\n• Low  (L)\n• High (H)\n➜ ")
    i = input('\n\033[31m'+"Integrity (I):"+'\033[m'"\n• None (N)\n• Low  (L)\n• High (H)\n➜ ")
    a = input('\n\033[32m'+"Availability (A):"+'\033[m'"\n• None (N)\n• Low  (L)\n• High (H)\n➜ ")

    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Vulnerability Score
    vector = f'CVSS:3.0/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}'
    c = CVSS3(vector)
    print('\n\033[37m'+"Vulnerability Score:\n"+'\033[m' + f"• {c.base_score} ({c.severities()[0]})\n")

except:
    print('\n\033[37m'+"Value Error\nExiting...\n"+'\033[m')
    quit()
