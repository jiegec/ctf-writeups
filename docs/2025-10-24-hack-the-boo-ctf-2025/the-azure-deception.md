# The Azure Deception

```
Shortly after the Door Without Handles began moving, someone sent Brynn a taunting message through the council's communication channels. It appeared to come from Microsoft's own security team—the address read azuresecuritycenter@onmicrosoft.com—but the words dripped with mockery: "It looks like you fell for it… Again. Not every onmicrosoft.com is official ;)". The domain seemed legitimate at first—onmicrosoft.com is genuine Microsoft territory—yet Brynn knows deception when she sees it. Someone is wearing a trusted mask. She must investigate this exact address through shadow-intelligence archives, identify which ghost organization has weaponized this Microsoft domain in past hauntings, and determine which named operation previously used this specific false identity to breach their victims. Even the most official-looking doors can lead to hollowed places.Flag Format: HTB{Operation_Name} Example (Fictional): HTB{Operation_Midnight} Important: Use underscore _ between words Capitalize first letter of each word Include "Operation" if it's part of the name
```

Ask Claude to find answer:

```
I need to investigate the suspicious email address `azuresecuritycenter@onmicrosoft.com` to identify which threat actor or APT group has used this specific domain for malicious operations.

Let me search for information about this specific email address and its use in cyber operations.Let me search more specifically for the azuresecuritycenter@onmicrosoft.com email address and phishing campaigns.Excellent! I found the key information. Let me search for the specific operation name associated with this Microsoft Teams phishing campaign.Perfect! I've found clear evidence that Midnight Blizzard used azuresecuritycenter.onmicrosoft.com as one of their fake domains in their Microsoft Teams phishing campaign. Now let me search for specific operation names associated with Midnight Blizzard's activities.I'm finding that Midnight Blizzard/APT29/NOBELIUM conducted these phishing campaigns, but I need to find the specific operation name. Let me search for more specific operation names related to their campaigns.I found a reference to "OPERATION GHOST" in the MITRE ATT&CK documentation. Let me search for more specific information about this operation.Perfect! I found it. However, I notice that the Microsoft Teams phishing campaign with azuresecuritycenter.onmicrosoft.com is separate from Operation Ghost. Let me verify if there's a specific operation name for the Microsoft Teams phishing campaign, or if it's just part of general Midnight Blizzard/NOBELIUM activities.Based on my research, I found that azuresecuritycenter.onmicrosoft.com was used by Midnight Blizzard (also known as APT29, NOBELIUM, and Cozy Bear) in their Microsoft Teams phishing campaign. However, the Microsoft security blog and other sources don't assign a specific "Operation" name to this particular Microsoft Teams phishing campaign from 2023.

The challenge mentions looking for "which named operation previously used this specific false identity." Let me search if there's documentation linking this specific domain to a named operation.Let me reconsider the context. This appears to be a CTF challenge. The most well-documented APT29/Midnight Blizzard operation I've found is "Operation Ghost" which was a long-running campaign by APT29. However, that operation (2013-2019) preceded the Microsoft Teams phishing campaign (2023) that used azuresecuritycenter.onmicrosoft.com.

Since the challenge asks for the operation name in the format HTB{Operation_Name}, and considering:
1. The threat actor is clearly Midnight Blizzard/APT29/NOBELIUM
2. The specific email address azuresecuritycenter@onmicrosoft.com was used in their phishing campaigns
3. "Operation Ghost" is the most prominent named operation associated with APT29

The answer is likely: **HTB{Operation_Ghost}**
```

Flag: `HTB{Operation_Ghost}`.
