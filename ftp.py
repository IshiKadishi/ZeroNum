from dataclasses import dataclass
from ftplib import FTP, error_perm
from typing import List, Optional
from pathlib import Path
import socket

@dataclass
class FTPResult:
    ip: str
    anonymous_access: bool
    banner: str = None
    directories: List[str] = None
    error: str = None

def check_anonymous_login(ip: str, username: str = None, password: str = None, timeout: int = 10) -> FTPResult:
    result = FTPResult(ip=ip, anonymous_access=False)
    try:
        with FTP(timeout=timeout) as ftp:
            ftp.connect(ip, 21)
            result.banner = ftp.getwelcome()

            # Try provided credentials first if supplied
            if username is not None and password is not None:
                try:
                    ftp.login(user=username, passwd=password)
                    result.anonymous_access = False  # Not anonymous if using credentials
                    try:
                        result.directories = ftp.nlst()
                    except Exception:
                        result.error = "Could not get directories"
                    return result
                except error_perm:
                    pass  # Fall through to anonymous attempts

            # Try anonymous login methods as fallback
            login_attempts = [
                ('anonymous', ''),
                ('anonymous', 'anonymous')
            ]

            for anon_user, anon_pass in login_attempts:
                try:
                    ftp.login(user=anon_user, passwd=anon_pass)
                    result.anonymous_access = True
                    try:
                        result.directories = ftp.nlst()
                    except Exception:
                        result.error = "Could not get directories"
                    return result
                except error_perm:
                    continue

            result.error = "Authentication failed"

    except socket.timeout:
        result.error = "Connection timed out"
    except ConnectionRefusedError:
        result.error = "Connection refused"
    except Exception as e:
        result.error = f"Error: {str(e)}"

    return result

def get_file_size(ftp: FTP, filename: str) -> int:
    try:
        return ftp.size(filename)
    except:
        return 0

def download_ftp_content(ip: str, output_dir: str, username: str, password: str, timeout: int = 10, max_size: int = 500*1024*1024) -> Optional[str]:
    try:
        with FTP(timeout=timeout) as ftp:
            ftp.connect(ip, 21)
            ftp.login(user=username, passwd=password)
            
            base_path = Path(output_dir)
            base_path.mkdir(parents=True, exist_ok=True)
            
            def download_recursive(current_path: str, local_path: Path):
                items = []
                ftp.dir(current_path, items.append)
                
                for item in items:
                    parts = item.split()
                    name = " ".join(parts[8:])
                    
                    if name in ('.', '..'):
                        continue
                        
                    remote_path = f"{current_path}/{name}"
                    item_path = local_path / name
                    
                    if item.startswith('d'):
                        print(f"Creating directory: {item_path}")
                        item_path.mkdir(exist_ok=True)
                        download_recursive(remote_path, item_path)
                    else:
                        file_size = get_file_size(ftp, remote_path)
                        if file_size > max_size:
                            print(f"Skipping large file {remote_path} ({file_size/1024/1024:.1f}MB)")
                            continue
                            
                        print(f"Downloading: {remote_path} ({file_size/1024/1024:.1f}MB)")
                        with open(item_path, 'wb') as f:
                            ftp.retrbinary(f'RETR {remote_path}', f.write)
            
            download_recursive('', base_path)
            return None
            
    except Exception as e:
        return f"Error: {str(e)}"
    

def main():
    print("\nFTP Service Enumeration")
    print("=====================")
    
    try:
        # Get target IP
        ip = input("\nEnter target IP: ").strip()
        
        # Optional credentials
        use_creds = input("Use credentials? (y/N): ").lower() == 'y'
        username = None
        password = None
        if use_creds:
            username = input("Username: ").strip()
            password = input("Password: ").strip()
        
        # Check FTP access
        print(f"\nChecking FTP access on {ip}...")
        result = check_anonymous_login(ip, username, password)
        
        if result.error:
            print(f"Error: {result.error}")
            return
            
        if result.banner:
            print(f"\nBanner: {result.banner}")
            
        if result.anonymous_access:
            print("\nAnonymous login successful!")
        elif username:
            print("\nAuthenticated login successful!")
            
        if result.directories:
            print("\nAccessible directories:")
            for dir in result.directories:
                print(f"  {dir}")
                
            choice = input("\nDownload accessible content? (y/N): ").lower()
            if choice == 'y':
                output_dir = f"enumeration_results/{ip}/ftp"
                error = download_ftp_content(ip, output_dir, username or 'anonymous', password or '')
                if error:
                    print(f"Error downloading content: {error}")
                else:
                    print(f"\nSuccessfully downloaded content to {output_dir}")
        else:
            print("No accessible directories found")
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")

if __name__ == "__main__":
    main()
           