from dataclasses import dataclass
from typing import List, Optional
from pathlib import Path
import socket
import posixpath
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SMB_DIALECT

@dataclass
class SMBResult:
    ip: str
    null_session: bool
    shares: List[str] = None
    readable_shares: List[str] = None
    error: str = None

def check_null_session(ip: str, username: str = None, password: str = None, timeout: int = 10) -> SMBResult:
    result = SMBResult(ip=ip, null_session=False)
    
    try:
        smb = SMBConnection(ip, ip, timeout=timeout)
        
        # Try provided credentials 
        if username is not None and password is not None:
            try:
                smb.login(username, password)
                result.null_session = False
            except SessionError:
                # Fall back to null session
                try:
                    smb.login('', '')
                    result.null_session = True
                except SessionError:
                    result.error = "Authentication failed"
                    return result
        else:
            # Original null session logic
            try:
                smb.login('', '')
                result.null_session = True
            except SessionError:
                result.error = "Null session failed"
                return result

        # Rest of the function remains the same
        try:
            shares = smb.listShares()
            result.shares = []
            result.readable_shares = []
            
            for share in shares:
                share_name = share['shi1_netname'][:-1]
                result.shares.append(share_name)
                
                try:
                    smb.listPath(share_name, '*')
                    result.readable_shares.append(share_name)
                except SessionError:
                    continue
                    
        except:
            result.error = "Could not list shares"

        smb.close()
        
    except socket.timeout:
        result.error = "Connection timed out"
    except ConnectionRefusedError:
        result.error = "Connection refused"
    except Exception as e:
        result.error = f"Error: {str(e)}"
        
    return result

def download_smb_content(ip: str, output_dir: str, share: str, username: str = None, password: str = None, max_size: int = 500*1024*1024) -> Optional[str]:
    try:
        smb = SMBConnection(ip, ip)
        if username and password:
            smb.login(username, password)
        else:
            smb.login('', '')

        base_path = Path(output_dir)
        base_path.mkdir(parents=True, exist_ok=True)
        print(f"Created directory: {base_path}")
        
        def download_recursive(share_name: str, remote_path: str, local_path: Path, depth: int = 0):
            indent = "  " * depth
            try:
                if remote_path:
                    search_path = posixpath.join(remote_path, '*')
                else:
                    search_path = '*'
                print(f"{indent}Scanning: {share_name}/{search_path}")
                
                files = smb.listPath(share_name, search_path)
                
                for f in files:
                    name = f.get_longname()
                    if name in ['.', '..']:
                        continue
                    
                    remote_file = posixpath.join(remote_path, name) if remote_path else name
                    local_file = local_path / name
                    
                    attrs = f.get_attributes()
                    is_directory = attrs & 0x10
                    
                    if is_directory:
                        print(f"{indent}Directory: {name}")
                        local_file.mkdir(exist_ok=True)
                        download_recursive(share_name, remote_file, local_file, depth + 1)
                    else:
                        size = f.get_filesize()
                        if size > max_size:
                            print(f"{indent}Skipping large file: {name} ({size/1024/1024:.1f}MB)")
                            continue
                        
                        print(f"{indent}File: {name} ({size/1024/1024:.1f}MB)")
                        try:
                            with open(local_file, 'wb') as file_obj:
                                smb.getFile(share_name, remote_file, file_obj.write)
                            print(f"{indent}✓ Downloaded: {name}")
                        except Exception as e:
                            print(f"{indent}Failed to download: {str(e)}")
                                
            except Exception as e:
                print(f"{indent}Error accessing {remote_path}: {str(e)}")
        
        # Start recursive download
        download_recursive(share, '', base_path)
        smb.close()
        return None
        
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    print("\nSMB Share Enumeration")
    print("==================")
    
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
        
        # Check SMB access
        print(f"\nChecking SMB access on {ip}...")
        result = check_null_session(ip, username, password)
        
        if result.error:
            print(f"Error: {result.error}")
            return
            
        if result.shares:
            print("\nDetected shares:")
            for share in result.shares:
                readable = "[READABLE]" if share in result.readable_shares else ""
                print(f"  {share} {readable}")
            
            if result.readable_shares:
                choice = input("\nDownload content from readable shares? (y/N): ").lower()
                if choice == 'y':
                    for share in result.readable_shares:
                        print(f"\nDownloading from share: {share}")
                        output_dir = f"enumeration_results/{ip}/smb/{share}"
                        error = download_smb_content(ip, output_dir, share, username, password)
                        if error:
                            print(f"Error downloading from {share}: {error}")
                        else:
                            print(f"Successfully downloaded content from {share}")
        else:
            print("No shares found")
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")

if __name__ == "__main__":
    main()