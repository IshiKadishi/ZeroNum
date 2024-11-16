import argparse
import sys
from services.portscan import port_scan, parse_services_file, is_valid_ipv4
from services.ftp import check_anonymous_login, download_ftp_content
from services.smb import check_null_session, download_smb_content
def banner():
    print(r"""
    ============================
              ZeroNum 
    ============================
    """)

if __name__ == "__main__":
    banner()
    
    parser = argparse.ArgumentParser(description="ZeroNum - Enumeration Tool")
    parser.add_argument('target', help="Target IPv4 address")
    parser.add_argument('-u', '--username', help="Username for authentication")
    parser.add_argument('-p', '--password', help="Password for authentication")
    parser.add_argument('--get-all', action='store_true', help="Download all accessible content")
    args = parser.parse_args()
    
    if not is_valid_ipv4(args.target):
        print(f"Error: '{args.target}' is not a valid IPv4 address.")
        sys.exit(1)
        
    ports_list, ports_services = parse_services_file('services/services.txt')
    scan_results = port_scan(args.target, ports_services)
    
    # Check for FTP (port 21)
    ftp_results = [r for r in scan_results if r.port == 21 and r.state == "open"]
    
    if ftp_results:
        print("\nFTP service detected!")
        ftp_result = check_anonymous_login(args.target, args.username, args.password)
        
        if ftp_result.error:
            print(f"FTP Error: {ftp_result.error}")
        else:
            if ftp_result.anonymous_access:
                print("Anonymous FTP access available!")
            elif args.username:
                print("Authenticated FTP access successful!")
                
            if ftp_result.directories:
                print("\nAccessible directories:")
                for dir in ftp_result.directories:
                    print(f"  {dir}")
                    
                if args.get_all:
                    output_dir = f"enumeration_results/{args.target}/ftp"
                    error = download_ftp_content(args.target, output_dir, 
                                               args.username or 'anonymous', 
                                               args.password or '')
                    if error:
                        print(f"Download error: {error}")
    
# Check for SMB (ports 139 and 445)
    smb_results = [r for r in scan_results if r.port in [139, 445] and r.state == "open"]
    
    if smb_results:
        print("\nSMB service detected!")
        smb_result = check_null_session(args.target, args.username, args.password)
        
        if smb_result.error:
            print(f"SMB Error: {smb_result.error}")
        else:
            if smb_result.null_session:
                print("Null session access available!")
            elif args.username:
                print("Authenticated SMB access successful!")
                
            if smb_result.shares:
                print("\nDetected shares:")
                for share in smb_result.shares:
                    readable = "[READABLE]" if share in smb_result.readable_shares else ""
                    print(f"  {share} {readable}")
                
                if args.get_all and smb_result.readable_shares:
                    print("\nDownloading from readable shares...")
                    for share in smb_result.readable_shares:
                        print(f"\nAccessing share: {share}")
                        output_dir = f"enumeration_results/{args.target}/smb/{share}"
                        error = download_smb_content(
                            ip=args.target,
                            output_dir=output_dir,
                            share=share,
                            username=args.username or '',
                            password=args.password or '',
                            max_size=500*1024*1024
                        )
                        if error:
                            print(f"Error downloading from {share}: {error}")