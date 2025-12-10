#!/usr/bin/env python3
"""
iCloud Email Spam Analyzer
Connects to iCloud Mail via IMAP and analyzes emails for spam patterns
"""

import imaplib
import email
from email.header import decode_header
import json
from datetime import datetime, timedelta
import re
import os

def get_password():
    """Read app-specific password from temp file"""
    try:
        with open(os.path.expanduser("~/.icloud_pass_temp"), "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        print("Error: Password file not found at ~/.icloud_pass_temp")
        return None

def decode_header_value(header_value):
    """Safely decode email header values"""
    if header_value is None:
        return ""
    if isinstance(header_value, str):
        return header_value
    if isinstance(header_value, int):
        return str(header_value)
    try:
        decoded_parts = decode_header(header_value)
        result = ""
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                result += part.decode(encoding or 'utf-8', errors='ignore')
            else:
                result += str(part)
        return result
    except:
        return str(header_value)

def get_body_preview(body, max_chars=300):
    """Extract a preview of the email body"""
    if not body:
        return "(No body text found)"
    
    # Remove excessive whitespace
    preview = ' '.join(body.split())
    
    if len(preview) <= max_chars:
        return preview
    
    # Truncate and add ellipsis
    return preview[:max_chars] + "..."

def extract_unsubscribe_links(email_msg):
    """Extract unsubscribe links from email headers and body"""
    links = []
    
    # Check List-Unsubscribe header (standard way)
    list_unsub = email_msg.get('List-Unsubscribe', '')
    if list_unsub:
        # Parse URLs from header (format: <url>, <url>)
        import re
        urls = re.findall(r'<(https?://[^>]+)>', list_unsub)
        links.extend(urls)
    
    # TODO: Could also parse body for unsubscribe links as backup
    # For now, just return header-based links
    
    return links

def analyze_for_spam(email_msg, sender, subject, body):
    """Analyze email and return spam score and reasoning"""
    score = 0
    reasons = []
    
    try:
        # Check for unsubscribe links (marketing indicator)
        email_str = email_msg.as_string()
    except:
        email_str = ""
    
    if email_str and re.search(r'unsubscribe|List-Unsubscribe', email_str, re.IGNORECASE):
        score += 30
        reasons.append("Has unsubscribe link (marketing)")
    
    # Check for common marketing/spam domains
    spam_domains = ['.ru', '.tk', '.ga', 'wordpress.com', 'blogspot.com', 'tumblr.com']
    if sender:
        try:
            sender_domain = sender.split('@')[-1].lower()
            for domain in spam_domains:
                if domain in sender_domain:
                    score += 25
                    reasons.append(f"Suspicious domain: {sender_domain}")
                    break
        except:
            pass
    
    # Check for "noreply" senders (often automated)
    if sender and 'noreply' in sender.lower():
        score += 15
        reasons.append("Noreply sender (automated)")
    
    # Check for common spam keywords
    spam_keywords = [
        'viagra', 'cialis', 'casino', 'lottery', 'click here', 'limited time',
        'act now', 'urgent', 'verify account', 'confirm identity', 'update payment',
        'click below', 'act now', 'limited offer'
    ]
    combined_text = (subject + " " + body).lower()
    for keyword in spam_keywords:
        if keyword in combined_text:
            score += 20
            reasons.append(f"Spam keyword: '{keyword}'")
            break  # Only count once
    
    # Check for excessive links/formatting (bulk mailer indicator)
    link_count = len(re.findall(r'https?://', body))
    if link_count > 5:
        score += 15
        reasons.append(f"Many links ({link_count})")
    
    # Check for no subject (sometimes spam)
    if not subject or subject.strip() == "":
        score += 10
        reasons.append("No subject line")
    
    # Limit score to 100
    score = min(score, 100)
    
    # Determine confidence level
    if score >= 70:
        confidence = "HIGH"
    elif score >= 40:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"
    
    return score, confidence, reasons

def list_folders(imap):
    """List all available IMAP folders"""
    try:
        status, folders = imap.list()
        if status == 'OK':
            print("Available folders:")
            for folder in folders:
                print(f"  {folder}")
        return folders
    except Exception as e:
        print(f"Error listing folders: {e}")
        return None

def parse_folder_name(folder_line):
    """Extract clean folder name from IMAP LIST response"""
    # IMAP returns: b'(\\HasNoChildren) "/" "INBOX"'
    # We want: INBOX
    try:
        if isinstance(folder_line, bytes):
            folder_line = folder_line.decode('utf-8')
        # Extract the quoted folder name at the end
        parts = folder_line.split('"')
        if len(parts) >= 4:
            return parts[-2]  # Second-to-last quoted part is the folder name
        return None
    except:
        return None

def get_folders_with_unread(imap):
    """Get all folders with their unread message counts"""
    # System folders to skip
    skip_folders = ['Junk', 'Trash', 'Sent', 'Drafts', 'Archive', 'Deleted Messages', 'Sent Messages']
    
    try:
        status, folders = imap.list()
        if status != 'OK':
            return None
        
        folders_with_counts = []
        
        for folder_line in folders:
            folder_name = parse_folder_name(folder_line)
            
            if not folder_name or folder_name in skip_folders:
                continue
            
            try:
                # Select folder (read-only)
                imap.select(folder_name, readonly=True)
                
                # Search for unread messages
                status, messages = imap.search(None, 'UNSEEN')
                
                if status == 'OK' and messages[0]:
                    unread_count = len(messages[0].split())
                    if unread_count > 0:
                        folders_with_counts.append({
                            'name': folder_name,
                            'unread': unread_count
                        })
            except Exception as e:
                # Skip folders we can't access
                print(f"  (Skipped {folder_name}: {e})")
                continue
        
        return folders_with_counts
    
    except Exception as e:
        print(f"Error getting folders: {e}")
        return None

def select_folder_menu(folders_with_counts):
    """Display folder menu and let user select which to review"""
    if not folders_with_counts:
        print("No folders with unread messages found.")
        return None
    
    print("\n" + "=" * 60)
    print("FOLDERS WITH UNREAD MESSAGES")
    print("=" * 60)
    
    for i, folder in enumerate(folders_with_counts, 1):
        print(f"{i}. {folder['name']} ({folder['unread']} unread)")
    
    print("\nEnter folder number to review (or 'q' to quit): ", end="")
    
    choice = input().strip().lower()
    
    if choice == 'q':
        return None
    
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(folders_with_counts):
            return folders_with_counts[idx]['name']
        else:
            print("Invalid selection.")
            return None
    except ValueError:
        print("Invalid input.")
        return None

def move_to_spam(imap, msg_id):
    """Move message to Junk/Spam folder"""
    try:
        print(f"DEBUG: Attempting to move {msg_id} to Junk...")
        # Copy to Junk folder
        result = imap.copy(msg_id, 'Junk')
        print(f"DEBUG: Copy result: {result}")
        if result[0] == 'OK':
            # Mark original as deleted
            store_result = imap.store(msg_id, '+FLAGS', '\\Deleted')
            print(f"DEBUG: Store result: {store_result}")
            # Expunge immediately
            expunge_result = imap.expunge()
            print(f"DEBUG: Expunge result: {expunge_result}")
            return True, "Moved to Junk"
        else:
            return False, f"Failed to copy to Junk: {result}"
    except Exception as e:
        return False, f"Error moving to spam: {e}"

def delete_email(imap, msg_id):
    """Delete message (move to Trash)"""
    try:
        print(f"DEBUG: Attempting to move {msg_id} to Trash...")
        # Copy to Trash folder
        result = imap.copy(msg_id, 'Trash')
        print(f"DEBUG: Copy result: {result}")
        if result[0] == 'OK':
            # Mark original as deleted
            store_result = imap.store(msg_id, '+FLAGS', '\\Deleted')
            print(f"DEBUG: Store result: {store_result}")
            # Expunge immediately
            expunge_result = imap.expunge()
            print(f"DEBUG: Expunge result: {expunge_result}")
            return True, "Moved to Trash"
        else:
            return False, f"Failed to move to Trash: {result}"
    except Exception as e:
        return False, f"Error deleting: {e}"

def unsubscribe_and_delete(imap, msg_id, email_msg):
    """Try to unsubscribe then delete the email"""
    unsub_links = extract_unsubscribe_links(email_msg)
    
    if not unsub_links:
        return False, "No unsubscribe link found", None
    
    # For now, just return the link for user to handle
    # TODO: Could add automatic HTTP request to click unsubscribe
    return True, f"Unsubscribe link found", unsub_links[0]

def connect_and_analyze(email_addr, folder_name="INBOX", num_messages=50):
    """Connect to iCloud and analyze recent emails from specified folder"""
    password = get_password()
    if not password:
        return None
    
    try:
        # Connect to iCloud IMAP
        print(f"Connecting to iCloud Mail for {email_addr}...")
        imap = imaplib.IMAP4_SSL("imap.mail.me.com", 993)
        imap.login(email_addr, password)
        imap.select(folder_name)
        
        # Debug: List available folders
        print("\nChecking available folders...")
        list_folders(imap)
        print()
        
        # Get recent message IDs
        status, messages = imap.search(None, "ALL")
        msg_ids = messages[0].split()[-num_messages:]  # Last N messages
        
        print(f"Found {len(msg_ids)} recent messages to analyze...\n")
        
        analysis_results = []
        email_objects = {}  # Store email objects by index for later actions
        
        for i, msg_id in enumerate(reversed(msg_ids), 1):  # Reverse to show newest first
            try:
                status, msg_data = imap.fetch(msg_id, "(BODY.PEEK[])")
                
                if not msg_data or not msg_data[0]:
                    continue
                
                # Extract the actual email bytes
                email_bytes = None
                for item in msg_data:
                    if isinstance(item, tuple):
                        for part in item:
                            if isinstance(part, bytes) and len(part) > 100:
                                email_bytes = part
                                break
                    if email_bytes:
                        break
                
                if not email_bytes:
                    continue
                
                email_msg = email.message_from_bytes(email_bytes)
                
                # Extract headers with comprehensive error handling
                try:
                    sender = decode_header_value(email_msg.get("From", "Unknown"))
                except:
                    sender = "Unknown"
                
                try:
                    subject = decode_header_value(email_msg.get("Subject", "(No Subject)"))
                except:
                    subject = "(No Subject)"
                
                try:
                    date_str = decode_header_value(email_msg.get("Date", "Unknown"))
                except:
                    date_str = "Unknown"
                
                # Extract body with error handling
                body = ""
                try:
                    if email_msg.is_multipart():
                        for part in email_msg.walk():
                            if part.get_content_type() == "text/plain":
                                try:
                                    payload = part.get_payload(decode=True)
                                    if payload and isinstance(payload, bytes):
                                        body = payload.decode('utf-8', errors='ignore')
                                    elif payload and isinstance(payload, str):
                                        body = payload
                                except:
                                    pass
                                break
                    else:
                        try:
                            payload = email_msg.get_payload(decode=True)
                            if payload and isinstance(payload, bytes):
                                body = payload.decode('utf-8', errors='ignore')
                            elif payload and isinstance(payload, str):
                                body = payload
                            else:
                                body = str(email_msg.get_payload()) if email_msg.get_payload() else ""
                        except:
                            body = ""
                except:
                    body = ""
                
                # Analyze
                score, confidence, reasons = analyze_for_spam(email_msg, sender, subject, body)
                
                # Get body preview
                body_preview = get_body_preview(body)
                
                analysis_results.append({
                    "msg_id": msg_id,
                    "from": sender,
                    "subject": subject,
                    "date": date_str,
                    "spam_score": score,
                    "confidence": confidence,
                    "reasons": reasons,
                    "body_preview": body_preview
                })
                
                # Store email object for later actions
                email_objects[len(analysis_results) - 1] = {
                    "msg_id": msg_id,
                    "email_msg": email_msg,
                    "body": body
                }
                
            except Exception as e:
                print(f"Error analyzing message: {e}")
                continue
        
        print(f"Analyzed {len(analysis_results)} emails successfully.\n")
        
        # Keep IMAP connection open for interactive actions
        return imap, analysis_results, email_objects
    
    except imaplib.IMAP4.error as e:
        print(f"IMAP Error: {e}")
        print("Check your email address and app-specific password")
        return None
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())
        return None

def interactive_review(imap, analysis_results, email_objects):
    """Interactive email review with spam/unsubscribe/keep actions"""
    total = len(analysis_results)
    actions_taken = {"spam": 0, "unsubscribed": 0, "deleted": 0, "kept": 0}
    
    for idx, email_data in enumerate(analysis_results):
        email_obj = email_objects.get(idx)
        if not email_obj:
            continue
            
        # Display email info
        print("=" * 80)
        print(f"EMAIL #{idx + 1} of {total} - SPAM SCORE: {email_data['spam_score']}/100 ({email_data['confidence']} confidence)")
        print("=" * 80)
        print(f"FROM: {email_data['from'][:70]}")
        print(f"SUBJECT: {email_data['subject'][:70]}")
        print(f"DATE: {email_data['date']}")
        print()
        
        if email_data['reasons']:
            print("WHY I THINK IT'S SPAM:")
            for reason in email_data['reasons']:
                print(f"  • {reason}")
        else:
            print("WHY: Looks legitimate - no spam indicators found")
        print()
        
        print("BODY PREVIEW:")
        print(email_data['body_preview'])
        print()
        
        # Get user action
        while True:
            choice = input("[S]pam  [U]nsubscribe+Delete  [K]eep  [V]iew full  [Q]uit: ").strip().lower()
            
            if choice == 'q':
                print("\nExiting review...")
                return actions_taken
            
            elif choice == 'k':
                actions_taken['kept'] += 1
                print("Kept (left unread)\n")
                break
            
            elif choice == 's':
                success, msg = move_to_spam(imap, email_obj['msg_id'])
                if success:
                    actions_taken['spam'] += 1
                    print(f"{msg}\n")
                else:
                    print(f"Error: {msg}\n")
                break
            
            elif choice == 'u':
                # Try to find unsubscribe link
                success, msg, unsub_link = unsubscribe_and_delete(imap, email_obj['msg_id'], email_obj['email_msg'])
                
                if success:
                    print(f"\nUnsubscribe link: {unsub_link}")
                    print("Opening link in browser...")
                    
                    # Open in browser
                    import webbrowser
                    webbrowser.open(unsub_link)
                    
                    # Ask what to do next
                    while True:
                        delete_choice = input("\nDid you unsubscribe? [D]elete email  [K]eep  [S]pam instead: ").strip().lower()
                        if delete_choice == 'd':
                            success, msg = delete_email(imap, email_obj['msg_id'])
                            if success:
                                actions_taken['unsubscribed'] += 1
                                actions_taken['deleted'] += 1
                                print(f"{msg}\n")
                            else:
                                print(f"Error: {msg}\n")
                            break
                        elif delete_choice == 'k':
                            actions_taken['kept'] += 1
                            print("Kept\n")
                            break
                        elif delete_choice == 's':
                            success, msg = move_to_spam(imap, email_obj['msg_id'])
                            if success:
                                actions_taken['spam'] += 1
                                print(f"{msg}\n")
                            else:
                                print(f"Error: {msg}\n")
                            break
                        else:
                            print("Invalid choice. Please enter D, K, or S.")
                    break
                else:
                    print(f"\n{msg}")
                    delete_anyway = input("Delete anyway? [Y/n]: ").strip().lower()
                    if delete_anyway != 'n':
                        success, msg = delete_email(imap, email_obj['msg_id'])
                        if success:
                            actions_taken['deleted'] += 1
                            print(f"{msg}\n")
                        else:
                            print(f"Error: {msg}\n")
                    else:
                        actions_taken['kept'] += 1
                        print("Kept\n")
                    break
            
            elif choice == 'v':
                print("\n" + "=" * 80)
                print("FULL EMAIL BODY:")
                print("=" * 80)
                print(email_obj['body'][:2000])  # Show first 2000 chars
                if len(email_obj['body']) > 2000:
                    print("\n[... truncated, showing first 2000 characters ...]")
                print("\n" + "=" * 80 + "\n")
                # Don't break, ask for action again
            
            else:
                print("Invalid choice. Please enter S, U, K, V, or Q.")
    
    return actions_taken

def print_results(results):
    """Pretty print analysis results"""
    print("=" * 100)
    print("EMAIL SPAM ANALYSIS")
    print("=" * 100)
    
    for i, email_analysis in enumerate(results, 1):
        print(f"\n{i}. FROM: {email_analysis['from']}")
        print(f"   SUBJECT: {email_analysis['subject']}")
        print(f"   DATE: {email_analysis['date']}")
        print(f"   SPAM SCORE: {email_analysis['spam_score']}/100 ({email_analysis['confidence']} confidence)")
        if email_analysis['reasons']:
            print(f"   WHY: {', '.join(email_analysis['reasons'])}")
        else:
            print(f"   WHY: Looks legitimate - no spam indicators found")
    
    print("\n" + "=" * 100)

if __name__ == "__main__":
    # Default to paf@fennerfam.com (the one that works with IMAP)
    icloud_email = input("Enter your iCloud email address [paf@fennerfam.com]: ").strip()
    if not icloud_email:
        icloud_email = "paf@fennerfam.com"
    
    # Connect and get folder list
    password = get_password()
    if not password:
        print("Failed to get password")
        exit(1)
    
    try:
        print(f"Connecting to iCloud Mail for {icloud_email}...")
        imap = imaplib.IMAP4_SSL("imap.mail.me.com", 993)
        imap.login(icloud_email, password)
        
        # Get folders with unread messages
        print("\nScanning folders for unread messages...")
        folders_with_counts = get_folders_with_unread(imap)
        
        if not folders_with_counts:
            print("\nNo unread messages found in any folder!")
            imap.logout()
            exit(0)
        
        # Let user select folder
        selected_folder = select_folder_menu(folders_with_counts)
        
        if not selected_folder:
            print("No folder selected. Exiting.")
            imap.logout()
            exit(0)
        
        # Close current connection and reconnect for analysis
        # (This is cleaner than trying to reuse the connection)
        imap.logout()
        
        print(f"\nAnalyzing folder: {selected_folder}...\n")
        
        # Get the unread count for this folder
        folder_info = next((f for f in folders_with_counts if f['name'] == selected_folder), None)
        num_messages = folder_info['unread'] if folder_info else 30
        
        # Analyze the selected folder
        result = connect_and_analyze(icloud_email, folder_name=selected_folder, num_messages=num_messages)
        
        if result:
            imap, analysis_results, email_objects = result
            
            # Start interactive review
            print("Starting interactive email review...\n")
            actions = interactive_review(imap, analysis_results, email_objects)
            
            # Clean up IMAP connection
            try:
                imap.expunge()  # Permanently remove deleted messages
                imap.close()
                imap.logout()
            except:
                pass
            
            # Print summary
            print("\n" + "=" * 80)
            print("REVIEW COMPLETE")
            print("=" * 80)
            print(f"Folder reviewed: {selected_folder}")
            print(f"Marked as spam: {actions['spam']}")
            print(f"Unsubscribed and deleted: {actions['unsubscribed']}")
            print(f"Deleted: {actions['deleted']}")
            print(f"Kept: {actions['kept']}")
            print("=" * 80)
            
        else:
            print("Failed to analyze emails")
            
    except imaplib.IMAP4.error as e:
        print(f"IMAP Error: {e}")
        print("Check your email address and app-specific password")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())
