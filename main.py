#!/usr/bin/env python3
"""
Secure File Encryptor with Dropbox & Telegram Integration
Enhanced with Interactive Telegram Bot with Buttons
"""

import os
import sys
import base64
import getpass
import json
import time
import threading
import queue
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List
import argparse
import webbrowser
import hashlib
import hmac
import tempfile

# Third-party imports with error handling
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import dropbox
    from dropbox.exceptions import AuthError, ApiError
    DROPBOX_AVAILABLE = True
except ImportError:
    DROPBOX_AVAILABLE = False

try:
    import requests
    import requests.exceptions
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False

try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Configuration management for the application"""
    
    CONFIG_DIR = Path.home() / '.secure_encryptor'
    CONFIG_FILE = CONFIG_DIR / 'config.json'
    ENCRYPTION_KEY_FILE = CONFIG_DIR / 'master_key.key'
    SALT_FILE = CONFIG_DIR / 'salt.salt'
    TELEGRAM_SESSIONS_DIR = CONFIG_DIR / 'telegram_sessions'
    
    def __init__(self):
        self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self.TELEGRAM_SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        self.config = self.load_config()
        
        # Dropbox settings
        self.DROPBOX_ACCESS_TOKEN = self.config.get('dropbox_access_token', '')
        self.DROPBOX_APP_KEY = self.config.get('dropbox_app_key', '')
        self.DROPBOX_APP_SECRET = self.config.get('dropbox_app_secret', '')
        
        # Telegram settings
        self.TELEGRAM_BOT_TOKEN = self.config.get('telegram_bot_token', '')
        self.TELEGRAM_CHAT_ID = self.config.get('telegram_chat_id', '')
        self.TELEGRAM_ALLOWED_USERS = self.config.get('telegram_allowed_users', [])
        self.TELEGRAM_BOT_ACTIVE = self.config.get('telegram_bot_active', False)
        
        # UI settings
        self.AUTO_COPY_LINK = self.config.get('auto_copy_link', True)
        self.COLOR_OUTPUT = self.config.get('color_output', True)
        
        # Security settings
        self.SESSION_TIMEOUT = self.config.get('session_timeout', 300)  # 5 minutes
        self.MAX_FILE_SIZE_MB = self.config.get('max_file_size_mb', 50)  # 50MB limit for Telegram
    
    def load_config(self) -> dict:
        """Load configuration from file"""
        if self.CONFIG_FILE.exists():
            try:
                with open(self.CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def save_config(self):
        """Save configuration to file"""
        self.config.update({
            'dropbox_access_token': self.DROPBOX_ACCESS_TOKEN,
            'dropbox_app_key': self.DROPBOX_APP_KEY,
            'dropbox_app_secret': self.DROPBOX_APP_SECRET,
            'telegram_bot_token': self.TELEGRAM_BOT_TOKEN,
            'telegram_chat_id': self.TELEGRAM_CHAT_ID,
            'telegram_allowed_users': self.TELEGRAM_ALLOWED_USERS,
            'telegram_bot_active': self.TELEGRAM_BOT_ACTIVE,
            'auto_copy_link': self.AUTO_COPY_LINK,
            'color_output': self.COLOR_OUTPUT,
            'session_timeout': self.SESSION_TIMEOUT,
            'max_file_size_mb': self.MAX_FILE_SIZE_MB
        })
        
        with open(self.CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=4)
        
        # Set secure permissions
        os.chmod(self.CONFIG_FILE, 0o600)

# ============================================================================
# UI HELPERS
# ============================================================================

class UI:
    """User interface helpers with colors and formatting"""
    
    def __init__(self, use_colors=True):
        self.use_colors = use_colors and COLORS_AVAILABLE
    
    def _c(self, color, text):
        """Apply color if enabled"""
        if self.use_colors:
            return f"{color}{text}{Style.RESET_ALL}"
        return text
    
    def print_banner(self):
        """Print application banner"""
        banner = f"""
{self._c(Fore.CYAN, '╔════════════════════════════════════════════════════════════╗')}
{self._c(Fore.CYAN, '║')}            {self._c(Fore.YELLOW + Style.BRIGHT, 'SECURE FILE ENCRYPTOR v2.0')}            {self._c(Fore.CYAN, '║')}
{self._c(Fore.CYAN, '║')}        {self._c(Fore.GREEN, 'Dropbox + Telegram Integration')}        {self._c(Fore.CYAN, '║')}
{self._c(Fore.CYAN, '║')}     {self._c(Fore.MAGENTA, 'Interactive Bot with Inline Buttons')}     {self._c(Fore.CYAN, '║')}
{self._c(Fore.CYAN, '╚════════════════════════════════════════════════════════════╝')}
        """
        print(banner)
    
    def print_success(self, message):
        print(self._c(Fore.GREEN, f"✓ {message}"))
    
    def print_error(self, message):
        print(self._c(Fore.RED, f"✗ {message}"))
    
    def print_warning(self, message):
        print(self._c(Fore.YELLOW, f"⚠️  {message}"))
    
    def print_info(self, message):
        print(self._c(Fore.CYAN, f"ℹ {message}"))
    
    def print_step(self, message):
        print(self._c(Fore.MAGENTA, f"→ {message}"))
    
    def separator(self, char='─', length=60):
        print(self._c(Fore.BLUE, char * length))
    
    def header(self, title):
        self.separator('=')
        print(self._c(Fore.CYAN + Style.BRIGHT, f"  {title}"))
        self.separator('─')
    
    def input_with_prompt(self, prompt, secret=False, default=None):
        """Get user input with styled prompt"""
        prompt = self._c(Fore.YELLOW, prompt)
        if default:
            prompt += f" [{self._c(Fore.GREEN, str(default))}]"
        prompt += ": "
        
        if secret:
            return getpass.getpass(prompt)
        return input(prompt)
    
    def confirm(self, message, default=True):
        """Get yes/no confirmation"""
        default_str = "Y/n" if default else "y/N"
        response = input(f"{self._c(Fore.YELLOW, message)} [{default_str}]: ").lower().strip()
        
        if not response:
            return default
        return response.startswith('y')
    
    def menu(self, title, options):
        """Display a menu and get selection"""
        self.header(title)
        for i, (key, desc) in enumerate(options.items(), 1):
            print(f"  {self._c(Fore.GREEN, str(i))}. {self._c(Fore.WHITE, key)}")
            if desc:
                print(f"     {self._c(Fore.BLUE, desc)}")
        print()
        
        while True:
            try:
                choice = int(self.input_with_prompt("Select option"))
                if 1 <= choice <= len(options):
                    return list(options.keys())[choice - 1]
            except ValueError:
                pass
            self.print_error("Invalid choice. Please try again.")

# ============================================================================
# ENCRYPTION MODULE
# ============================================================================

class FileEncryptor:
    """Core encryption functionality"""
    
    def __init__(self, ui: UI):
        self.ui = ui
        self.backend = default_backend() if CRYPTO_AVAILABLE else None
        self.key = None
        self.temp_files = []
        
        if not CRYPTO_AVAILABLE:
            self.ui.print_error("Cryptography library not installed. Please install: pip install cryptography")
            sys.exit(1)
    
    def generate_salt(self) -> bytes:
        """Generate a random salt for key derivation"""
        return os.urandom(16)
    
    def derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Derive an encryption key from a password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,  # Increased for better security
            backend=self.backend
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def generate_master_key(self) -> bool:
        """Generate and save a master encryption key"""
        config = Config()
        
        if config.ENCRYPTION_KEY_FILE.exists():
            if not self.ui.confirm("Master key already exists. Overwrite?"):
                return False
        
        # Generate a new key
        key = Fernet.generate_key()
        
        # Save the key
        with open(config.ENCRYPTION_KEY_FILE, 'wb') as key_file:
            key_file.write(key)
        
        # Set secure permissions
        os.chmod(config.ENCRYPTION_KEY_FILE, 0o600)
        
        self.ui.print_success(f"Master key generated and saved to: {config.ENCRYPTION_KEY_FILE}")
        self.ui.print_warning("Keep this key safe! If you lose it, encrypted files cannot be recovered.")
        
        # Show backup options
        if self.ui.confirm("Would you like to backup this key to Telegram?"):
            return "backup"
        
        return True
    
    def load_master_key(self) -> Optional[bytes]:
        """Load the master encryption key"""
        config = Config()
        
        if not config.ENCRYPTION_KEY_FILE.exists():
            self.ui.print_error("No master key found. Generate one first.")
            return None
        
        with open(config.ENCRYPTION_KEY_FILE, 'rb') as key_file:
            self.key = key_file.read()
        
        return self.key
    
    def encrypt_file(self, input_file: Path, use_password: bool = False, 
                    output_name: Optional[str] = None, password: str = None) -> Tuple[Optional[Path], Optional[bytes]]:
        """Encrypt a file using either master key or password"""
        if not input_file.exists():
            raise FileNotFoundError(f"File not found: {input_file}")
        
        # Get file size for progress indication
        file_size = input_file.stat().st_size
        self.ui.print_info(f"File size: {self._format_size(file_size)}")
        
        # Setup encryption
        if use_password:
            self.ui.print_step("Password-based encryption selected")
            if not password:
                password = self.ui.input_with_prompt("Enter encryption password", secret=True)
                confirm = self.ui.input_with_prompt("Confirm password", secret=True)
                
                if password != confirm:
                    self.ui.print_error("Passwords do not match")
                    return None, None
            
            salt = self.generate_salt()
            key = self.derive_key_from_password(password, salt)
            # Save salt for decryption
            salt_file = input_file.with_suffix(input_file.suffix + '.salt')
            with open(salt_file, 'wb') as sf:
                sf.write(salt)
            self.ui.print_success(f"Salt saved to: {salt_file}")
        else:
            self.ui.print_step("Master key encryption selected")
            if not self.key:
                self.load_master_key()
            key = self.key
            salt = None
        
        fernet = Fernet(key)
        
        # Determine output filename
        if output_name:
            output_file = Path(output_name)
        else:
            output_file = input_file.with_suffix(input_file.suffix + '.encrypted')
        
        # Encrypt the file with progress indication
        self.ui.print_step("Encrypting file...")
        
        try:
            with open(input_file, 'rb') as f:
                file_data = f.read()
            
            encrypted_data = fernet.encrypt(file_data)
            
            with open(output_file, 'wb') as f:
                f.write(encrypted_data)
            
            self.ui.print_success(f"File encrypted successfully: {output_file}")
            self.ui.print_info(f"Encrypted size: {self._format_size(len(encrypted_data))}")
            
            # Track temp file for cleanup
            self.temp_files.append(output_file)
            
            return output_file, salt
            
        except Exception as e:
            self.ui.print_error(f"Encryption failed: {e}")
            return None, None
    
    def decrypt_file(self, input_file: Path, use_password: bool = False,
                    output_name: Optional[str] = None, password: str = None,
                    salt: bytes = None) -> Optional[Path]:
        """Decrypt a file using either master key or password"""
        if not input_file.exists():
            raise FileNotFoundError(f"File not found: {input_file}")
        
        # Setup decryption
        if use_password:
            self.ui.print_step("Password-based decryption selected")
            if not password:
                password = self.ui.input_with_prompt("Enter decryption password", secret=True)
            
            # Try to find salt file
            if not salt:
                salt_file = input_file.with_suffix('')  # Remove .encrypted
                salt_file = Path(str(salt_file) + '.salt')
                
                if not salt_file.exists():
                    self.ui.print_error("Salt file not found. Cannot decrypt password-encrypted file.")
                    return None
                
                with open(salt_file, 'rb') as sf:
                    salt = sf.read()
            
            key = self.derive_key_from_password(password, salt)
        else:
            self.ui.print_step("Master key decryption selected")
            if not self.key:
                self.load_master_key()
            key = self.key
        
        fernet = Fernet(key)
        
        # Determine output filename
        if output_name:
            output_file = Path(output_name)
        else:
            output_file = input_file.with_suffix('')  # Remove .encrypted
        
        # Decrypt the file
        self.ui.print_step("Decrypting file...")
        
        try:
            with open(input_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = fernet.decrypt(encrypted_data)
            
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
            
            self.ui.print_success(f"File decrypted successfully: {output_file}")
            self.ui.print_info(f"Decrypted size: {self._format_size(len(decrypted_data))}")
            
            # Track temp file for cleanup
            self.temp_files.append(output_file)
            
            return output_file
            
        except Exception as e:
            self.ui.print_error(f"Decryption failed. Wrong password or corrupted file?")
            return None
    
    def cleanup_temp_files(self):
        """Clean up temporary files"""
        for file in self.temp_files:
            try:
                if file.exists():
                    file.unlink()
            except:
                pass
        self.temp_files.clear()
    
    def _format_size(self, size: int) -> str:
        """Format file size for display"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

# ============================================================================
# DROPBOX MODULE
# ============================================================================

class DropboxManager:
    """Dropbox integration"""
    
    def __init__(self, ui: UI, config: Config):
        self.ui = ui
        self.config = config
        self.dbx = None
        
        if not DROPBOX_AVAILABLE:
            self.ui.print_warning("Dropbox SDK not installed. Install with: pip install dropbox")
            return
    
    def is_configured(self) -> bool:
        """Check if Dropbox is configured"""
        return bool(self.config.DROPBOX_ACCESS_TOKEN)
    
    def configure(self):
        """Configure Dropbox settings"""
        self.ui.header("DROPBOX CONFIGURATION")
        
        self.ui.print_info("You need a Dropbox access token. Get one from:")
        self.ui.print_info("https://www.dropbox.com/developers/apps")
        print()
        
        self.config.DROPBOX_ACCESS_TOKEN = self.ui.input_with_prompt(
            "Enter Dropbox Access Token", 
            default=self.config.DROPBOX_ACCESS_TOKEN
        )
        
        self.config.DROPBOX_APP_KEY = self.ui.input_with_prompt(
            "Enter Dropbox App Key (optional)",
            default=self.config.DROPBOX_APP_KEY
        )
        
        self.config.DROPBOX_APP_SECRET = self.ui.input_with_prompt(
            "Enter Dropbox App Secret (optional)",
            default=self.config.DROPBOX_APP_SECRET,
            secret=True
        )
        
        # Test connection
        if self.test_connection():
            self.config.save_config()
            self.ui.print_success("Dropbox configured successfully!")
        else:
            self.ui.print_error("Failed to connect to Dropbox. Please check your token.")
    
    def test_connection(self) -> bool:
        """Test Dropbox connection"""
        if not self.config.DROPBOX_ACCESS_TOKEN:
            return False
        
        try:
            self.dbx = dropbox.Dropbox(self.config.DROPBOX_ACCESS_TOKEN)
            account = self.dbx.users_get_current_account()
            self.ui.print_success(f"Connected to Dropbox as: {account.name.display_name}")
            return True
        except AuthError:
            self.ui.print_error("Invalid Dropbox access token")
            return False
        except Exception as e:
            self.ui.print_error(f"Connection failed: {e}")
            return False
    
    def connect(self) -> bool:
        """Establish Dropbox connection"""
        if not self.is_configured():
            return False
        
        if not self.dbx:
            return self.test_connection()
        
        return True
    
    def upload_file(self, local_path: Path, dropbox_path: str = None) -> Tuple[Optional[str], Optional[str]]:
        """Upload a file to Dropbox"""
        if not self.connect():
            return None, None
        
        if not local_path.exists():
            self.ui.print_error(f"File not found: {local_path}")
            return None, None
        
        # Prepare Dropbox path
        if dropbox_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dropbox_path = f"/{local_path.stem}_{timestamp}{local_path.suffix}"
        elif not dropbox_path.startswith('/'):
            dropbox_path = '/' + dropbox_path
        
        try:
            file_size = os.path.getsize(local_path)
            self.ui.print_step(f"Uploading to Dropbox: {dropbox_path}")
            
            with open(local_path, 'rb') as f:
                # For large files, use chunked upload
                if file_size > 10 * 1024 * 1024:  # 10 MB
                    self._chunked_upload(f, dropbox_path, file_size)
                else:
                    self.dbx.files_upload(f.read(), dropbox_path)
            
            self.ui.print_success("File uploaded successfully")
            
            # Create shared link
            shared_link = self.create_shared_link(dropbox_path)
            if shared_link:
                self.ui.print_success(f"Shared link: {shared_link}")
                
                # Copy to clipboard if available
                if CLIPBOARD_AVAILABLE and self.config.AUTO_COPY_LINK:
                    pyperclip.copy(shared_link)
                    self.ui.print_info("Link copied to clipboard!")
            
            return dropbox_path, shared_link
            
        except ApiError as e:
            self.ui.print_error(f"Dropbox API error: {e}")
            return None, None
        except Exception as e:
            self.ui.print_error(f"Upload failed: {e}")
            return None, None
    
    def _chunked_upload(self, file_obj, dropbox_path, file_size, chunk_size=4 * 1024 * 1024):
        """Upload large files in chunks with progress"""
        uploaded = 0
        upload_session = self.dbx.files_upload_session_start(file_obj.read(chunk_size))
        uploaded += chunk_size
        self.ui.print_info(f"Uploaded: {self._format_size(uploaded)} / {self._format_size(file_size)}")
        
        cursor = dropbox.files.UploadSessionCursor(
            session_id=upload_session.session_id, 
            offset=file_obj.tell()
        )
        
        while file_obj.tell() < file_size:
            remaining = file_size - file_obj.tell()
            if remaining <= chunk_size:
                # Last chunk
                self.dbx.files_upload_session_finish(
                    file_obj.read(chunk_size),
                    cursor,
                    dropbox.files.CommitInfo(path=dropbox_path)
                )
                uploaded = file_size
            else:
                # Continue session
                self.dbx.files_upload_session_append_v2(
                    file_obj.read(chunk_size),
                    cursor
                )
                cursor.offset = file_obj.tell()
                uploaded = file_obj.tell()
            
            self.ui.print_info(f"Uploaded: {self._format_size(uploaded)} / {self._format_size(file_size)}")
    
    def create_shared_link(self, dropbox_path: str) -> Optional[str]:
        """Create a shared link for the uploaded file"""
        try:
            shared_link = self.dbx.sharing_create_shared_link_with_settings(dropbox_path)
            return shared_link.url
        except ApiError:
            # Link might already exist, try to get existing
            try:
                links = self.dbx.sharing_list_shared_links(path=dropbox_path)
                if links.links:
                    return links.links[0].url
            except:
                pass
            return None
    
    def list_files(self, path: str = '') -> list:
        """List files in Dropbox"""
        if not self.connect():
            return []
        
        try:
            result = self.dbx.files_list_folder(path)
            files = []
            for entry in result.entries:
                if isinstance(entry, dropbox.files.FileMetadata):
                    files.append({
                        'name': entry.name,
                        'path': entry.path_display,
                        'size': entry.size,
                        'modified': entry.client_modified
                    })
            return files
        except ApiError as e:
            self.ui.print_error(f"Error listing files: {e}")
            return []
    
    def download_file(self, dropbox_path: str, local_path: Optional[Path] = None) -> Optional[Path]:
        """Download a file from Dropbox"""
        if not self.connect():
            return None
        
        try:
            if local_path is None:
                local_path = Path(dropbox_path).name
            
            metadata, response = self.dbx.files_download(dropbox_path)
            
            file_size = len(response.content)
            self.ui.print_step(f"Downloading: {self._format_size(file_size)}")
            
            with open(local_path, 'wb') as f:
                f.write(response.content)
            
            self.ui.print_success(f"File downloaded to: {local_path}")
            return Path(local_path)
            
        except ApiError as e:
            self.ui.print_error(f"Error downloading file: {e}")
            return None
    
    def _format_size(self, size: int) -> str:
        """Format file size for display"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

# ============================================================================
# TELEGRAM BOT MODULE WITH INTERACTIVE BUTTONS
# ============================================================================

class TelegramBot:
    """Interactive Telegram Bot with Inline Buttons"""
    
    def __init__(self, ui: UI, config: Config, encryptor: FileEncryptor, dropbox: DropboxManager):
        self.ui = ui
        self.config = config
        self.encryptor = encryptor
        self.dropbox = dropbox
        self.running = False
        self.update_id = 0
        self.user_sessions = {}  # Track user sessions
        self.pending_actions = {}  # Track pending operations
        
        # Bot commands and their descriptions
        self.commands = {
            'start': 'Start the bot and show main menu',
            'help': 'Show available commands',
            'encrypt': 'Encrypt a file (send file to encrypt)',
            'decrypt': 'Decrypt a file (send .encrypted file)',
            'list': 'List files in Dropbox',
            'download': 'Download a file from Dropbox',
            'status': 'Check bot status',
            'settings': 'Configure bot settings',
            'cancel': 'Cancel current operation'
        }
    
    def is_authorized(self, user_id: int) -> bool:
        """Check if user is authorized to use the bot"""
        # If no allowed users configured, allow all
        if not self.config.TELEGRAM_ALLOWED_USERS:
            return True
        return str(user_id) in self.config.TELEGRAM_ALLOWED_USERS
    
    def create_inline_keyboard(self, buttons: List[Tuple[str, str]], row_width: int = 2) -> dict:
        """Create an inline keyboard markup"""
        keyboard = []
        row = []
        
        for i, (text, callback_data) in enumerate(buttons, 1):
            row.append({
                'text': text,
                'callback_data': callback_data
            })
            if i % row_width == 0:
                keyboard.append(row)
                row = []
        
        if row:
            keyboard.append(row)
        
        return {
            'inline_keyboard': keyboard
        }
    
    def send_message(self, chat_id: int, text: str, reply_markup: dict = None, parse_mode: str = 'HTML') -> bool:
        """Send a message with optional inline keyboard"""
        url = f"https://api.telegram.org/bot{self.config.TELEGRAM_BOT_TOKEN}/sendMessage"
        
        data = {
            'chat_id': chat_id,
            'text': text,
            'parse_mode': parse_mode
        }
        
        if reply_markup:
            data['reply_markup'] = json.dumps(reply_markup)
        
        try:
            response = requests.post(url, data=data, timeout=10)
            return response.status_code == 200
        except Exception as e:
            self.ui.print_error(f"Failed to send message: {e}")
            return False
    
    def edit_message(self, chat_id: int, message_id: int, text: str, reply_markup: dict = None) -> bool:
        """Edit an existing message"""
        url = f"https://api.telegram.org/bot{self.config.TELEGRAM_BOT_TOKEN}/editMessageText"
        
        data = {
            'chat_id': chat_id,
            'message_id': message_id,
            'text': text,
            'parse_mode': 'HTML'
        }
        
        if reply_markup:
            data['reply_markup'] = json.dumps(reply_markup)
        
        try:
            response = requests.post(url, data=data, timeout=10)
            return response.status_code == 200
        except Exception as e:
            return False
    
    def send_file(self, chat_id: int, file_path: Path, caption: str = "") -> bool:
        """Send a file to Telegram"""
        url = f"https://api.telegram.org/bot{self.config.TELEGRAM_BOT_TOKEN}/sendDocument"
        
        try:
            with open(file_path, 'rb') as f:
                files = {'document': f}
                data = {
                    'chat_id': chat_id,
                    'caption': caption[:200]
                }
                
                response = requests.post(url, data=data, files=files, timeout=30)
                return response.status_code == 200
        except Exception as e:
            self.ui.print_error(f"Failed to send file: {e}")
            return False
    
    def answer_callback(self, callback_id: str, text: str = "", show_alert: bool = False):
        """Answer a callback query"""
        url = f"https://api.telegram.org/bot{self.config.TELEGRAM_BOT_TOKEN}/answerCallbackQuery"
        
        data = {
            'callback_query_id': callback_id,
            'text': text,
            'show_alert': show_alert
        }
        
        try:
            requests.post(url, data=data, timeout=5)
        except:
            pass
    
    def handle_start(self, chat_id: int, user_name: str):
        """Handle /start command"""
        welcome_text = f"""
👋 <b>Welcome to Secure File Encryptor Bot, {user_name}!</b>

I can help you encrypt and decrypt files securely, and upload them to Dropbox.

<b>Available Commands:</b>
• /encrypt - Encrypt a file
• /decrypt - Decrypt a file
• /list - List Dropbox files
• /download - Download from Dropbox
• /status - Check bot status
• /settings - Configure settings
• /help - Show all commands

<b>How to use:</b>
1. Send me any file to encrypt
2. Choose encryption method
3. Get encrypted file back
4. Optionally upload to Dropbox
        """
        
        # Create main menu keyboard
        keyboard = self.create_inline_keyboard([
            ("🔒 Encrypt File", "menu_encrypt"),
            ("🔓 Decrypt File", "menu_decrypt"),
            ("📁 Dropbox Files", "menu_list"),
            ("⚙️ Settings", "menu_settings"),
            ("❓ Help", "menu_help")
        ], row_width=2)
        
        self.send_message(chat_id, welcome_text, reply_markup=keyboard)
    
    def handle_help(self, chat_id: int):
        """Handle /help command"""
        help_text = "<b>📚 Available Commands:</b>\n\n"
        
        for cmd, desc in self.commands.items():
            help_text += f"• /{cmd} - {desc}\n"
        
        help_text += "\n<b>File Operations:</b>\n"
        help_text += "• Send any file to encrypt it\n"
        help_text += "• Send .encrypted files to decrypt\n"
        help_text += "• Files are processed securely and deleted after use\n"
        
        keyboard = self.create_inline_keyboard([
            ("🔙 Main Menu", "menu_main")
        ])
        
        self.send_message(chat_id, help_text, reply_markup=keyboard)
    
    def handle_encrypt_menu(self, chat_id: int, message_id: int = None):
        """Show encryption options menu"""
        text = "<b>🔒 File Encryption</b>\n\nChoose encryption method:"
        
        keyboard = self.create_inline_keyboard([
            ("🔑 Master Key", "encrypt_master"),
            ("🔐 Password", "encrypt_password"),
            ("🔙 Back", "menu_main")
        ])
        
        if message_id:
            self.edit_message(chat_id, message_id, text, keyboard)
        else:
            self.send_message(chat_id, text, keyboard)
    
    def handle_decrypt_menu(self, chat_id: int, message_id: int = None):
        """Show decryption options menu"""
        text = "<b>🔓 File Decryption</b>\n\nChoose decryption method:"
        
        keyboard = self.create_inline_keyboard([
            ("🔑 Master Key", "decrypt_master"),
            ("🔐 Password", "decrypt_password"),
            ("🔙 Back", "menu_main")
        ])
        
        if message_id:
            self.edit_message(chat_id, message_id, text, keyboard)
        else:
            self.send_message(chat_id, text, keyboard)
    
    def handle_dropbox_menu(self, chat_id: int, message_id: int = None):
        """Show Dropbox operations menu"""
        if not self.dropbox.is_configured():
            text = "<b>⚠️ Dropbox Not Configured</b>\n\nPlease configure Dropbox first in settings."
            keyboard = self.create_inline_keyboard([
                ("⚙️ Go to Settings", "menu_settings"),
                ("🔙 Back", "menu_main")
            ])
        else:
            text = "<b>📁 Dropbox Operations</b>\n\nChoose an option:"
            keyboard = self.create_inline_keyboard([
                ("📋 List Files", "dropbox_list"),
                ("⬇️ Download File", "dropbox_download"),
                ("🔗 Generate Link", "dropbox_link"),
                ("🔙 Back", "menu_main")
            ])
        
        if message_id:
            self.edit_message(chat_id, message_id, text, keyboard)
        else:
            self.send_message(chat_id, text, keyboard)
    
    def handle_settings_menu(self, chat_id: int, message_id: int = None):
        """Show settings menu"""
        dropbox_status = "✅ Configured" if self.dropbox.is_configured() else "❌ Not Configured"
        bot_status = "🟢 Active" if self.config.TELEGRAM_BOT_ACTIVE else "🔴 Inactive"
        
        text = f"""
<b>⚙️ Bot Settings</b>

<b>Current Configuration:</b>
• Dropbox: {dropbox_status}
• Bot Status: {bot_status}
• Max File Size: {self.config.MAX_FILE_SIZE_MB} MB
• Auto-copy Links: {'✅' if self.config.AUTO_COPY_LINK else '❌'}

<b>Options:</b>
        """
        
        keyboard = self.create_inline_keyboard([
            ("☁️ Configure Dropbox", "settings_dropbox"),
            ("📊 Toggle Bot", "settings_toggle_bot"),
            ("📏 Set Max Size", "settings_max_size"),
            ("📋 Allowed Users", "settings_users"),
            ("🔙 Main Menu", "menu_main")
        ], row_width=2)
        
        if message_id:
            self.edit_message(chat_id, message_id, text, keyboard)
        else:
            self.send_message(chat_id, text, keyboard)
    
    def handle_file_upload(self, chat_id: int, file_id: str, file_name: str, file_size: int):
        """Handle file upload from user"""
        # Check file size
        max_size = self.config.MAX_FILE_SIZE_MB * 1024 * 1024
        if file_size > max_size:
            self.send_message(chat_id, 
                f"❌ File too large! Maximum size: {self.config.MAX_FILE_SIZE_MB} MB")
            return
        
        # Store file info in pending actions
        self.pending_actions[chat_id] = {
            'file_id': file_id,
            'file_name': file_name,
            'file_size': file_size,
            'step': 'waiting_encryption_method'
        }
        
        # Show encryption method choice
        text = f"📄 <b>File Received:</b> {file_name}\n"
        text += f"📊 Size: {self._format_size(file_size)}\n\n"
        text += "Choose encryption method:"
        
        keyboard = self.create_inline_keyboard([
            ("🔑 Master Key", "file_encrypt_master"),
            ("🔐 Password", "file_encrypt_password"),
            ("❌ Cancel", "file_cancel")
        ])
        
        self.send_message(chat_id, text, keyboard)
    
    def handle_encrypt_file(self, chat_id: int, file_id: str, file_name: str, 
                           use_password: bool, password: str = None):
        """Download and encrypt a file"""
        try:
            # Send processing message
            processing_msg = self.send_message(chat_id, "⏳ Processing file...")
            
            # Download file from Telegram
            file_path = self.download_telegram_file(file_id, file_name)
            if not file_path:
                self.send_message(chat_id, "❌ Failed to download file")
                return
            
            # Encrypt the file
            encrypted_file, salt = self.encryptor.encrypt_file(
                file_path,
                use_password=use_password,
                password=password
            )
            
            if not encrypted_file:
                self.send_message(chat_id, "❌ Encryption failed")
                return
            
            # Send encrypted file back
            caption = f"🔒 <b>Encrypted: {file_name}</b>\n"
            caption += f"Method: {'Password' if use_password else 'Master Key'}\n"
            if salt:
                caption += f"Salt: <code>{base64.b64encode(salt).decode()[:20]}...</code>"
            
            if self.send_file(chat_id, encrypted_file, caption):
                # Ask about Dropbox upload
                keyboard = self.create_inline_keyboard([
                    ("✅ Upload to Dropbox", f"dropbox_upload_{encrypted_file.name}"),
                    ("❌ Skip", "file_complete")
                ])
                
                self.send_message(chat_id, 
                    "✅ Encryption complete!\n\nUpload to Dropbox?",
                    keyboard)
            else:
                self.send_message(chat_id, "❌ Failed to send encrypted file")
            
            # Clean up original file
            file_path.unlink(missing_ok=True)
            
        except Exception as e:
            self.send_message(chat_id, f"❌ Error: {str(e)}")
    
    def handle_decrypt_file(self, chat_id: int, file_id: str, file_name: str,
                           use_password: bool, password: str = None, salt: bytes = None):
        """Download and decrypt a file"""
        try:
            # Send processing message
            self.send_message(chat_id, "⏳ Processing file...")
            
            # Download file from Telegram
            file_path = self.download_telegram_file(file_id, file_name)
            if not file_path:
                self.send_message(chat_id, "❌ Failed to download file")
                return
            
            # Decrypt the file
            decrypted_file = self.encryptor.decrypt_file(
                file_path,
                use_password=use_password,
                password=password,
                salt=salt
            )
            
            if not decrypted_file:
                self.send_message(chat_id, "❌ Decryption failed")
                return
            
            # Send decrypted file back
            caption = f"🔓 <b>Decrypted: {file_name.replace('.encrypted', '')}</b>"
            self.send_file(chat_id, decrypted_file, caption)
            
            # Clean up
            file_path.unlink(missing_ok=True)
            decrypted_file.unlink(missing_ok=True)
            
        except Exception as e:
            self.send_message(chat_id, f"❌ Error: {str(e)}")
    
    def download_telegram_file(self, file_id: str, file_name: str) -> Optional[Path]:
        """Download a file from Telegram"""
        try:
            # Get file path
            url = f"https://api.telegram.org/bot{self.config.TELEGRAM_BOT_TOKEN}/getFile"
            response = requests.get(url, params={'file_id': file_id})
            
            if response.status_code != 200:
                return None
            
            file_path = response.json()['result']['file_path']
            
            # Download file
            download_url = f"https://api.telegram.org/file/bot{self.config.TELEGRAM_BOT_TOKEN}/{file_path}"
            response = requests.get(download_url, stream=True)
            
            if response.status_code != 200:
                return None
            
            # Save to temp file
            temp_dir = Path(tempfile.gettempdir()) / 'secure_encryptor'
            temp_dir.mkdir(exist_ok=True)
            local_path = temp_dir / file_name
            
            with open(local_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            return local_path
            
        except Exception as e:
            self.ui.print_error(f"Download failed: {e}")
            return None
    
    def handle_callback(self, callback_data: dict):
        """Handle inline keyboard callbacks"""
        callback_id = callback_data['id']
        chat_id = callback_data['message']['chat']['id']
        message_id = callback_data['message']['message_id']
        data = callback_data['data']
        user_id = callback_data['from']['id']
        
        # Check authorization
        if not self.is_authorized(user_id):
            self.answer_callback(callback_id, "⛔ Unauthorized", show_alert=True)
            return
        
        # Handle menu navigation
        if data == "menu_main":
            self.answer_callback(callback_id, "Main Menu")
            self.handle_start(chat_id, callback_data['from']['first_name'])
        
        elif data == "menu_encrypt":
            self.answer_callback(callback_id, "Encryption Menu")
            self.handle_encrypt_menu(chat_id, message_id)
        
        elif data == "menu_decrypt":
            self.answer_callback(callback_id, "Decryption Menu")
            self.handle_decrypt_menu(chat_id, message_id)
        
        elif data == "menu_list":
            self.answer_callback(callback_id, "Dropbox Menu")
            self.handle_dropbox_menu(chat_id, message_id)
        
        elif data == "menu_settings":
            self.answer_callback(callback_id, "Settings Menu")
            self.handle_settings_menu(chat_id, message_id)
        
        elif data == "menu_help":
            self.answer_callback(callback_id, "Help")
            self.handle_help(chat_id)
        
        # Handle encryption methods
        elif data == "encrypt_master":
            self.answer_callback(callback_id, "Send file to encrypt with master key")
            self.edit_message(chat_id, message_id, 
                "🔑 <b>Master Key Encryption</b>\n\nSend me the file you want to encrypt.",
                self.create_inline_keyboard([("🔙 Back", "menu_encrypt")]))
            self.pending_actions[chat_id] = {'action': 'encrypt_master', 'step': 'waiting_file'}
        
        elif data == "encrypt_password":
            self.answer_callback(callback_id, "Send file to encrypt with password")
            self.edit_message(chat_id, message_id,
                "🔐 <b>Password Encryption</b>\n\nSend me the file you want to encrypt.\n\n"
                "I'll ask for your password after receiving the file.",
                self.create_inline_keyboard([("🔙 Back", "menu_encrypt")]))
            self.pending_actions[chat_id] = {'action': 'encrypt_password', 'step': 'waiting_file'}
        
        # Handle decryption methods
        elif data == "decrypt_master":
            self.answer_callback(callback_id, "Send file to decrypt with master key")
            self.edit_message(chat_id, message_id,
                "🔑 <b>Master Key Decryption</b>\n\nSend me the .encrypted file.",
                self.create_inline_keyboard([("🔙 Back", "menu_decrypt")]))
            self.pending_actions[chat_id] = {'action': 'decrypt_master', 'step': 'waiting_file'}
        
        elif data == "decrypt_password":
            self.answer_callback(callback_id, "Send file to decrypt with password")
            self.edit_message(chat_id, message_id,
                "🔐 <b>Password Decryption</b>\n\nSend me the .encrypted file.\n\n"
                "I'll ask for your password after receiving the file.",
                self.create_inline_keyboard([("🔙 Back", "menu_decrypt")]))
            self.pending_actions[chat_id] = {'action': 'decrypt_password', 'step': 'waiting_file'}
        
        # Handle Dropbox operations
        elif data == "dropbox_list":
            self.answer_callback(callback_id, "Fetching file list...")
            files = self.dropbox.list_files()
            
            if not files:
                text = "📁 <b>No files found in Dropbox</b>"
            else:
                text = "📁 <b>Dropbox Files:</b>\n\n"
                for i, file in enumerate(files[:10], 1):  # Show first 10
                    size = self._format_size(file['size'])
                    modified = file['modified'].strftime('%Y-%m-%d %H:%M')
                    text += f"{i}. <b>{file['name']}</b>\n"
                    text += f"   Size: {size} | Modified: {modified}\n\n"
                
                if len(files) > 10:
                    text += f"<i>... and {len(files) - 10} more files</i>"
            
            keyboard = self.create_inline_keyboard([
                ("⬇️ Download", "dropbox_download"),
                ("🔙 Back", "menu_list")
            ])
            
            self.edit_message(chat_id, message_id, text, keyboard)
        
        elif data == "dropbox_download":
            self.answer_callback(callback_id, "Enter filename to download")
            self.edit_message(chat_id, message_id,
                "⬇️ <b>Download from Dropbox</b>\n\n"
                "Please enter the filename or path to download.\n"
                "Example: <code>/myfile.pdf</code> or <code>folder/file.txt</code>",
                self.create_inline_keyboard([("🔙 Back", "menu_list")]))
            self.pending_actions[chat_id] = {'action': 'dropbox_download', 'step': 'waiting_path'}
        
        # Handle file operations
        elif data.startswith('file_encrypt_'):
            method = data.replace('file_encrypt_', '')
            pending = self.pending_actions.get(chat_id, {})
            
            if method == 'master':
                self.answer_callback(callback_id, "Encrypting with master key...")
                self.handle_encrypt_file(chat_id, pending['file_id'], 
                                       pending['file_name'], False)
            elif method == 'password':
                self.answer_callback(callback_id, "Please enter password")
                self.edit_message(chat_id, message_id,
                    "🔐 <b>Enter Password</b>\n\nPlease type your password below:",
                    self.create_inline_keyboard([("❌ Cancel", "file_cancel")]))
                pending['step'] = 'waiting_password'
        
        elif data.startswith('dropbox_upload_'):
            filename = data.replace('dropbox_upload_', '')
            self.answer_callback(callback_id, "Uploading to Dropbox...")
            
            # Find the encrypted file in temp
            temp_dir = Path(tempfile.gettempdir()) / 'secure_encryptor'
            file_path = temp_dir / filename
            
            if file_path.exists():
                dropbox_path, link = self.dropbox.upload_file(file_path)
                if link:
                    self.send_message(chat_id, f"✅ Uploaded to Dropbox!\n🔗 Link: {link}")
                file_path.unlink(missing_ok=True)
        
        elif data == "file_cancel":
            self.answer_callback(callback_id, "Operation cancelled")
            if chat_id in self.pending_actions:
                del self.pending_actions[chat_id]
            self.handle_start(chat_id, callback_data['from']['first_name'])
        
        elif data == "file_complete":
            self.answer_callback(callback_id, "Operation complete")
            if chat_id in self.pending_actions:
                del self.pending_actions[chat_id]
            self.handle_start(chat_id, callback_data['from']['first_name'])
        
        # Handle settings
        elif data == "settings_dropbox":
            self.answer_callback(callback_id, "Dropbox configuration")
            self.edit_message(chat_id, message_id,
                "<b>☁️ Dropbox Configuration</b>\n\n"
                "To configure Dropbox, please run the main application "
                "and use the configuration menu.\n\n"
                "Bot cannot securely input tokens via chat.",
                self.create_inline_keyboard([("🔙 Back", "menu_settings")]))
        
        elif data == "settings_toggle_bot":
            self.config.TELEGRAM_BOT_ACTIVE = not self.config.TELEGRAM_BOT_ACTIVE
            self.config.save_config()
            self.answer_callback(callback_id, 
                f"Bot {'activated' if self.config.TELEGRAM_BOT_ACTIVE else 'deactivated'}")
            self.handle_settings_menu(chat_id, message_id)
    
    def handle_message(self, message: dict):
        """Handle regular messages"""
        chat_id = message['chat']['id']
        user_id = message['from']['id']
        user_name = message['from'].get('first_name', 'User')
        
        # Check authorization
        if not self.is_authorized(user_id):
            self.send_message(chat_id, "⛔ You are not authorized to use this bot.")
            return
        
        # Check if there's a pending action
        pending = self.pending_actions.get(chat_id, {})
        
        # Handle text messages
        if 'text' in message:
            text = message['text']
            
            # Handle commands
            if text.startswith('/'):
                cmd = text[1:].split()[0].lower()
                
                if cmd == 'start':
                    self.handle_start(chat_id, user_name)
                elif cmd == 'help':
                    self.handle_help(chat_id)
                elif cmd == 'encrypt':
                    self.handle_encrypt_menu(chat_id)
                elif cmd == 'decrypt':
                    self.handle_decrypt_menu(chat_id)
                elif cmd == 'list':
                    self.handle_dropbox_menu(chat_id)
                elif cmd == 'status':
                    self.send_message(chat_id, self.get_status_message())
                elif cmd == 'cancel':
                    if chat_id in self.pending_actions:
                        del self.pending_actions[chat_id]
                    self.send_message(chat_id, "✅ Operation cancelled.")
            
            # Handle pending password input
            elif pending.get('step') == 'waiting_password':
                password = text
                
                if pending['action'] == 'encrypt_password':
                    self.handle_encrypt_file(chat_id, pending['file_id'],
                                           pending['file_name'], True, password)
                elif pending['action'] == 'decrypt_password':
                    # For decrypt, need to ask for salt or extract from message
                    self.send_message(chat_id, "Please provide the salt (base64):")
                    pending['step'] = 'waiting_salt'
                    pending['password'] = password
            
            elif pending.get('step') == 'waiting_salt':
                try:
                    salt = base64.b64decode(text)
                    self.handle_decrypt_file(chat_id, pending['file_id'],
                                           pending['file_name'], True,
                                           pending['password'], salt)
                except:
                    self.send_message(chat_id, "❌ Invalid salt format")
            
            elif pending.get('step') == 'waiting_path':
                if pending['action'] == 'dropbox_download':
                    file = self.dropbox.download_file(text)
                    if file:
                        self.send_file(chat_id, file, f"📥 Downloaded: {file.name}")
                        file.unlink(missing_ok=True)
                    else:
                        self.send_message(chat_id, "❌ File not found")
        
        # Handle document uploads
        elif 'document' in message:
            doc = message['document']
            file_id = doc['file_id']
            file_name = doc['file_name']
            file_size = doc['file_size']
            
            # Check if there's a pending action
            if pending:
                if pending['action'] in ['encrypt_master', 'encrypt_password']:
                    # File is for encryption
                    use_password = pending['action'] == 'encrypt_password'
                    pending['file_id'] = file_id
                    pending['file_name'] = file_name
                    pending['file_size'] = file_size
                    
                    if use_password:
                        self.send_message(chat_id, 
                            "🔐 Please enter the password for encryption:")
                        pending['step'] = 'waiting_password'
                    else:
                        self.handle_encrypt_file(chat_id, file_id, file_name, False)
                
                elif pending['action'] in ['decrypt_master', 'decrypt_password']:
                    # File is for decryption
                    use_password = pending['action'] == 'decrypt_password'
                    pending['file_id'] = file_id
                    pending['file_name'] = file_name
                    
                    if use_password:
                        self.send_message(chat_id,
                            "🔐 Please enter the password for decryption:")
                        pending['step'] = 'waiting_password'
                    else:
                        self.handle_decrypt_file(chat_id, file_id, file_name, False)
            else:
                # No pending action, ask what to do with file
                self.handle_file_upload(chat_id, file_id, file_name, file_size)
    
    def get_status_message(self) -> str:
        """Get bot status message"""
        dropbox_status = "✅ Connected" if self.dropbox.is_configured() and self.dropbox.connect() else "❌ Disconnected"
        
        status = f"""
<b>🤖 Bot Status</b>

• Bot: {'🟢 Running' if self.running else '🔴 Stopped'}
• Dropbox: {dropbox_status}
• Active Sessions: {len(self.user_sessions)}
• Pending Actions: {len(self.pending_actions)}
• Max File Size: {self.config.MAX_FILE_SIZE_MB} MB
        """
        
        return status
    
    def _format_size(self, size: int) -> str:
        """Format file size for display"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
    
    def start_polling(self):
        """Start polling for Telegram updates"""
        if not self.config.TELEGRAM_BOT_TOKEN:
            self.ui.print_error("Telegram bot token not configured")
            return
        
        self.running = True
        self.ui.print_success("Telegram bot started! Press Ctrl+C to stop.")
        
        while self.running:
            try:
                url = f"https://api.telegram.org/bot{self.config.TELEGRAM_BOT_TOKEN}/getUpdates"
                params = {
                    'offset': self.update_id,
                    'timeout': 30,
                    'allowed_updates': ['message', 'callback_query']
                }
                
                response = requests.get(url, params=params, timeout=35)
                
                if response.status_code == 200:
                    updates = response.json().get('result', [])
                    
                    for update in updates:
                        self.update_id = update['update_id'] + 1
                        
                        if 'callback_query' in update:
                            self.handle_callback(update['callback_query'])
                        elif 'message' in update:
                            self.handle_message(update['message'])
                
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.ConnectionError:
                self.ui.print_error("Connection error, retrying in 5 seconds...")
                time.sleep(5)
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.ui.print_error(f"Polling error: {e}")
                time.sleep(5)
        
        self.running = False
        self.ui.print_info("Telegram bot stopped")
    
    def stop(self):
        """Stop the bot"""
        self.running = False

# ============================================================================
# TELEGRAM MANAGER (for backward compatibility)
# ============================================================================

class TelegramManager:
    """Legacy Telegram manager for backward compatibility"""
    
    def __init__(self, ui: UI, config: Config):
        self.ui = ui
        self.config = config
        self.bot = None
    
    def is_configured(self) -> bool:
        """Check if Telegram is configured"""
        return bool(self.config.TELEGRAM_BOT_TOKEN and self.config.TELEGRAM_CHAT_ID)
    
    def configure(self):
        """Configure Telegram settings"""
        self.ui.header("TELEGRAM CONFIGURATION")
        
        self.ui.print_info("You need a Telegram Bot Token and Chat ID.")
        self.ui.print_info("1. Talk to @BotFather on Telegram to create a bot and get a token")
        self.ui.print_info("2. Get your chat ID by messaging @userinfobot")
        print()
        
        self.config.TELEGRAM_BOT_TOKEN = self.ui.input_with_prompt(
            "Enter Telegram Bot Token",
            default=self.config.TELEGRAM_BOT_TOKEN,
            secret=True
        )
        
        self.config.TELEGRAM_CHAT_ID = self.ui.input_with_prompt(
            "Enter Telegram Chat ID",
            default=self.config.TELEGRAM_CHAT_ID
        )
        
        # Test connection
        if self.test_connection():
            self.config.save_config()
            self.ui.print_success("Telegram configured successfully!")
        else:
            self.ui.print_error("Failed to connect to Telegram. Please check your credentials.")
    
    def test_connection(self) -> bool:
        """Test Telegram connection"""
        if not self.is_configured():
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.config.TELEGRAM_BOT_TOKEN}/getMe"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                bot_info = response.json()
                self.ui.print_success(f"Connected to bot: {bot_info['result']['username']}")
                return True
            else:
                self.ui.print_error(f"Telegram API error: {response.status_code}")
                return False
                
        except Exception as e:
            self.ui.print_error(f"Connection failed: {e}")
            return False
    
    def send_message(self, message: str) -> bool:
        """Send a text message via Telegram"""
        if not self.is_configured():
            self.ui.print_warning("Telegram not configured")
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.config.TELEGRAM_BOT_TOKEN}/sendMessage"
            data = {
                'chat_id': self.config.TELEGRAM_CHAT_ID,
                'text': message,
                'parse_mode': 'HTML'
            }
            
            response = requests.post(url, data=data, timeout=10)
            
            if response.status_code == 200:
                self.ui.print_success("Message sent to Telegram")
                return True
            else:
                self.ui.print_error(f"Failed to send message: {response.status_code}")
                return False
                
        except Exception as e:
            self.ui.print_error(f"Telegram send failed: {e}")
            return False
    
    def send_file(self, file_path: Path, caption: str = "") -> bool:
        """Send a file via Telegram"""
        if not self.is_configured():
            self.ui.print_warning("Telegram not configured")
            return False
        
        if not file_path.exists():
            self.ui.print_error(f"File not found: {file_path}")
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.config.TELEGRAM_BOT_TOKEN}/sendDocument"
            
            with open(file_path, 'rb') as f:
                files = {'document': f}
                data = {
                    'chat_id': self.config.TELEGRAM_CHAT_ID,
                    'caption': caption[:200]  # Telegram caption limit
                }
                
                response = requests.post(url, data=data, files=files, timeout=30)
            
            if response.status_code == 200:
                self.ui.print_success(f"File sent to Telegram: {file_path.name}")
                return True
            else:
                self.ui.print_error(f"Failed to send file: {response.status_code}")
                return False
                
        except Exception as e:
            self.ui.print_error(f"Telegram send failed: {e}")
            return False
    
    def send_encryption_key(self, key_path: Path) -> bool:
        """Securely send encryption key via Telegram"""
        if not key_path.exists():
            return False
        
        # Create a secure message with key info
        with open(key_path, 'rb') as f:
            key_data = f.read()
        
        message = f"""
🔐 <b>ENCRYPTION MASTER KEY BACKUP</b>
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Key File: {key_path.name}

<b>IMPORTANT:</b> Store this key securely!
Key (Base64): <code>{key_data.decode()}</code>
        """
        
        return self.send_message(message)

# ============================================================================
# MAIN APPLICATION
# ============================================================================

class SecureEncryptorApp:
    """Main application class"""
    
    def __init__(self):
        self.config = Config()
        self.ui = UI(use_colors=self.config.COLOR_OUTPUT)
        self.encryptor = FileEncryptor(self.ui)
        self.dropbox = DropboxManager(self.ui, self.config)
        self.telegram = TelegramManager(self.ui, self.config)
        self.telegram_bot = None
        self.bot_thread = None
        
        # Check for required dependencies
        self._check_dependencies()
    
    def _check_dependencies(self):
        """Check if all required dependencies are installed"""
        missing = []
        
        if not CRYPTO_AVAILABLE:
            missing.append("cryptography")
        if not DROPBOX_AVAILABLE:
            missing.append("dropbox")
        if not TELEGRAM_AVAILABLE:
            missing.append("requests")
        
        if missing:
            self.ui.print_warning("Missing optional dependencies:")
            for dep in missing:
                self.ui.print_info(f"  • {dep}")
            print()
    
    def run(self):
        """Main application loop"""
        self.ui.print_banner()
        
        while True:
            action = self.ui.menu(
                "MAIN MENU",
                {
                    "Encrypt File": "Encrypt a file with optional cloud upload",
                    "Decrypt File": "Decrypt an encrypted file",
                    "Configure Services": "Set up Dropbox and Telegram",
                    "Generate Master Key": "Create a new encryption master key",
                    "Start Telegram Bot": "Start interactive Telegram bot",
                    "Stop Telegram Bot": "Stop the Telegram bot",
                    "List Cloud Files": "View files in Dropbox",
                    "Download from Cloud": "Download files from Dropbox",
                    "Backup Key to Telegram": "Send master key to Telegram",
                    "Exit": "Exit the application"
                }
            )
            
            if action == "Encrypt File":
                self._encrypt_interactive()
            elif action == "Decrypt File":
                self._decrypt_interactive()
            elif action == "Configure Services":
                self._configure_services()
            elif action == "Generate Master Key":
                self._generate_master_key()
            elif action == "Start Telegram Bot":
                self._start_telegram_bot()
            elif action == "Stop Telegram Bot":
                self._stop_telegram_bot()
            elif action == "List Cloud Files":
                self._list_cloud_files()
            elif action == "Download from Cloud":
                self._download_interactive()
            elif action == "Backup Key to Telegram":
                self._backup_key_to_telegram()
            elif action == "Exit":
                self.ui.print_info("Goodbye!")
                self._cleanup()
                break
            
            print()
    
    def _start_telegram_bot(self):
        """Start the interactive Telegram bot"""
        if not self.config.TELEGRAM_BOT_TOKEN:
            self.ui.print_error("Telegram bot token not configured")
            if self.ui.confirm("Configure now?"):
                self.telegram.configure()
            return
        
        if self.telegram_bot and self.telegram_bot.running:
            self.ui.print_warning("Telegram bot is already running")
            return
        
        self.ui.header("STARTING TELEGRAM BOT")
        self.ui.print_info("Bot will start in polling mode. Press Ctrl+C to stop.")
        
        # Create bot instance
        self.telegram_bot = TelegramBot(self.ui, self.config, self.encryptor, self.dropbox)
        
        # Start bot in a separate thread
        self.bot_thread = threading.Thread(target=self.telegram_bot.start_polling, daemon=True)
        self.bot_thread.start()
        
        # Update config
        self.config.TELEGRAM_BOT_ACTIVE = True
        self.config.save_config()
    
    def _stop_telegram_bot(self):
        """Stop the Telegram bot"""
        if self.telegram_bot and self.telegram_bot.running:
            self.telegram_bot.stop()
            self.telegram_bot = None
            self.bot_thread = None
            self.ui.print_success("Telegram bot stopped")
            
            # Update config
            self.config.TELEGRAM_BOT_ACTIVE = False
            self.config.save_config()
        else:
            self.ui.print_warning("Telegram bot is not running")
    
    def _encrypt_interactive(self):
        """Interactive file encryption"""
        self.ui.header("FILE ENCRYPTION")
        
        # Get file to encrypt
        file_path = Path(self.ui.input_with_prompt("Enter path to file"))
        if not file_path.exists():
            self.ui.print_error("File not found")
            return
        
        # Choose encryption method
        use_password = self.ui.confirm("Use password instead of master key?", default=False)
        
        # Optional output name
        custom_output = self.ui.input_with_prompt(
            "Custom output name (optional)",
            default=""
        )
        
        # Encrypt the file
        encrypted_file, salt = self.encryptor.encrypt_file(
            file_path, 
            use_password=use_password,
            output_name=custom_output if custom_output else None
        )
        
        if not encrypted_file:
            return
        
        # Ask about cloud upload
        if self.ui.confirm("Upload to Dropbox?", default=True):
            if not self.dropbox.is_configured():
                self.ui.print_warning("Dropbox not configured")
                if self.ui.confirm("Configure now?"):
                    self.dropbox.configure()
            
            if self.dropbox.is_configured():
                dropbox_path = self.ui.input_with_prompt(
                    "Dropbox path (optional)",
                    default=""
                )
                dropbox_path, link = self.dropbox.upload_file(
                    encrypted_file,
                    dropbox_path if dropbox_path else None
                )
        
        # Ask about Telegram notification
        if self.telegram.is_configured() and self.ui.confirm("Send notification via Telegram?", default=False):
            message = f"""
🔒 <b>File Encrypted</b>
File: {file_path.name}
Encrypted: {encrypted_file.name}
Method: {"Password" if use_password else "Master Key"}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """
            self.telegram.send_message(message)
        
        # Ask about deleting original
        if self.ui.confirm("Delete original file?", default=False):
            file_path.unlink()
            self.ui.print_success("Original file deleted")
    
    def _decrypt_interactive(self):
        """Interactive file decryption"""
        self.ui.header("FILE DECRYPTION")
        
        # Get file to decrypt
        file_path = Path(self.ui.input_with_prompt("Enter path to encrypted file"))
        if not file_path.exists():
            self.ui.print_error("File not found")
            return
        
        # Determine if password was used
        use_password = self.ui.confirm("Was this file encrypted with a password?", default=False)
        
        # Optional output name
        custom_output = self.ui.input_with_prompt(
            "Custom output name (optional)",
            default=""
        )
        
        # Decrypt the file
        decrypted_file = self.encryptor.decrypt_file(
            file_path,
            use_password=use_password,
            output_name=custom_output if custom_output else None
        )
        
        if decrypted_file and self.ui.confirm("Delete encrypted file?", default=False):
            file_path.unlink()
            # Also delete salt if exists
            salt_file = file_path.with_suffix('')  # Remove .encrypted
            salt_file = Path(str(salt_file) + '.salt')
            if salt_file.exists():
                salt_file.unlink()
            self.ui.print_success("Encrypted file deleted")
    
    def _configure_services(self):
        """Configure cloud services"""
        action = self.ui.menu(
            "SERVICE CONFIGURATION",
            {
                "Configure Dropbox": "Set up Dropbox integration",
                "Configure Telegram": "Set up Telegram bot",
                "Manage Allowed Users": "Set allowed Telegram users",
                "View Current Settings": "Show current configuration",
                "Toggle Auto-Copy": "Toggle automatic link copying",
                "Set Max File Size": "Set maximum file size for Telegram",
                "Back": "Return to main menu"
            }
        )
        
        if action == "Configure Dropbox":
            self.dropbox.configure()
        elif action == "Configure Telegram":
            self.telegram.configure()
        elif action == "Manage Allowed Users":
            self._manage_allowed_users()
        elif action == "View Current Settings":
            self._show_settings()
        elif action == "Toggle Auto-Copy":
            self.config.AUTO_COPY_LINK = not self.config.AUTO_COPY_LINK
            self.config.save_config()
            self.ui.print_success(f"Auto-copy links: {'ON' if self.config.AUTO_COPY_LINK else 'OFF'}")
        elif action == "Set Max File Size":
            self._set_max_file_size()
    
    def _manage_allowed_users(self):
        """Manage allowed Telegram users"""
        self.ui.header("MANAGE ALLOWED USERS")
        
        current_users = self.config.TELEGRAM_ALLOWED_USERS.copy()
        
        self.ui.print_info("Current allowed users:")
        if not current_users:
            self.ui.print_info("  None (all users allowed)")
        else:
            for i, user in enumerate(current_users, 1):
                print(f"  {i}. {user}")
        
        print()
        action = self.ui.menu(
            "USER MANAGEMENT",
            {
                "Add User": "Add a user ID to allowed list",
                "Remove User": "Remove a user from allowed list",
                "Clear All": "Allow all users (remove restrictions)",
                "Back": "Return to settings"
            }
        )
        
        if action == "Add User":
            user_id = self.ui.input_with_prompt("Enter Telegram user ID")
            if user_id and user_id not in current_users:
                current_users.append(user_id)
                self.config.TELEGRAM_ALLOWED_USERS = current_users
                self.config.save_config()
                self.ui.print_success(f"Added user {user_id}")
        
        elif action == "Remove User":
            if current_users:
                print("\nSelect user to remove:")
                for i, user in enumerate(current_users, 1):
                    print(f"  {i}. {user}")
                
                try:
                    choice = int(self.ui.input_with_prompt("Enter number"))
                    if 1 <= choice <= len(current_users):
                        removed = current_users.pop(choice - 1)
                        self.config.TELEGRAM_ALLOWED_USERS = current_users
                        self.config.save_config()
                        self.ui.print_success(f"Removed user {removed}")
                except ValueError:
                    self.ui.print_error("Invalid input")
            else:
                self.ui.print_warning("No users to remove")
        
        elif action == "Clear All":
            self.config.TELEGRAM_ALLOWED_USERS = []
            self.config.save_config()
            self.ui.print_success("All users now allowed")
    
    def _set_max_file_size(self):
        """Set maximum file size for Telegram"""
        self.ui.header("SET MAX FILE SIZE")
        
        current = self.config.MAX_FILE_SIZE_MB
        self.ui.print_info(f"Current maximum: {current} MB")
        
        try:
            new_size = int(self.ui.input_with_prompt("Enter new maximum size in MB", default=str(current)))
            if 1 <= new_size <= 2000:  # Telegram limit is 2GB, but we'll be conservative
                self.config.MAX_FILE_SIZE_MB = new_size
                self.config.save_config()
                self.ui.print_success(f"Max file size set to {new_size} MB")
            else:
                self.ui.print_error("Size must be between 1 and 2000 MB")
        except ValueError:
            self.ui.print_error("Invalid input")
    
    def _show_settings(self):
        """Display current configuration"""
        self.ui.header("CURRENT SETTINGS")
        
        print(f"Dropbox Token: {self._mask_string(self.config.DROPBOX_ACCESS_TOKEN)}")
        print(f"Dropbox App Key: {self._mask_string(self.config.DROPBOX_APP_KEY)}")
        print(f"Telegram Bot Token: {self._mask_string(self.config.TELEGRAM_BOT_TOKEN)}")
        print(f"Telegram Chat ID: {self.config.TELEGRAM_CHAT_ID or 'Not set'}")
        print(f"Telegram Bot Active: {'Yes' if self.config.TELEGRAM_BOT_ACTIVE else 'No'}")
        print(f"Allowed Users: {len(self.config.TELEGRAM_ALLOWED_USERS)} users")
        print(f"Max File Size: {self.config.MAX_FILE_SIZE_MB} MB")
        print(f"Auto-copy links: {'Yes' if self.config.AUTO_COPY_LINK else 'No'}")
        print(f"Color output: {'Yes' if self.config.COLOR_OUTPUT else 'No'}")
        print(f"Session Timeout: {self.config.SESSION_TIMEOUT} seconds")
    
    def _mask_string(self, s: str, visible: int = 4) -> str:
        """Mask a string for display"""
        if not s:
            return "Not set"
        if len(s) <= visible:
            return "*" * len(s)
        return s[:visible] + "*" * (len(s) - visible)
    
    def _generate_master_key(self):
        """Generate a new master key"""
        self.ui.header("MASTER KEY GENERATION")
        
        result = self.encryptor.generate_master_key()
        
        if result == "backup":
            self._backup_key_to_telegram()
    
    def _list_cloud_files(self):
        """List files in Dropbox"""
        if not self.dropbox.connect():
            return
        
        files = self.dropbox.list_files()
        
        if not files:
            self.ui.print_info("No files found in Dropbox")
            return
        
        self.ui.header("DROPBOX FILES")
        for i, file in enumerate(files, 1):
            size = self.dropbox._format_size(file['size'])
            modified = file['modified'].strftime('%Y-%m-%d %H:%M')
            print(f"{i:2d}. {file['name']} ({size}) - {modified}")
    
    def _download_interactive(self):
        """Interactive file download from Dropbox"""
        if not self.dropbox.connect():
            return
        
        files = self.dropbox.list_files()
        
        if not files:
            self.ui.print_info("No files found in Dropbox")
            return
        
        self.ui.header("SELECT FILE TO DOWNLOAD")
        for i, file in enumerate(files, 1):
            size = self.dropbox._format_size(file['size'])
            print(f"{i:2d}. {file['name']} ({size})")
        
        print()
        try:
            choice = int(self.ui.input_with_prompt("Select file number"))
            if 1 <= choice <= len(files):
                selected = files[choice - 1]
                
                local_path = self.ui.input_with_prompt(
                    "Local path to save (optional)",
                    default=selected['name']
                )
                
                self.dropbox.download_file(selected['path'], Path(local_path))
            else:
                self.ui.print_error("Invalid selection")
        except ValueError:
            self.ui.print_error("Invalid input")
    
    def _backup_key_to_telegram(self):
        """Backup master key to Telegram"""
        config = Config()
        
        if not config.ENCRYPTION_KEY_FILE.exists():
            self.ui.print_error("No master key found")
            return
        
        if not self.telegram.is_configured():
            self.ui.print_warning("Telegram not configured")
            if self.ui.confirm("Configure now?"):
                self.telegram.configure()
            else:
                return
        
        self.ui.print_step("Sending master key to Telegram...")
        
        # Send as encrypted message
        success = self.telegram.send_encryption_key(config.ENCRYPTION_KEY_FILE)
        
        if success:
            self.ui.print_success("Master key backed up to Telegram")
            self.ui.print_warning("Make sure to delete the message after saving the key!")
        else:
            self.ui.print_error("Failed to backup key")
    
    def _cleanup(self):
        """Clean up resources"""
        if self.telegram_bot and self.telegram_bot.running:
            self.telegram_bot.stop()
        
        self.encryptor.cleanup_temp_files()
        self.ui.print_info("Cleanup complete")

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def cli_mode():
    """Command line interface mode"""
    parser = argparse.ArgumentParser(description='Secure File Encryptor with Dropbox & Telegram')
    parser.add_argument('action', choices=['encrypt', 'decrypt', 'generate-key', 'config', 'bot'],
                       help='Action to perform')
    parser.add_argument('file', nargs='?', help='File to process')
    parser.add_argument('--password', '-p', action='store_true',
                       help='Use password instead of master key')
    parser.add_argument('--upload', '-u', action='store_true',
                       help='Upload to Dropbox after encryption')
    parser.add_argument('--telegram', '-t', action='store_true',
                       help='Send notification via Telegram')
    parser.add_argument('--output', '-o', help='Output filename')
    parser.add_argument('--dropbox-path', help='Custom Dropbox path')
    parser.add_argument('--no-copy', action='store_true',
                       help='Disable automatic link copying')
    parser.add_argument('--bot-only', action='store_true',
                       help='Run only the Telegram bot')
    
    args = parser.parse_args()
    
    # Initialize app
    app = SecureEncryptorApp()
    
    if args.bot_only:
        app._start_telegram_bot()
        # Keep the bot running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            app._stop_telegram_bot()
        return
    
    if args.action == 'generate-key':
        app.encryptor.generate_master_key()
        return
    
    if args.action == 'config':
        app._configure_services()
        return
    
    if args.action == 'bot':
        app._start_telegram_bot()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            app._stop_telegram_bot()
        return
    
    if not args.file:
        app.ui.print_error("Please specify a file")
        return
    
    file_path = Path(args.file)
    if not file_path.exists():
        app.ui.print_error(f"File not found: {file_path}")
        return
    
    if args.action == 'encrypt':
        # Encrypt file
        encrypted_file, salt = app.encryptor.encrypt_file(
            file_path,
            use_password=args.password,
            output_name=args.output
        )
        
        if encrypted_file and args.upload:
            if app.dropbox.connect():
                dropbox_path, link = app.dropbox.upload_file(
                    encrypted_file,
                    args.dropbox_path
                )
                
                if link and not args.no_copy and CLIPBOARD_AVAILABLE:
                    pyperclip.copy(link)
                    print("Link copied to clipboard!")
        
        if encrypted_file and args.telegram and app.telegram.is_configured():
            message = f"File encrypted: {file_path.name}"
            app.telegram.send_message(message)
    
    elif args.action == 'decrypt':
        # Decrypt file
        decrypted_file = app.encryptor.decrypt_file(
            file_path,
            use_password=args.password,
            output_name=args.output
        )

# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    # Check if running in CLI mode with arguments
    if len(sys.argv) > 1:
        cli_mode()
    else:
        # Run interactive mode
        app = SecureEncryptorApp()
        try:
            app.run()
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
        except Exception as e:
            app.ui.print_error(f"Unexpected error: {e}")
            return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
