import os
import imghdr  # Built-in Python module for image validation
from werkzeug.utils import secure_filename

class FileSecurity:
    def __init__(self, allowed_extensions, max_sizes):
        self.allowed_extensions = allowed_extensions
        self.max_sizes = max_sizes
        # Map extensions to expected magic bytes
        self.signatures = {
            'png': b'\x89PNG',
            'jpg': b'\xFF\xD8\xFF',
            'jpeg': b'\xFF\xD8\xFF',
            'webp': b'RIFF',
            'mp3': b'ID3',
            'wav': b'RIFF',
            'flac': b'fLaC',
            'mp4': b'\x00\x00\x00\x20ftyp',
            'mov': b'\x00\x00\x00\x20ftyp',
            'avi': b'RIFF',
            'webm': b'\x1A\x45\xDF\xA3',
            'mkv': b'\x1A\x45\xDF\xA3'
        }
    
    def allowed_file(self, filename, file_type='image'):
        """Check if file extension is allowed"""
        if not filename or '.' not in filename:
            return False
            
        extensions = self.allowed_extensions.get(file_type, set())
        return filename.rsplit('.', 1)[1].lower() in extensions
    
    def allowed_file_size(self, file, file_type='image'):
        """Check if file size is within limits"""
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        return file_size <= self.max_sizes.get(file_type, 50 * 1024 * 1024)
    
    def is_valid_image(self, file_path):
        """Validate image files using Python's built-in imghdr"""
        try:
            image_type = imghdr.what(file_path)
            return image_type in ['jpeg', 'png', 'gif', 'webp']
        except:
            return False
    
    def is_valid_audio(self, file_path):
        """Validate audio files by checking magic bytes"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(12)
            
            # Check for common audio signatures
            if header.startswith(b'ID3'):  # MP3
                return True
            if header.startswith(b'RIFF') and header[8:12] == b'WAVE':  # WAV
                return True
            if header.startswith(b'fLaC'):  # FLAC
                return True
                
            return False
        except:
            return False
    
    def is_valid_video(self, file_path):
        """Validate video files by checking magic bytes"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
            # Check for common video signatures
            if header.startswith(b'\x00\x00\x00\x20ftyp'):  # MP4, MOV
                return True
            if header.startswith(b'RIFF') and header[8:12] == b'AVI ':  # AVI
                return True
            if header.startswith(b'\x1A\x45\xDF\xA3'):  # WebM, MKV
                return True
                
            return False
        except:
            return False
    
    def is_safe_path(self, basedir, path, follow_symlinks=True):
        """Prevent directory traversal attacks"""
        if follow_symlinks:
            real_path = os.path.realpath(path)
            real_basedir = os.path.realpath(basedir)
        else:
            real_path = os.path.abspath(path)
            real_basedir = os.path.abspath(basedir)
        
        return real_path.startswith(real_basedir)
    
    def validate_file_upload(self, file_stream, filename, file_type='image'):
        """Comprehensive file upload validation"""
        if not file_stream or not filename:
            return False, "No file provided"
        
        # Check extension
        if not self.allowed_file(filename, file_type):
            return False, "Invalid file type"
        
        # Check size
        if not self.allowed_file_size(file_stream, file_type):
            max_size = self.max_sizes.get(file_type, 50 * 1024 * 1024)
            return False, f"File too large (max {max_size//(1024*1024)}MB)"
        
        return True, "File validated"
