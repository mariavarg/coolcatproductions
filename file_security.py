import os
import magic
from werkzeug.utils import secure_filename

class FileSecurity:
    def __init__(self, allowed_extensions, max_sizes):
        self.allowed_extensions = allowed_extensions
        self.max_sizes = max_sizes
    
    def allowed_file(self, filename, file_type='image'):
        extensions = self.allowed_extensions.get(file_type, set())
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in extensions
    
    def allowed_file_size(self, file, file_type='image'):
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        return file_size <= self.max_sizes.get(file_type, 50 * 1024 * 1024)
    
    def is_valid_image(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                header = f.read(12)
            
            if (header.startswith(b'\xFF\xD8\xFF') or
                header.startswith(b'\x89PNG\r\n\x1a\n') or
                (header[:4] == b'RIFF' and header[8:12] == b'WEBP')):
                return True
                
            return False
        except:
            return False
    
    def is_valid_video(self, file_path):
        try:
            mime = magic.Magic(mime=True)
            file_mime = mime.from_file(file_path)
            return file_mime.startswith('video/')
        except:
            return False
    
    def is_safe_path(self, basedir, path, follow_symlinks=True):
        if follow_symlinks:
            real_path = os.path.realpath(path)
            real_basedir = os.path.realpath(basedir)
        else:
            real_path = os.path.abspath(path)
            real_basedir = os.path.abspath(basedir)
        
        return real_path.startswith(real_basedir)
