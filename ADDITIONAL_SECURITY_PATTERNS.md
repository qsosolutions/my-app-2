# Additional Security Patterns (Python)

## 7. Secure File Uploads
```python
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def upload_file(request):
    if 'file' not in request.files:
        return "No file part"
    file = request.files['file']
    if file.filename == '':
        return "No selected file"
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return "File uploaded successfully"
    return "Invalid file type"
```
---

## 8. Password Hashing
```python
from werkzeug.security import generate_password_hash, check_password_hash

def hash_password(password):
    return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

def verify_password(stored_hash, provided_password):
    return check_password_hash(stored_hash, provided_password)
```
---

## 9. CSRF Protection (Flask-WTF)
```python
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired

class SampleForm(FlaskForm):
    csrf_token = StringField()  # Flask-WTF automatically adds CSRF protection
    name = StringField('Name', validators=[DataRequired()])
```
---

## 10. Secure API Usage (Rate Limiting)
```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route('/api/resource')
@limiter.limit("10/minute")
def resource():
    return "Rate limited resource"
```
---

## 11. Environment Variables for Secrets
```python
import os

SECRET_KEY = os.environ.get('SECRET_KEY', 'default-secret')
DATABASE_PASSWORD = os.environ.get('DB_PASSWORD')
```
---

## 12. HTTP Security Headers (Flask-Talisman)
```python
from flask_talisman import Talisman
Talisman(app)
# This automatically sets secure HTTP headers like HSTS, CSP, X-Frame-Options etc.
```