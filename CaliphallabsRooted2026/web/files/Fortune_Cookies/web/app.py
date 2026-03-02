import re
import uuid
from flask import Flask, request, render_template_string, abort

app = Flask(__name__)

fortunes = {}

def sanitize_html(text):
    try:
        text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL | re.IGNORECASE)
        dangerous_tags = [
            'script', 'iframe', 'object', 'embed', 'applet', 'meta', 'link',
            'base', 'style', 'svg', 'math', 'template', 'frameset', 'frame',
            'noscript', 'xmp', 'plaintext', 'form', 'input', 'button', 'textarea',
            'select', 'option', 'video', 'audio', 'source', 'track', 'canvas', 
            'details', 'summary', 'marquee', 'blink', 'layer', 'ilayer', 'div'
            'bgsound', 'basefont', 'portal', 'isindex', 'shadow', 'vibe', 'data'
        ]
        
        tag_pattern = r'|'.join(dangerous_tags)
        pattern = r'<(/?(?:' + tag_pattern + r'|on\w+))(?:\s+[^>]*?)?>'
    
        def _recursive_strip(current_text):
            match = re.search(pattern, current_text, flags=re.IGNORECASE)
            if match:  
                new_text = re.sub(pattern, '', current_text, count=1, flags=re.IGNORECASE)
                return _recursive_strip(new_text)
            return current_text

        return _recursive_strip(text)
    except:
        return text

@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>🥠 Fortune Cookie Fortune Submitter</title>
        <link rel="stylesheet" href="/static/css/style.css">
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🥠 Fortune Cookie Fortune Submitter</h1>
                <p class="tagline">Share your wisdom with the world!</p>
            </header>
            
            <div class="info-box">
                <p>✨ Have an idea for a fortune cookie? Submit it here! ✨</p>
                <p>Our fortune cookie quality control team will review your submission.</p>
            </div>
            
            <form method="POST" action="/submit" class="fortune-form">
                <label for="fortune">Your Fortune:</label>
                <textarea name="fortune" id="fortune" rows="6" placeholder="You will find happiness in unexpected places..." required></textarea>
                
                <label for="author">Your Name (optional):</label>
                <input type="text" name="author" id="author" placeholder="Anonymous Sage" maxlength="50">
                
                <button type="submit" class="submit-btn">🥠 Submit Fortune</button>
            </form>
        </div>
    </body>
    </html>
    ''')

@app.route('/submit', methods=['POST'])
def submit():
    fortune = request.form.get('fortune', '')
    author = request.form.get('author', 'Anonymous')
    filtered = sanitize_html(fortune)
    fortune_id = str(uuid.uuid4())[:8]
    fortunes[fortune_id] = {'text': filtered, 'author': author}
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Fortune Submitted!</title>
        <link rel="stylesheet" href="/static/css/style.css">
    </head>
    <body>
        <div class="container">
            <div class="success-box">
                <h2>🎉 Fortune Submitted Successfully!</h2>
                <p>Your wisdom has been recorded for posterity.</p>
                
                <div class="action-buttons">
                    <a href="/view/{{ fortune_id }}" class="btn btn-primary">👀 Preview Your Fortune</a>
                    <a href="/report/{{ fortune_id }}" class="btn btn-secondary">📢 Send to Quality Control</a>
                    <a href="/" class="btn btn-link">✍️ Submit Another</a>
                </div>
                
                <div class="fortune-id">
                    Fortune ID: <code>{{ fortune_id }}</code>
                </div>
            </div>
        </div>
    </body>
    </html>
    ''', fortune_id=fortune_id)

@app.route('/view/<fortune_id>')
def view(fortune_id):
    fortune_data = fortunes.get(fortune_id)
    if fortune_data is None:
        abort(404)
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Fortune Preview</title>
        <link rel="stylesheet" href="/static/css/style.css">
        <script src="/static/js/purify.min.js"></script>
    </head>
    <body>
        <div class="container">
            <div class="fortune-display">
                <h2>🥠 Fortune Cookie Preview</h2>
                <div class="cookie-wrapper">
                    <div class="fortune-paper">
                        <div id="fortune-content"></div>
                        <div class="fortune-author">— {{ author }}</div>
                    </div>
                </div>
                <a href="/" class="btn btn-link">← Back to Submission</a>
            </div>
        </div>
        <script>
            var fortune = {{ fortune_text|tojson }};
            var container = document.getElementById('fortune-content');
            container.innerHTML = DOMPurify.sanitize(fortune);
        </script>
    </body>
    </html>
    ''', fortune_text=fortune_data['text'], author=fortune_data['author'])

@app.route('/report/<fortune_id>')
def report(fortune_id):
    try:
        with open('/shared/queue.txt', 'a') as f:
            f.write(fortune_id + '\n')
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Sent to Quality Control</title>
            <link rel="stylesheet" href="/static/css/style.css">
        </head>
        <body>
            <div class="container">
                <div class="success-box">
                    <h2>📬 Sent to Quality Control!</h2>
                    <p>Our fortune cookie quality control specialist will review your submission shortly.</p>
                    <a href="/" class="btn btn-primary">Submit Another Fortune</a>
                </div>
            </div>
        </body>
        </html>
        ''')
    except Exception as e:
        return f'Error: {e}', 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
