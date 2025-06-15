from flask import Flask, render_template, request
from crypto_utils import generate_keys, encrypt_message, decrypt_message, load_key

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ''
    private_pem = ''
    public_pem = ''
    error = ''

    if request.method == 'POST':
        action = request.form.get('action')
        message = request.form.get('message', '')
        private_key_input = request.form.get('private_key', '').strip()
        public_key_input = request.form.get('public_key', '').strip()

        try:
            if action == 'generate':
                _, _, private_pem, public_pem = generate_keys()
            elif action == 'encrypt':
                public_key = load_key(public_key_input, is_private=False)
                result = encrypt_message(public_key, message)
            elif action == 'decrypt':
                private_key = load_key(private_key_input, is_private=True)
                result = decrypt_message(private_key, message)
        except Exception as e:
            error = f'Ошибка: {str(e)}'

    return render_template('index.html', result=result,
                           private_pem=private_pem, public_pem=public_pem,
                           error=error)

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
