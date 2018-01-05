import os

from flask import Flask


app = Flask(__name__)


if __name__ == '__main__':
    app.run(debug=os.environ.get('DEBUG') == 'True', host='0.0.0.0')
