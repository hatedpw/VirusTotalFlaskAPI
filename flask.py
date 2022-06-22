from hashlib import md5
from flask import Flask, request
from flask_restful import Api, Resource
from api.VTApiv2 import *
from api.AccessKeyScan import *

app = Flask(__name__)
api = Api(app)


@app.route('/md5/')
def md5_se():
    return md5_search()

@app.route('/ip/')
def ip_s():
    return ip_search()
      
@app.route('/url/')
def url_s():
    return url_search()

if __name__ == "__main__":
    app.run(debug=True)