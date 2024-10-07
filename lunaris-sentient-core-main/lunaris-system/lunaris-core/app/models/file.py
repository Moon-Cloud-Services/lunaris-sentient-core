from app import db

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    hash = db.Column(db.String(64), unique=True, nullable=False)
    label = db.Column(db.Integer, nullable=False)
    features = db.Column(db.PickleType)