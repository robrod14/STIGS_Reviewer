from flask_sqlalchemy import SQLAlchemy
from datetime import datetime


db = SQLAlchemy()


class STIG(db.Model):
    __tablename__ = 'stigs'
    id = db.Column(db.Integer, primary_key=True)
    stig_id = db.Column(db.String(120), index=True)
    title = db.Column(db.Text, index=True)
    description = db.Column(db.Text)
    check_text = db.Column(db.Text)
    fix_text = db.Column(db.Text)
    finding_details = db.Column(db.Text)
    comments = db.Column(db.Text)
    nist_cci = db.Column(db.Text)
    severity = db.Column(db.String(50), index=True)
    status = db.Column(db.String(50), index=True)
    hostname = db.Column(db.String(200), index=True, nullable=True)
    content_blob = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


    def to_summary(self):
        return {
            'id': self.id,
            'stig_id': self.stig_id,
            'title': self.title,
            'severity': self.severity,
            'status': self.status,
        }


    def to_detail(self):
        return {
            'id': self.id,
            'stig_id': self.stig_id,
            'title': self.title,
            'description': self.description,
            'check_text': self.check_text,
            'fix_text': self.fix_text,
            'finding_details': self.finding_details,
            'comments': self.comments,
            'nist_cci': self.nist_cci,
            'severity': self.severity,
            'status': self.status,
            'hostname': self.hostname,
    }
