from models import db, STIG


def ingest_list(parsed_stigs):
    """Take a list of dicts from your parser and insert into DB."""
    for s in parsed_stigs:
        obj = STIG(
            stig_id=s.get('stig_id'),
            title=s.get('title'),
            description=s.get('description'),
            check_text=s.get('check_text'),
            fix_text=s.get('fix_text'),
            finding_details=s.get('finding_details'),
            comments=s.get('comments'),
            nist_cci=s.get('nist_cci'),
            severity=s.get('severity'),
            status=s.get('status'),
            hostname=s.get('hostname'),
            content_blob=s.get('raw')
        )
        db.session.add(obj)
    db.session.commit()
