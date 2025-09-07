# helpers/ingest_to_db.py

from flask import current_app
from models import db, STIG


def ingest_records(records):
    """
    Ingests a list of parsed STIG/checklist records into the database.

    Args:
        records (list[dict]): Output of Parser.read_checklist_detailed
    """

    if not records:
        current_app.logger.warning("No records provided for ingestion.")
        return

    objs = []
    for rec in records:
        obj = STIG(
            stig_id=rec.get("stig_id"),
            title=rec.get("title"),
            severity=rec.get("severity"),
            status=rec.get("status"),
            description=rec.get("description", ""),  # sometimes absent in XML
            check_text=rec.get("check_text", ""),
            fix_text=rec.get("fix_text", ""),
            finding_details=rec.get("finding_details", ""),
            comments=rec.get("comments", ""),
            nist_mapping=rec.get("nist_mapping", ""),
            cci_mapping=rec.get("cci_mapping", ""),
        )
        objs.append(obj)

    try:
        db.session.bulk_save_objects(objs)
        db.session.commit()
        current_app.logger.info(f"Ingested {len(objs)} records into the database.")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error ingesting records: {e}")
        raise


def clear_database():
    """
    Clears the STIG table. Use carefully!
    """
    try:
        num_deleted = STIG.query.delete()
        db.session.commit()
        current_app.logger.info(f"Cleared {num_deleted} records from database.")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error clearing database: {e}")
        raise
