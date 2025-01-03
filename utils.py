# utils.py
from flask import request

def log_action(db, user_id, action, table_name=None, record_id=None):
    """
    Logs user actions into the audit_logs table.
    :param db: Database connection object.
    :param user_id: ID of the user performing the action.
    :param action: Description of the action performed.
    :param table_name: (Optional) Name of the affected table.
    :param record_id: (Optional) ID of the affected record.
    """
    ip_address = request.remote_addr  # Capture the user's IP address
    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO audit_logs (user_id, action, table_name, record_id, ip_address)
        VALUES (%s, %s, %s, %s, %s)
    """, (user_id, action, table_name, record_id, ip_address))
    db.commit()