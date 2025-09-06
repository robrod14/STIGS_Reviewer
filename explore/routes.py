from flask import Blueprint, render_template_string, request, jsonify
from models import db, STIG
import re


bp = Blueprint('explore', __name__, url_prefix='/explore')


# Load explore.html from file since no templates folder yet
@bp.route('/')
def explore_page():
    with open("explore/explore.html") as f:
        return render_template_string(f.read())


@bp.route('/api/search', methods=['POST'])
def api_search():
    payload = request.get_json() or {}
    filters = payload.get('filters', [])
    query = STIG.query


    for f in filters:
        field = f.get('field')
        op = f.get('op')
        val = f.get('value')
        if not field or not op:
            continue
        col = getattr(STIG, field, None)
        if col is None:
            continue


        if op == 'contains':
            query = query.filter(col.ilike(f"%{val}%"))
        elif op == 'not_contains':
            query = query.filter(~col.ilike(f"%{val}%"))
        elif op == 'equals':
            query = query.filter(col == val)
        elif op == 'regex':
            allrows = query.all()
            pattern = re.compile(val)
            matched_ids = [r.id for r in allrows if pattern.search((getattr(r, field) or ''))]
            query = STIG.query.filter(STIG.id.in_(matched_ids))


    results = [r.to_summary() for r in query.limit(100).all()]
    return jsonify({'results': results})


@bp.route('/api/item/<int:id>', methods=['GET'])
def api_item(id):
    r = STIG.query.get_or_404(id)
    return jsonify(r.to_detail())
