from flask import Blueprint, render_template,request

components = Blueprint('components', __name__)

@components.route('/more_records')
def more_records():
    mode = request.args.get('mode', 'basic')
    return render_template('more_records.html', mode=mode)