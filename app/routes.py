# Staff and Menu. Define URLs, etc.

from flask import Blueprint, render_template, request

from .sniffer import start_sniffing

bp = Blueprint('main', __name__)

@bp.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        filter_str = request.form.get('filter')
        count = int(request.form.get('count', 10))
        timeout = int(request.form.get('timeout', 10))

        print(f"Starting sniff with filter='{filter_str}', count={count}, time={timeout}")
        captured_packets = start_sniffing(filter_str, count, timeout)

        results = [p.summary() for p in captured_packets]

        return render_template('index.html', results=results,

filter_val=filter_str, count_val=count, timeout_val=timeout)

    return render_template('index.html', results=None)