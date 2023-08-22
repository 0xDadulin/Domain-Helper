from flask import Flask, render_template, request, jsonify,render_template_string,Blueprint,session,flash
import dns.resolver
from blueprints.main_routes import main_routes
from blueprints.components import components
from datetime import datetime,timedelta
import pytz
import ssl
import socket
import http.client
import requests
from flask_session import Session
import os
import pandas as pd
import time
from helpers import *


app = Flask(__name__)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.secret_key = os.environ['app.secret_key']
app.register_blueprint(main_routes)
app.register_blueprint(components)
app.config['SESSION_TYPE'] = 'filesystem'  # Użyj systemu plików do przechowywania sesji
Session(app)
timezone = pytz.timezone('Europe/Warsaw')



@app.route('/check_dns', methods=['POST'])
def check_dns():
    domains = [dom.strip() for dom in request.form.get('domain').split(',')]
    for domain in domains:
        error_page = check_domain(domain)  
        if error_page:
            return error_page
    records_to_fetch = request.form.getlist('record_types')
    all_dns_data = []

    for domain in domains:
        dns_data = {}
        for record_type in records_to_fetch:
            try:
                result = dns.resolver.resolve(domain, record_type)
                if record_type in ["A", "AAAA"]:
                    dns_data[record_type] = ', '.join([ip.address for ip in result])
                elif record_type == "MX":
                    dns_data[record_type] = ', '.join([f"{mx.exchange} ({mx.preference})" for mx in result])
                else:
                    dns_data[record_type] = ', '.join([str(rdata) for rdata in result])
            except Exception as e:
                dns_data[record_type] = f"Błąd: {str(e)}"
        all_dns_data.append({'domain': domain, 'dns_data': dns_data})

        # Zapisywanie statystyk dla każdej domeny
        current_time = datetime.now(timezone).strftime('%Y-%m-%d %H:%M:%S')
        zapisz_statystyke("DNS", domain, current_time)
        if 'dns_history' not in session:
            session['dns_history'] = []

        session['dns_history'].append({
            'all_dns_data': all_dns_data,
            'timestamp': current_time
        })

        session.modified = True  # Informuje Flask, żeby zapisał dane sesji

    session.permanent = True
    return render_template('dns_results.html', all_dns_data=all_dns_data, timestamp=current_time)


@app.route('/check_ssl', methods=['POST'])
def check_ssl():
    domain = request.form.get('ssl_domain')
    error_page = check_domain(domain)

    if error_page:
        return error_page

    # Zapisz dane w sesji od razu, nawet jeśli wystąpi błąd
    current_time = datetime.now(timezone).strftime('%Y-%m-%d %H:%M:%S')
    zapisz_statystyke("SSL", domain, current_time)

    if 'ssl_history' not in session:
        session['ssl_history'] = []

    cert, server_type = get_certificate_info(domain)
    
    # Jeśli nie udało się uzyskać informacji o certyfikacie, informuj użytkownika
    if cert is None or server_type is None:
        session['ssl_history'].append({
            'domain': domain,
            'ssl_data': 'Błąd podczas weryfikacji certyfikatu.',
            'timestamp': current_time
        })
        session.modified = True
        flash('Nie udało się zweryfikować certyfikatu dla podanej domeny. Możliwe, że certyfikat jest nieprawidłowy lub ma zbyt słaby klucz.', 'error')
        return render_template('alert_message.html')

    ssl_data = format_certificate_info(domain, cert, server_type)

    session['ssl_history'].append({
        'domain': domain,
        'ssl_data': ssl_data,
        'timestamp': current_time
    })

    session.modified = True  # Informuje Flask, żeby zapisał dane sesji
    session.permanent = True

    return render_template('ssl_results.html', ssl_data=ssl_data, domain=domain)




@app.route('/whois_checker', methods=['POST'])
def whois_checker():
    domain = request.form.get('domain')
    error_page = check_domain(domain)  
    if error_page:
        return error_page
    print(f'Wyszukiwana domena {domain}')
    api_key = os.environ['whois_api']  
    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&domainName={domain}&outputFormat=json"
    
    try:
        response = requests.get(url)
        if response.status_code == 200:
            json_response = response.json()
            w = json_response.get("WhoisRecord", {})

            # Zapisywanie wyniku w sesji
            current_time = datetime.now(timezone).strftime('%Y-%m-%d %H:%M:%S')
            zapisz_statystyke("Whois", domain, current_time)
            if 'whois_history' not in session:
                session['whois_history'] = []

            session['whois_history'].append({
                'domain': domain,
                'result': w,
                'timestamp': current_time
            })

            session.modified = True
            session.permanent = True
            
            return render_template('whois_results.html', domain=domain, result=w)
        else:
            error_message = {"error": f"Error: {response.status_code}"}
            return render_template('whois_results.html', domain=domain, result=error_message)
    except Exception as e:
        return render_template('whois_results.html', domain=domain, result=f"Błąd: {str(e)}")





app.run(host='0.0.0.0', port=81)


