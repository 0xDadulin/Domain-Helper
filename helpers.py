import re
from datetime import datetime, timedelta
from flask import flash, render_template, session
import pandas as pd
from flask import Flask, render_template, request, jsonify,render_template_string,Blueprint,session,flash
import dns.resolver
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
import plotly.graph_objects as go
import csv


import babel.dates as babel_dates


TIME_LIMIT = timedelta(seconds=5)

def format_date(date_obj):
    return babel_dates.format_date(date_obj, format='d MMM', locale='pl_PL')

def log_error(domain):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open('errors.csv', 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([domain, timestamp])



def zapisz_statystyke(funkcja, domena, current_time):
    plik = "statystyki.csv"
    
    # Spróbuj wczytać istniejący arkusz, jeśli nie istnieje to stworz nowy
    try:
        df = pd.read_csv(plik)
    except FileNotFoundError:
        df = pd.DataFrame(columns=['funkcja', 'domena', 'data_czas'])
    
    # Dodaj nowy wpis
    new_row = {'funkcja': funkcja, 'domena': domena, 'data_czas': current_time}
    df.loc[len(df)] = new_row

    # Zapisz zmieniony arkusz
    df.to_csv(plik, index=False)


def get_certificate_info(host, port=443):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
    try:
        conn.connect((host, port))
        cert = conn.getpeercert()
        server_type = conn.version()
    except ssl.SSLCertVerificationError as e:
        print(f"Błąd weryfikacji certyfikatu dla {host}: {e}")
        return None, None
    finally:
        conn.close()

    return cert, server_type

def format_certificate_info(host, cert, server_type):
    subject = dict(cert['subject'][0])
    issuer = dict(cert['issuer'][0])
    ip = socket.gethostbyname(host)
    expiration_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
    days_to_expire = (expiration_date - datetime.utcnow()).days
    connection = http.client.HTTPSConnection(host)
    connection.request("GET", "/")
    response = connection.getresponse()
    server_info = response.getheader('Server')
  
    days_to_expire = (expiration_date - datetime.utcnow()).days
    ssl_status = "✅" if days_to_expire > 0 else "❌"
  
    return {
        'ssl_status': ssl_status,
        'host': host,
        'ip': ip,
        'server_type': server_info or server_type,
        'days_to_expire': days_to_expire,
        'common_name': subject.get('commonName', 'N/A'),
        'sans': ', '.join([x[1] for x in cert.get('subjectAltName', [])]),
        'organization': subject.get('organizationName', 'N/A'),
        'location': f"{subject.get('stateOrProvinceName', 'N/A')}, {subject.get('countryName', 'N/A')}",
        'valid_from': cert['notBefore'],
        'valid_to': cert['notAfter'],
        'serial_number': cert['serialNumber'],
        'signature_algorithm': 'Nieznany' if 'signatureAlgorithm' not in cert else cert['signatureAlgorithm'],
        'issuer': issuer.get('organizationName', 'N/A')
    }


def generate_plot():
    # Wczytaj dane
    df = pd.read_csv("statystyki.csv")

    # Konwersja daty (zostawiamy tylko część z datą, bez czasu)
    df['data'] = pd.to_datetime(df['data_czas']).dt.date

    # Zakres dat: 15 dni wstecz i 15 dni do przodu
    start_date = datetime.now().date() - timedelta(days=5)
    end_date = datetime.now().date() + timedelta(days=5)
    date_range = pd.date_range(start=start_date, end=end_date, freq='D').date

    # Grupuj według daty i funkcji, a następnie podsumuj
    df_grouped = df.groupby(['data', 'funkcja']).size().reset_index(name='ilosc_wywolan')

    # Pivot table
    df_pivot = df_grouped.pivot(index='data', columns='funkcja', values='ilosc_wywolan').reindex(date_range).fillna(0)

    # Dodaj kolumnę z sumą wszystkich wywołań
    df_pivot['suma'] = df_pivot.sum(axis=1)

    # Tworzenie wykresu
    fig = go.Figure()

    colors = {'DNS': 'blue', 'Whois': 'green', 'SSL': 'red'}

    # Dodaj wykres słupkowy dla każdej funkcji
    for function, color in colors.items():
        fig.add_trace(go.Bar(x=df_pivot.index, y=df_pivot[function], name=function, marker_color=color))

    # Aktualizacja wyglądu wykresu
    fig.update_layout(
        title='Statystyki wywołań funkcji',
        xaxis_title='Dzień',
        yaxis_title='Liczba wywołań',
        barmode='stack',
        xaxis=dict(
            tickvals=df_pivot.index,
            ticktext=[format_date(date) for date in df_pivot.index]
        )
    )
    return fig

def extract_domains(input_string):
    # Usuń wielokrotne spacje
    input_string = re.sub(r'\s+', ' ', input_string)
    
    # Rozdziel na podstawie przecinka i spacji
    domains = re.split(r'[ ,]+', input_string)

    # Usuń puste elementy
    domains = [domain for domain in domains if domain]

    return domains


def check_domain(domain):
    # Sprawdzenie, czy domena nie jest pusta lub czy nie składa się tylko z białych znaków
    if not domain or domain.isspace():
        flash('Proszę podać domenę.', 'error')
        log_error(domain)
        return render_template('alert_message.html')

    # Weryfikacja domeny za pomocą wyrażeń regularnych
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"

    if not re.match(pattern, domain, re.IGNORECASE):
        flash('Niepoprawny format domeny.', 'error')
        log_error(domain)
        return render_template('alert_message.html')

    # Sprawdzenie, czy od ostatniego sprawdzenia tej domeny minął czas określony w TIME_LIMIT
    now = datetime.now()
    if 'LAST_CHECKED' not in session:
        session['LAST_CHECKED'] = {}

    if domain in session['LAST_CHECKED']:
        last_checked_time = datetime.strptime(session['LAST_CHECKED'][domain], '%Y-%m-%d %H:%M:%S')
        if now - last_checked_time < TIME_LIMIT:
            flash(f'Proszę poczekać {TIME_LIMIT.seconds} sekund przed ponownym sprawdzeniem tej domeny.', 'error')
            return render_template('alert_message.html')

    # Aktualizacja czasu sprawdzenia w sesji
    session['LAST_CHECKED'][domain] = now.strftime('%Y-%m-%d %H:%M:%S')
    session.modified = True

    return None  # zwróć None jeśli wszystko jest w porządku