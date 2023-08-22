from flask import Blueprint, render_template
import pandas as pd
import json
from helpers import *

main_routes = Blueprint('main_routes', __name__)

@main_routes.route('/')
def index():
    # Wczytaj plik CSV
    try:
      statystyki = pd.read_csv("statystyki.csv").to_dict(orient="records")
    except FileNotFoundError:
        statystyki = []
    return render_template('index.html',statystyki=statystyki)

@main_routes.route('/ssl_checker_interface')
def ssl_checker_interface():
    return render_template('ssl_checker.html')

@main_routes.route('/dns_checker_interface')
def dns_checker_interface():
    return render_template('dns_checker.html')

@main_routes.route('/whois_checker_interface')
def whois_checker_interface():
    return render_template('whois_checker.html')

@main_routes.route('/statistics_interface')
def statistics_interface():
    fig = generate_plot()
    plot_json = fig.to_json()
    return render_template('statistics.html', plot=plot_json)
