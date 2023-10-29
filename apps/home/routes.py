# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from apps.home import blueprint
from flask import render_template, request, jsonify, url_for
from flask_login import login_required
from jinja2 import TemplateNotFound
import json
import requests

@blueprint.route('/index')
@login_required
def index():

    return render_template('home/index.html', segment='index')


@blueprint.route('/<template>')
@login_required
def route_template(template):

    try:

        if not template.endswith('.html'):
            template += '.html'

        # Detect the current page
        segment = get_segment(request)

        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template("home/" + template, segment=segment)

    except TemplateNotFound:
        return render_template('home/page-404.html'), 404

    except:
        return render_template('home/page-500.html'), 500


# Helper - Extract current page name from request
def get_segment(request):

    try:

        segment = request.path.split('/')[-1]

        if segment == '':
            segment = 'index'

        return segment

    except:
        return None

@blueprint.route('/processcvessite')
def processcvessite():
    file_path = "apps/static/assets/data/nexpose/site_8/all_cves_details_site_8.json"
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            # Return the data as JSON
            return jsonify(data)
    except FileNotFoundError:
        # Handle the error if the file is not found
        return jsonify({'error': 'File not found'}), 404
    except json.JSONDecodeError:
        # Handle the error if the file content is not valid JSON
        return jsonify({'error': 'Error reading JSON data'}), 500
    
@blueprint.route('/processdetaildatajson')
def processdetaildatajson():
    file_path = "apps/static/assets/data/nexpose/site_8/asset_data_detail.json"
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            # Return the data as JSON
            return jsonify(data)
    except FileNotFoundError:
        # Handle the error if the file is not found
        return jsonify({'error': 'File not found'}), 404
    except json.JSONDecodeError:
        # Handle the error if the file content is not valid JSON
        return jsonify({'error': 'Error reading JSON data'}), 500    
    
@blueprint.route('/processassetsjson')
def processassetsjson():
    file_path = "apps/static/assets/data/nexpose/site_8/asset_data.json"
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            # Return the data as JSON
            return jsonify(data)
    except FileNotFoundError:
        # Handle the error if the file is not found
        return jsonify({'error': 'File not found'}), 404
    except json.JSONDecodeError:
        # Handle the error if the file content is not valid JSON
        return jsonify({'error': 'Error reading JSON data'}), 500

@blueprint.route('/processvulnerabilitiesdetailsdatajson')
def processvulnerabilitiesdetailsdatajson():
    file_path = "apps/static/assets/data/nexpose/vulnerabilities_details_data.json"
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            # Return the data as JSON
            return jsonify(data)
    except FileNotFoundError:
        # Handle the error if the file is not found
        return jsonify({'error': 'File not found'}), 404
    except json.JSONDecodeError:
        # Handle the error if the file content is not valid JSON
        return jsonify({'error': 'Error reading JSON data'}), 500
    
@blueprint.route('/processvulnerabilitiesreferences')
def processvulnerabilitiesreferences():
    file_path = "apps/static/assets/data/nexpose/site_8/vulnerabilities_references_in_8.json"
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            # Return the data as JSON
            return jsonify(data)
    except FileNotFoundError:
        # Handle the error if the file is not found
        return jsonify({'error': 'File not found'}), 404
    except json.JSONDecodeError:
        # Handle the error if the file content is not valid JSON
        return jsonify({'error': 'Error reading JSON data'}), 500
    
@blueprint.route('/processvulnerabilitiessolutions')
def processvulnerabilitiessolutions():
    file_path = "apps/static/assets/data/nexpose/site_8/vulnerabilities_solutions_in_8.json"
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            # Return the data as JSON
            return jsonify(data)
    except FileNotFoundError:
        # Handle the error if the file is not found
        return jsonify({'error': 'File not found'}), 404
    except json.JSONDecodeError:
        # Handle the error if the file content is not valid JSON
        return jsonify({'error': 'Error reading JSON data'}), 500
    
@blueprint.route('/processvulnerabilitiesjson')
def processvulnerabilitiesjson():
    file_path = "apps/static/assets/data/nexpose/site_8/vulnerability_table_data.json"
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            # Return the data as JSON
            return jsonify(data)
    except FileNotFoundError:
        # Handle the error if the file is not found
        return jsonify({'error': 'File not found'}), 404
    except json.JSONDecodeError:
        # Handle the error if the file content is not valid JSON
        return jsonify({'error': 'Error reading JSON data'}), 500

    
@blueprint.route('/processgraphdata')
def process_graph_data():
    response = processassetsjson()
    assets_data = response.get_json()  # Extract the JSON data from the Response object
    vulnerabilities_response = processvulnerabilitiesdetailsdatajson()
    vulnerabilities_data = vulnerabilities_response.get_json()     
    # Process the data into a format that can be easily used on the frontend
    graph_data = []
    for asset in assets_data:
        ip_address = None
        for vulnerability in vulnerabilities_data:
            if vulnerability['IP-Address'] == asset['address']:
                ip_address = vulnerability['IP-Address']
                break

        if ip_address:
            graph_data.append({
                'id': asset['id'],
                'name': asset['name'],
                'address': asset['address'],
                'risk_score': asset['risk_score'],
                'num_vulnerabilities': len(vulnerability['Vulnerabilities'])
            })

    return jsonify(graph_data)   