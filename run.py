# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import os
from  sys import exit
from flask import render_template
from apps.config import config_dict
from apps import create_app
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
from datetime import datetime
# Import Methods for automatically update files
import apps.dataInput.Nexpose.schwachstellen as nexpose


# WARNING: Don't run with debug turned on in production!
DEBUG = (os.getenv('DEBUG', 'False') == 'True')

# The configuration
get_config_mode = 'Debug' if DEBUG else 'Production'

try:
    # Load the configuration using the default values
    app_config = config_dict[get_config_mode.capitalize()]

except KeyError:
    exit('Error: Invalid <config_mode>. Expected values [Debug, Production] ')

app = create_app(app_config)

# Automatically update files
scheduler = BackgroundScheduler()

def run_sequence():
    try:
        site_name = 'KDO-TVM-Systeme'
        site_id = nexpose.find_site_id(site_name)

        # Execute your sequence of functions
        # nexpose.get_cve_details_for_site(site_id)
        nexpose.get_cves_in_site(site_id)
        nexpose.process_asset_data(site_id)
        nexpose.generate_asset_data(site_id)
        nexpose.get_references_in_site(site_id)
        nexpose.get_solutions_in_site(site_id)
        nexpose.generate_vulnerability_table()
        nexpose.get_all_cves()
        nexpose.get_vulnerabilities_details()

        print(f'Sequence completed successfully at {datetime.now()}')
    except Exception as e:
        print(f'Error during sequence run: {e}')
        
# Schedule job_function to be called every day at 00:00
scheduler.add_job(func=run_sequence, trigger='cron', hour=13, minute=2)
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())
if __name__ == "__main__":
    app.run()
