from bs4 import BeautifulSoup
import re

#general data

def extract_general_information_numbers(html_path):
    with open(html_path, 'r', encoding='utf-8') as file:
        html_content = file.read()
     # Fix the HTML attributes
    html_content = fix_html_attributes(html_content)
    soup = BeautifulSoup(html_content, 'html.parser')

    # Extract the required numbers from the given tables
    admin_groups_table = soup.find("table", {"aria-label": "Admin groups list"})
    account_analysis_table = soup.find("table", {"aria-label": "Account analysis list"})
    computer_info_table = soup.find("table", {"aria-label": "Computer information list"})
    os_list_table = soup.find("table", {"aria-label": "Operating System list"})

    # Admin groups list extraction
    headers = admin_groups_table.select("thead th")
    nb_admins_column_index = next((idx for idx, th in enumerate(headers) if "Nb Admins" in th.text), None)
    nb_admins = sum(int(row.select("td")[nb_admins_column_index].text) for row in admin_groups_table.select("tbody tr"))

    # Account analysis list extraction
    nb_users = int(account_analysis_table.select("td.num")[0].text)

    # Computer information list extraction
    nb_computers = int(computer_info_table.select("td.num")[0].text)

    # Operating System list extraction
    headers = os_list_table.select("thead th")
    nb_active_column_index = next((idx for idx, th in enumerate(headers) if "Nb Active" in th.text), None)
    nb_active_systems = sum(int(row.select("td")[nb_active_column_index].text) for row in os_list_table.select("tbody tr"))
    print(nb_admins, nb_active_systems, nb_users, nb_computers)
    return {
        "admins": nb_admins,
        "active_systems": nb_active_systems,
        "users": nb_users,
        "computers": nb_computers
    }

def update_general_information_numbers(ad_html_path, extracted_numbers):
    # Read the 'ad.html' content
    with open(ad_html_path, 'r', encoding='utf-8') as file:
        ad_html_content = file.read()
    
    soup = BeautifulSoup(ad_html_content, 'html.parser')
    
    # For Number of Users
    user_h6 = soup.find("h6", string="Users")
    if user_h6:
        user_number_div = user_h6.find_previous_sibling("div").div
        user_number_div.string = str(extracted_numbers["users"])

    # For Number of Computer Objects
    computer_h6 = soup.find("h6", string="Computer Objects")
    if computer_h6:
        computer_number_div = computer_h6.find_previous_sibling("div").div
        computer_number_div.string = str(extracted_numbers["computers"])

    # For Group Admins
    admin_h6 = soup.find("h6", string="Group Admins ")
    if admin_h6:
        admin_number_div = admin_h6.find_previous_sibling("div").div
        admin_number_div.string = str(extracted_numbers["admins"])

    # For Active Systems
    active_systems_h6 = soup.find("h6", string="Active Systems")
    if active_systems_h6:
        active_systems_number_div = active_systems_h6.find_previous_sibling("div").div
        active_systems_number_div.string = str(extracted_numbers["active_systems"])

    updated_ad_html_content = str(soup)

    output_path = ad_html_path.replace("ad.html", "updated_ad.html")
    
    # Save the updated 'ad.html' content
    with open(output_path, 'w', encoding='utf-8') as file:
        file.write(updated_ad_html_content)

    return output_path



#First Graphic with svgs

def extract_data_points(html_content):
    """
    Extracts specific data points from the provided HTML content.

    Args:
    html_content (str): HTML content as a string.

    Returns:
    dict: Extracted data points as a dictionary.
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    data_sections = []

    # Find all sections that contain the chart-gauge and descriptions
    sections = soup.find_all('div', class_='col-xs-12 col-md-6 col-sm-6')

    for section in sections:
        # Check if this section contains the elements we're interested in
        if section.find_all('div', class_='chart-gauge') and section.find('p', class_='small'):
            data_sections.append(str(section))

    return data_sections

def integrate_data_into_ad_html(ad_html_content, data_sections):
    """
    Integrates extracted data points into the 'ad.html' content.

    Args:
    ad_html_content (str): The HTML content of 'ad.html'.
    data_points (dict): Extracted data points from 'ad_hc...' file.

    Returns:
    str: Updated 'ad.html' content with new data integrated.
    """
    soup_ad = BeautifulSoup(ad_html_content, 'html.parser')
    
    target_sections = soup_ad.find_all('div', class_='col-xs-12 col-md-6 col-sm-6')
    
    for target_section, new_section_content in zip(target_sections, data_sections):
        new_section = BeautifulSoup(new_section_content, 'html.parser')
        target_section.replace_with(new_section)
        
    return str(soup_ad)

def update_ad_html_with_new_data(ad_html_path, ad_hc_html_path, output_path):
    """
    Update 'ad.html' with data extracted from a new 'ad_hc...' HTML file.

    Args:
    ad_html_path (str): File path of the original 'ad.html'.
    ad_hc_html_path (str): File path of the 'ad_hc...' HTML file containing new data.
    output_path (str): File path where the updated 'ad.html' should be saved.

    Returns:
    str: The path to the updated 'ad.html' file.
    """
    # Load the HTML contents
    with open(ad_html_path, 'r', encoding='utf-8') as file:
        ad_html_content = file.read()
    
    with open(ad_hc_html_path, 'r', encoding='utf-8') as file:
        ad_hc_html_content = file.read()

    # Extract data points from 'ad_hc...'
    extracted_data = extract_data_points(ad_hc_html_content)
    #print("Extracted data points:", extracted_data)

    # Integrate the extracted data into 'ad.html'
    updated_ad_html_content = integrate_data_into_ad_html(ad_html_content, extracted_data)
    print(updated_ad_html_content)
    # Save the updated 'ad.html' content
    with open(output_path, 'w', encoding='utf-8') as file:
        file.write(updated_ad_html_content)
    
    #print(extracted_data)   
    #print(updated_ad_html_content == written_content)

    return output_path

# Table data

def extract_specific_tables(html_content, aria_labels):
    """
    Extracts tables from the HTML content based on specific aria-labels.

    Args:
    html_content (str): The HTML content to parse.
    aria_labels (list): A list of aria-label values to match.

    Returns:
    dict: A dictionary containing the matched aria-labels as keys and the corresponding HTML table strings as values.
    """
    # Parse the HTML content
    soup = BeautifulSoup(html_content, 'html.parser')

    # Dictionary to hold the extracted tables
    extracted_tables = {}

    # Iterate over each desired aria-label
    for label in aria_labels:
        # Find all tables with the specific aria-label
        tables = soup.find_all('table', {'aria-label': label})
        
        # Store all found tables
        extracted_tables[label] = []
        for table in tables:
            if table:
                # If the table is found, extract the entire section containing the table
                parent_div = table.find_parent('div', class_='col-md-12 table-responsive')
                if parent_div:
                    # Add the HTML string of the section to the list in the dictionary
                    extracted_tables[label].append(str(parent_div))

    return extracted_tables

def integrate_tables_into_ad_html(ad_html_content, extracted_tables):
    """
    Integrates the extracted tables into the 'ad.html' content.

    Args:
    ad_html_content (str): The HTML content of 'ad.html'.
    extracted_tables (dict): A dictionary containing the extracted tables.

    Returns:
    str: Updated 'ad.html' content with the new tables integrated.
    """
    soup_ad = BeautifulSoup(ad_html_content, 'html.parser')

    for label, new_tables_html_list in extracted_tables.items():
        # Find all original tables based on the aria-label
        original_tables = soup_ad.find_all('table', {'aria-label': label})

        # Only proceed if the number of original tables and new tables are the same
        if len(original_tables) == len(new_tables_html_list):
            for original_table, new_table_html in zip(original_tables, new_tables_html_list):
                if original_table:
                    # Find the parent div for replacement
                    parent_div = original_table.find_parent('div', class_='col-md-12 table-responsive')

                    if parent_div:
                        # Replace the old section with the new one
                        new_section = BeautifulSoup(new_table_html, 'html.parser')
                        parent_div.replace_with(new_section)

    # Convert the updated HTML back to a string
    return str(soup_ad)


def update_ad_html_with_new_tables(ad_html_path, ad_hc_html_path, output_path, aria_labels_of_interest):
    """
    Updates the 'ad.html' file with new tables from the 'ad_hc...' file.

    Args:
    ad_html_path (str): The file path to the original 'ad.html'.
    ad_hc_html_path (str): The file path to the 'ad_hc...' HTML file.
    output_path (str): The file path to save the updated 'ad.html'.
    aria_labels_of_interest (list): A list of aria-labels corresponding to the tables of interest.
    """
    # Read the original 'ad.html' content
    with open(ad_html_path, 'r', encoding='utf-8') as file:
        ad_html_content = file.read()

    # Read the 'ad_hc...' HTML content
    with open(ad_hc_html_path, 'r', encoding='utf-8') as file:
        ad_hc_html_content = file.read()

    # Extract the tables from the 'ad_hc...' HTML content
    extracted_tables = extract_specific_tables(ad_hc_html_content, aria_labels_of_interest)
    #print(extracted_tables)
    #print(f"Number of extracted tables: {len(extracted_tables)}")
    # Integrate the extracted tables into the 'ad.html' content
    updated_html_content = integrate_tables_into_ad_html(ad_html_content, extracted_tables)

    # Write the updated HTML content to a new file
    with open(output_path, 'w', encoding='utf-8') as file:
        file.write(updated_html_content)

    # Read the file back to check if it was written correctly
    with open(output_path, 'r', encoding='utf-8') as file:
        written_content = file.read()

    # Check if there's a difference between what was supposed to be written and what was written.
    #print(updated_html_content)  # Should print True if they are the same
    #print(written_content)

# For adaptation of the shown tables from PingCastle
# Usage:
# Specify the aria-labels for the tables you want to extract
aria_labels_of_interest = [
    "Admin groups list",
    "Operating System list",
    "Account analysis list",
    "Computer information list"
]

def extract_section_by_id(html_content, section_id):
    soup = BeautifulSoup(html_content, 'html.parser')
    section = soup.find(id=section_id)
    return str(section) if section else None

def save_section_to_file(output_path, section_content):
    # Make the code formatted
    soup = BeautifulSoup(section_content, 'html.parser')
    prettified_content = soup.prettify()
    with open(output_path, 'w', encoding='utf-8') as file:
        file.write(prettified_content)

#For fixing problem with false statement in the provided PingCastle HTML
def fix_html_attributes(html_content):
    # Fix the 'aria-label' attribute in the HTML
    fixed_html = re.sub(r'(class="[^"]+?)\s(aria-label="[^"]+?")', r'\1" \2', html_content)
    return fixed_html

# Usage:
# Specify the paths to the files and the output file
# result_file_path = update_ad_html_with_new_data("path/to/ad.html", "path/to/ad_hc.html", "path/to/output_ad.html")
if __name__ == "__main__":
    ad_html_path = "apps/templates/home/ad.html"
    ad_hc_html_path = "apps/static/assets/data/pingcastle/ad_hc_anwendung1.ads.kdo.de_20230911.html"
    output_path = "apps/static/assets/data/pingcastle/new_ad.html"
    numbers = extract_general_information_numbers(ad_hc_html_path)
    updated_html_content = update_general_information_numbers(ad_html_path, numbers)
    update_ad_html_with_new_data(updated_html_content, ad_hc_html_path, output_path)
    #Here the output_path is the input for the next function, so that the overall graphics with the svg are also updated in the final version
    update_ad_html_with_new_tables(output_path, ad_hc_html_path, output_path, aria_labels_of_interest)
    
    # Extract and save sections (for the dashboard)
    # Load the main HTML content
    with open(output_path, 'r', encoding='utf-8') as file:
        main_html_content = file.read()

    numbers_content = extract_section_by_id(main_html_content, "numbers-section")
    save_section_to_file("apps/templates/layouts/pingcastle/ad_numbers.html", numbers_content)

    graphics_content = extract_section_by_id(main_html_content, "graphics-section")
    save_section_to_file("apps/templates/layouts/pingcastle/ad_graphics.html", graphics_content)
