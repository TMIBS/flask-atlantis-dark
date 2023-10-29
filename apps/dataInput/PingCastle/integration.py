from bs4 import BeautifulSoup
import re

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
    #with open("apps/static/assets/data/pingcastle/testa", 'w', encoding='utf-8') as file:
        #file.write(data_points)
    #print("Extracted data points:", data_points["svg_chart"])
    # Integrate the data into specific points in your 'ad.html'
    # Find the target sections in the original 'ad.html' content
    target_sections = soup_ad.find_all('div', class_='col-xs-12 col-md-6 col-sm-6')

    # Assuming that the order of sections in both HTML contents is the same
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

    # Save the updated 'ad.html' content
    with open(output_path, 'w', encoding='utf-8') as file:
        file.write(updated_ad_html_content)

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
    print(extracted_tables)
    print(f"Number of extracted tables: {len(extracted_tables)}")
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

# Usage:
# Specify the paths to the files and the output file
# result_file_path = update_ad_html_with_new_data("path/to/ad.html", "path/to/ad_hc.html", "path/to/output_ad.html")
if __name__ == "__main__":
    ad_html_path = "apps/templates/home/ad.html"
    ad_hc_html_path = "apps/static/assets/data/pingcastle/ad_hc_anwendung1.ads.kdo.de_20220805.html"
    output_path = "apps/static/assets/data/pingcastle/new_ad.html"
    update_ad_html_with_new_data(ad_html_path, ad_hc_html_path, output_path)
    update_ad_html_with_new_tables(ad_html_path, ad_hc_html_path, output_path, aria_labels_of_interest)
    
    
    
