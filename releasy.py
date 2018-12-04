from collections import defaultdict, Counter
from datetime import datetime, timedelta
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from httplib2 import Http
from oauth2client.service_account import ServiceAccountCredentials
from xml.dom import minidom, Node


import configparser
import csv
import errno
import gspread
import json
import logging
import os
import pandas as pd
import pyjokes
import re
import requests
import shutil
import smtplib
import subprocess
import sys
import xml.etree.ElementTree as ET
import xmltodict
import zipfile


def setup_conf():

    # Read config values from config.ini.
    CONF = configparser.ConfigParser()
    cini = open('config.ini','r')
    CONF.read_file(cini)
    cini.close()

    # Override with Heroku's config vars (if they are set).
    for key, confs in CONF.iteritems():
        for conf, val in confs.iteritems():
            override = os.environ.get(conf.upper(), None)
            if override:
                CONF.set(key, conf, override)

    # If credentials file does not exist, try to create it from Heroku's config var.
    if not os.path.isfile(CONF['LOCATIONS']['CREDENTIALS_FILE']):
        heroku_creds = os.environ.get('GOOGLE_SHEET_CREDENTIALS', None)
        if heroku_creds:
            path = os.path.dirname(CONF['LOCATIONS']['CREDENTIALS_FILE'])
            try:
                os.makedirs(path)
            except OSError as exc:
                if exc.errno == errno.EEXIST and os.path.isdir(path):
                    pass
                else: raise

            file = open(CONF['LOCATIONS']['CREDENTIALS_FILE'], 'w') 
            file.write(heroku_creds)
            file.close()
        else: print 'Could not read or create GSheet credentials file'

    return CONF


CONF = setup_conf()


class Logger:
    
    def setup_logger():
        logger = logging.getLogger('my_logger')
        if not logger.handlers:
            formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s',
                                          datefmt='%Y-%m-%d %H:%M:%S')
            handler = logging.FileHandler(CONF['LOCATIONS']['LOG_FILE'], mode='w')
            handler.setFormatter(formatter)
            screen_handler = logging.StreamHandler(stream=sys.stdout)
            screen_handler.setFormatter(formatter)
            logger.setLevel(logging.DEBUG)
            logger.addHandler(handler)
            logger.addHandler(screen_handler)

        return logger
    
    log = setup_logger()


class Helper:
    
    @staticmethod
    def execute(cmd):
        ' Takes a command and executes it in the terminal. '

        popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 universal_newlines=True, bufsize=1)
        out, err = popen.communicate()

        # Print (and return) stderr if command failed.
        return_code = popen.wait()
        if return_code:
            try:
                if len(err) > 0:
                    Logger.log.error('COMMAND FAILED WITH RETURN CODE ' + str(return_code))
                    err = json.loads(err.splitlines()[0])
                    if 'name' in err and err['name'] == 'mdapiDeployFailed': return err
                    elif 'stack' in err and 'ERROR_HTTP_400' in err['stack']:
                        errors = json.loads(err['stack'].replace('ERROR_HTTP_400: ', '').splitlines()[0])['results']
                        fields = set()
                        for error in errors:
                            fields.update(error['errors'][0]['fields'])
                        return list(fields)
                    elif 'message' in err:                 Logger.log.error(err['message'])
                    else:                                  Logger.log.error(err)
            except Exception as e:
                Logger.log.error(err)

        return out
    
    @staticmethod
    def remove(target):
        ' Removes a file or folder. '
        if os.path.exists:
            if os.path.isfile(target):
                os.remove(target)
                Logger.log.info('Removed file ' + target)
                return
            if os.path.isdir(target):
                shutil.rmtree(target)
                Logger.log.info('Removed folder ' + target)
                return
        Logger.log.warning('Could not remove ' + target)
    
    @staticmethod
    def to_sf_datetime(date):
        ' Converts Python datetime to SF datetime. '
        return date.strftime('%Y-%m-%dT%H:%M:%S.000+0000')
    
    @staticmethod
    def ready_to_push(row, include_all=False):
        ' Determines if row is ready to be pushed. '
        # If include_all=True, include all components with a Ready to Push Date.
        if include_all:
            return not pd.isnull(row[CONF['SHEET']['READY_TO_PUSH_DATE']])
        # Else, include only components where the Ready to Push Date is later than the Last Push Date.
        else:
            return (row[CONF['SHEET']['READY_TO_PUSH_DATE']] > row[CONF['SHEET']['LAST_PUSH_DATE']]) or \
                   (not pd.isnull(row[CONF['SHEET']['READY_TO_PUSH_DATE']]) and \
                    pd.isnull(row[CONF['SHEET']['LAST_PUSH_DATE']]) and datetime.today() > row[CONF['SHEET']['READY_TO_PUSH_DATE']])

    @staticmethod
    def remove_file(filename):
        ' Removes a file. '
        if os.path.exists(filename): os.remove(filename)

    @staticmethod
    def merge_dirs(source, dest, indent=0):
        ' Copies a directory structure, overwriting existing files. '
    
        # Based on https://gist.github.com/dreikanter/5650973.
        for root, dirs, files in os.walk(source):
            if not os.path.isdir(root): os.makedirs(root)
            for each_file in files:
                if 'package.xml' in each_file: continue
                rel_path = root.replace(source, '').lstrip(os.sep)
                dest_path = os.path.join(dest, rel_path, each_file)
                if not os.path.exists(dest_path):
                    shutil.copyfile(os.path.join(root, each_file), dest_path)
                    Logger.log.info('Added ' + each_file + ' to ' + dest)
                    
    @staticmethod
    def find_new_components(components, new_components):
        '''
        Takes two component dicts, returns a dict with components
        that are in the second one but not in the first.
        '''

        missing = defaultdict(list)

        for md_name, md_members in new_components.items():
            for md_member in md_members:
                if md_name not in components or md_member not in components[md_name]:
                    missing[md_name].append(md_member)

        return missing
    
    @staticmethod
    def execute_apex(apex_code, org=CONF['DEPLOYMENT']['DEFAULT_SOURCE_ORG']):
        ' Takes Apex code, executes it and returns the logs. '
        
        # Write the Apex code to a file, execute the code, and then remove the file again.
        with open('code.apex', 'a') as apex_file:
            apex_file.write(apex_code)

        output = Helper.execute(['sfdx', 'force:apex:execute', '-f', 'code.apex', '-u', org, '--json'])

        Helper.remove_file('code.apex')

        # Create a code slice for logging purposes.
        apex_slice = apex_code[:50] + '[...]' if len(apex_code) > 100 else apex_code

        # Extract the log lines from the output.
        try:
            output = json.loads(output)
            if 'result' in output and 'logs' in output['result']:
                logs = output['result']['logs'].split('\n')
                Logger.log.info('Successfully executed Apex code "{}" on {}'.format(apex_slice, org))
                return logs
        except:
            Logger.log.error('Error executing Apex code "{}" on {}'.format(apex_slice, org))


class GSheet:
    
    def __init__(self):
        credentials = ServiceAccountCredentials.from_json_keyfile_name(CONF['LOCATIONS']['CREDENTIALS_FILE'], 'https://www.googleapis.com/auth/spreadsheets')
        self.gc = gspread.authorize(credentials)
        
        self.manifest = self.get_manifest()
        
    def get_manifest(self):
        ' Returns the SHEET_KEY as a DataFrame. '

        # Get manifest and convert it to a DataFrame.
        manifest = self.gc.open_by_key(CONF['SHEET']['SHEET_KEY'])
        manifest = pd.DataFrame(manifest.worksheet(CONF['SHEET']['MANIFEST_TAB']).get_all_records())

        # Convert the two date columns to datetime.
        manifest[CONF['SHEET']['READY_TO_PUSH_DATE']] = pd.to_datetime(manifest[CONF['SHEET']['READY_TO_PUSH_DATE']])
        manifest[CONF['SHEET']['LAST_PUSH_DATE']] = pd.to_datetime(manifest[CONF['SHEET']['LAST_PUSH_DATE']], errors='coerce')

        return manifest
    
    @staticmethod
    def filter_manifest(manifest, md_type):
        '''
        Takes a manifest and metadata type, returns an (API Name,
        Developer) dict for all manifest rows of that MD type.
        '''
        
        filtered = {}

        for index, row in manifest.iterrows():
            if row[CONF['SHEET']['MD_TYPE']] == md_type:
                filtered[row[CONF['SHEET']['API_NAME']]] = row[CONF['SHEET']['DEVELOPER']]

        return filtered
    
    @staticmethod
    def get_deploy_date(self):
        ' Returns the first future deploy date. '

        # Get deployment worksheet and convert it to a DataFrame.
        manifest = self.gc.open_by_key(CONF['SHEET']['SHEET_KEY'])
        manifest = pd.DataFrame(manifest.worksheet(CONF['SHEET']['DEPLOYMENTS_TAB']).get_all_records())

        # Convert the deployment date column to datetime.
        manifest[CONF['SHEET']['DEPLOYMENT_DATE']] = pd.to_datetime(manifest[CONF['SHEET']['DEPLOYMENT_DATE']])

        # Find the first deployment date that lies in the future.
        for dep_date in manifest[CONF['SHEET']['DEPLOYMENT_DATE']]:
            if dep_date > datetime.now():
                return dep_date.to_pydatetime()

        Logger.log.warning('No next deployment date found')

        return None
    
    @staticmethod
    def get_developer_overview(manifest):
        '''
        Takes a manifest DataFrame, returns a dictionary
        with pushed/not pushed items per developer.
        '''

        devdict = defaultdict(lambda: defaultdict(list))

        # For each developer, create a list with included and excluded components.
        for index, row in manifest.iterrows():
            if row[CONF['SHEET']['DEVELOPER']] == '': continue
            key = 'included' if Helper.ready_to_push(row) else 'excluded'
            devdict[row[CONF['SHEET']['DEVELOPER']]][key].append(row[CONF['SHEET']['MD_TYPE']] + ' - ' + row[CONF['SHEET']['API_NAME']])

        return devdict
    
    @staticmethod
    def find_column_number(self, cellName):
        " Finds a cell's column number. "
        manifest = self.gc.open_by_key(CONF['SHEET']['SHEET_KEY'])
        worksheet = manifest.worksheet(CONF['SHEET']['MANIFEST_TAB'])
        try:
            return worksheet.find(cellName).col
        except:
            return None
    
    @staticmethod
    def update_last_push_date(self, components, environment):
        '''
        Takes a dictionary of pushed components,
        updates the Google Sheet's "Last Push Date"
        column based on that dictionary + puts a "Y"
        in the appropriate environment column (e.g. TEST).
        '''

        # Find column numbers based on column names.
        col_number = {
            'mdType'      : GSheet.find_column_number(self, CONF['SHEET']['MD_TYPE']),
            'apiName'     : GSheet.find_column_number(self, CONF['SHEET']['API_NAME']),
            'lastPushDate': GSheet.find_column_number(self, CONF['SHEET']['LAST_PUSH_DATE']),
            'environment' : GSheet.find_column_number(self, environment),
        }

        # Get table with metadata components.
        manifest = self.gc.open_by_key(CONF['SHEET']['SHEET_KEY']).worksheet(CONF['SHEET']['MANIFEST_TAB'])
        table = manifest.range('A2:' + chr(ord('a') + GSheet.find_column_number(self, environment)-1).upper() + '1000')

        today = datetime.today().strftime('%d %b %Y')
        md_type = ''
        changed = False
        updated_rows_counter = 0

        for cell in table:
            # Reset 'changed' flag for every new row.
            if cell.col == 1:
                changed = False
                md_type = ''

            # Check if (MD Type, API Name) combination is in dict of pushed components.
            if cell.col == col_number['mdType']:
                md_type = cell.value
            elif cell.col == col_number['apiName'] and md_type in components and cell.value in components[md_type]:
                changed = True

            # If this row represents a pushed component, update the Last Push Date column.
            elif cell.col == col_number['lastPushDate'] and changed:
                cell.value = today
                updated_rows_counter += 1

            elif cell.col == col_number['environment'] and changed:
                cell.value = 'Y'
        
        manifest.update_cells(table)
        Logger.log.info('Updated Last Push Date column of ' + str(updated_rows_counter) + ' rows in the manifest')
    
    def update_components_tab(self, component_cells, headers):
        ' Updates the Components tab based on a list. '
        
        worksheet = self.gc.open_by_key(CONF['SHEET']['SHEET_KEY']).worksheet(CONF['SHEET']['COMPONENTS_TAB'])
        worksheet.clear()
        
        # Calculate the cell range.
        no_of_rows = int(len(component_cells) / len(headers) + 1)
        cell_range = worksheet.range('A1:' + chr(len(headers)+64) + str(no_of_rows))

        # Insert the new cell values into the range.
        cell_values = headers + component_cells
        for i, cell in enumerate(cell_range):
            cell.value = cell_values[i]

        # Update the range with the new values.
        worksheet.update_cells(cell_range)
        
        Logger.log.info('Successfully added {} components to the manifest'.format(no_of_rows-1))


class Package:

	def __init__(self, include_all=False, components=None, destructive=False):
	    self.sheet = GSheet()
	    self.components = components if components else self.generate_components(self.sheet.manifest, include_all)
	    self.xml = self.generate_package_xml(self.components)
	    
	    if destructive:
	        self.unpackaged = self.generate_destructive_xml(self.components)  

	def generate_components(self, manifest, include_all=False):
	    '''
	    Takes a manifest DataFrame, returns a dictionary
	    with all components that need to be pushed.
	    '''

	    components = defaultdict(list)    

	    # For each record, check if a new push is required.
	    for index, row in manifest.iterrows():
	        if Helper.ready_to_push(row, include_all) and row[CONF['SHEET']['MD_TYPE']] != '':
	            components[row[CONF['SHEET']['MD_TYPE']]].append(row[CONF['SHEET']['API_NAME']].strip())

	    Logger.log.info('Found ' + str(sum(len(v) for v in components.values())) + ' components ready to be pushed')

	    return components

	def generate_package_xml(self, components, filename=None):
	    '''
	    Takes a dict with MD components,
	    returns a Package.xml based on that.
	    '''

	    xml = minidom.Document()

	    # Add 'Package' tag, which will contain all others.
	    package = xml.createElement('Package')
	    package.setAttribute('xmlns', 'http://soap.sforce.com/2006/04/metadata')
	    xml.appendChild(package)

	    for md_name, md_members in components.items():
	        # Add 'types' tag for metadata component, and include 'name' tag as child.
	        tag_type = xml.createElement('types')
	        package.appendChild(tag_type)

	        tag_name = xml.createElement('name')
	        tag_name.appendChild(xml.createTextNode(md_name))
	        tag_type.appendChild(tag_name)

	        # Add all components as children to the 'types' tag.
	        for md_member in md_members:
	            tag_member = xml.createElement('members')
	            tag_member.appendChild(xml.createTextNode(md_member))
	            tag_type.appendChild(tag_member)

	    # Add tag with metadata version.
	    tag_version = (xml.createElement('version'))
	    tag_version.appendChild(xml.createTextNode(str(float(CONF['DEPLOYMENT']['MD_API_VERSION']))))
	    package.appendChild(tag_version)

	    # Generate the filename if user did not specify one, and store the package.
	    if not filename: filename = CONF['LOCATIONS']['PACKAGE_FOLDER'] + '/package_' + datetime.now().strftime('%Y_%m_%d_%H_%M_%S') + '.xml'
	    xml_content = xml.toprettyxml(encoding='UTF-8', indent = '    ')

	    with open(filename, 'w') as f:
	        f.write(xml_content)

	    Logger.log.info('Created ' + filename.replace(CONF['LOCATIONS']['PACKAGE_FOLDER'] + '/', ''))

	    return filename

	def generate_destructive_xml(self, components):
	    '''
	    Takes a dict with components and generates a
	    destructive package based on that.
	    '''
	    
	    # Create a directory for the destructive changes package.
	    destructive_dir = CONF['LOCATIONS']['RETRIEVE_FOLDER'] + '/destructive_' + datetime.now().strftime('%Y_%m_%d_%H_%M_%S')
	    if not os.path.isdir(destructive_dir): os.mkdir(destructive_dir)

	    # Create an emtpy package.xml.
	    package_xml = open(destructive_dir + '/package.xml', 'w') 
	    package_xml.write('<?xml version="1.0" encoding="UTF-8"?><Package xmlns="http://soap.sforce.com/2006/04/metadata"><version>43.0</version></Package>') 
	    package_xml.close()

	    # Generate a destructiveChanges.xml.
	    destroy_components = ''
	    for md_name, md_members in components.items():
	        destroy_components += '<types><name>' + md_name + '</name>'
	        for md_member in md_members:
	            destroy_components += '<members>' + md_member + '</members>'
	        destroy_components += '</types>'

	    # Create the destructiveChanges.xml
	    destructive_xml = open(destructive_dir + '/destructiveChanges.xml', 'w') 
	    destructive_xml.write('<?xml version="1.0" encoding="UTF-8"?><Package xmlns="http://soap.sforce.com/2006/04/metadata">' + destroy_components + '</Package>')
	    destructive_xml.close()

	    Logger.log.info('Successfully generated destructive package {}'.format(destructive_dir))

	    return destructive_dir

	#### FUNCTIONS CALLING OTHER CLASSES ####

	def get_deployment_info(self):
	    apex_classes = GSheet.filter_manifest(self.sheet.manifest, 'ApexClass')
	    apex_classes = {k:v for k,v in apex_classes.items() if not k.startswith('webm__')}
	    self.apex_coverage = DeploymentInfo.test_apex_coverage(apex_classes)
	    self.audit_trail = DeploymentInfo.search_audit_trail('created')
	    Logger.log.info('Successfully retrieved deployment info')
	    
	def mail_deployment_update(self, preview_only=False):
	    devdict = GSheet.get_developer_overview(self.sheet.manifest)
	    mailer = Mailer()
	    mailer.mail_deployment_update(self.sheet, devdict, self.apex_coverage, self.audit_trail, preview_only)
	    
	def retrieve(self, source=CONF['DEPLOYMENT']['DEFAULT_SOURCE_ORG'], unpackaged_folder=None):
	    self.unpackaged = Releaser.retrieve(self.xml, source, unpackaged_folder)
	    
	def retrieve_update(self):
	    self.components = Releaser.retrieve_update(self)
	        
	def deploy(self, test_level='RunLocalTests', check_only=True, target=CONF['DEPLOYMENT']['DEFAULT_TARGET_ORG']):
	    if self.unpackaged: Releaser.deploy(self.unpackaged, test_level=test_level, check_only=check_only, target=target)
	    else:               Logger.log.error('Cannot deploy a package that has not been retrieved yet')
	        
	def update_sheet(self, environment='TEST'):
	    GSheet.update_last_push_date(self.sheet, self.components, environment)


class DeploymentInfo():

	@staticmethod
	def test_apex_coverage(apex_classes, insufficient_only = False):
	    '''
	    Takes a dictionary with Apex classes.
	    returns a dict with the ones that have
	    insufficient test coverage (including the developer).
	    '''

	    # Execute SFDX apex test run with all classes in 'apex'.
	    if len(apex_classes) == 0: return {}
	    coverage = Helper.execute(['sfdx', 'force:apex:test:run', '-u', CONF['DEPLOYMENT']['DEFAULT_SOURCE_ORG'], '-r', 'json', '-w', '10', '--codecoverage', '-n', ','.join(apex_classes.keys())]) 
	    
	    try:
	        coverage = json.loads(coverage)
	    except Exception as e:
	        Logger.log.warning('Apex test run failed with error: ' + str(e))
	        coverage = {}

	    testcoverage = {}

	    # Generate a classname:coverageDetails dictionary.
	    for tested_class in coverage['result']['coverage']['coverage']:
	        if ((insufficient_only == False) or (insufficient_only and tested_class['coveredPercent'] < 80)) and tested_class['coveredPercent']:
	            developer = apex_classes[tested_class['name']] if tested_class['name'] in apex_classes else None
	            tested_class['developer'] = developer
	            testcoverage[tested_class['name']] = tested_class

	    return testcoverage

	@staticmethod
	def search_audit_trail(keyword, date=datetime.now()):
	    '''
	    Takes a keyword and date, returns all records in
	    the Setup Audit Trail matching that keyword from that
	    specific date in a <developer : list of records> dict.
	    '''

	    today = Helper.to_sf_datetime(date)
	    yesterday = Helper.to_sf_datetime(date-timedelta(1))

	    trail = Helper.execute(['sfdx', 'force:data:soql:query', '-q',
	                     'SELECT Id, Action, CreatedBy.Email, CreatedDate, Display \
	                      FROM SetupAuditTrail \
	                      WHERE CreatedDate > ' + yesterday + ' \
	                      AND CreatedDate < ' + today,
	                     '-u', CONF['DEPLOYMENT']['DEFAULT_SOURCE_ORG'], '--json'])
	    trail = json.loads(trail)

	    matches = defaultdict(list)

	    for record in trail['result']['records']:
	        if re.search(keyword, record['Display'], re.IGNORECASE):
	            developer = record['CreatedBy']['Email'] if record['CreatedBy'] else 'Unknown'
	            matches[developer].append(record['Display'])

	    return matches


class MailerHelper:

    @staticmethod
    def list_coverage(coverage):
        ' Returns a string with all insufficiently covered classes. '

        output = ''

        for apex_class, details in coverage.items():
            covered_percent = details['coveredPercent']
            if covered_percent < 80:
                if not details['developer']: details['developer'] = 'ANONYMOUS'
                output += '* ' + apex_class + ' - ' + details['developer'] + ' - ' + str(covered_percent) + '%\n'

        if len(output) > 0: output = 'APEX CLASSES LACKING COVERAGE\n' + output + '\n\n'

        return output

    @staticmethod
    def list_components(overview, coverage, title):
        ' Returns a string with all components and their coverage. '

        output = title + '\n'

        if len(overview) > 0:

            # Loop over all components, and include their test coverage if known.
            for component in sorted(overview):
                if component.split(' - ')[1] in coverage:
                    covered_percent = coverage[component.split(' - ')[1]]['coveredPercent']
                    output += '* ' + component + ' (' + str(round(covered_percent)) + '% covered)'
                    if covered_percent > 80: output += '\n'
                    else:                    output += ' <-- FIX ASAP!\n'
                else:
                    output += '* ' + component + '\n'
            output += '\n'
        else:
            output += 'None\n\n'

        return output

    @staticmethod
    def list_audit_trail_changes(audit_trail, developer=None):
        ' Returns a string with all Audit Trail changes (for a specific developer). '

        output = ''

        # If no developer was specified, list all changes.
        if not developer:
            for developer, changes in audit_trail.items():
                for change in changes:
                    output += '* ' + change + ' - ' + developer + '\n'

            if len(output) > 0: output = 'CREATED COMPONENTS\n' + output + '\n\n'

        # List only the changes of the specified developer.
        elif developer in audit_trail:
            for record in audit_trail[developer]:
                output += '* ' + record + '\n'
            output = 'WARNING: You added ' + str(len(audit_trail[developer])) + ' component(s) ' \
                     'in the last 24 hours. Consider adding them to the Manifest:\n' + output + '\n'

        return output


class Mailer:
    
    def generate_attachment(self, devdict, coverage, audit_trail, depdate):
        '''
        Takes coverage and audit_trail dicts, generates an
        overview of coverage-lacking classes + audit trail
        changes that are relevant for all developers.
        '''

        output = 'NEXT DEPLOYMENT ON ' + depdate.strftime('%d %B at %I:%M %p').upper() + '\n\n----\n\n'

        # List Apex classes lacking coverage and Audit Trail changes.
        output += MailerHelper.list_coverage(coverage)
        output += MailerHelper.list_audit_trail_changes(audit_trail)

        # List included/excluded items.
        included, excluded = [], []

        for developer, overview in devdict.items():
            included.extend(overview['included'])
            excluded.extend(overview['excluded'])

        output += MailerHelper.list_components(sorted(included), coverage, 'INCLUDED IN NEXT DEPLOYMENT')
        output += '\n' + MailerHelper.list_components(sorted(excluded), coverage, 'EXCLUDED FROM NEXT DEPLOYMENT')

        # Save output to file.
        filename = datetime.today().strftime('deployment_report_%d_%m_%y.txt')  
        attachment = open(filename, 'w')
        attachment.write(output.encode('utf-8'))
        attachment.close()

        return filename
    
    def mail_deployment_update(self, sheet, devdict, apex_coverage, audit_trail, preview_only=False):
        '''
        Pretty print the included/excluded overview
        (generated by get_developer_overview) per developer.
        '''

        depdate = GSheet.get_deploy_date(sheet)

        # Correctly set the subject and generic body.
        subject = CONF['MAIL']['SUBJECT'].replace('%DATE', datetime.now().strftime('%d %b %Y'))
        gBody   = CONF['MAIL']['BODY'].replace('%DEPDATE', depdate.strftime('%d %B at %I:%M %p'))
        gBody   = gBody.replace('%DAYSREM', str((depdate.date() - datetime.date(datetime.now())).days))
        gBody   = gBody.replace('%URL', 'https://docs.google.com/spreadsheets/d/' + CONF['SHEET']['SHEET_KEY'])
        gBody   = gBody.replace('%PUSHCOL', CONF['SHEET']['READY_TO_PUSH_DATE'])
        gBody   = gBody.replace('%JOKE', pyjokes.get_joke())

        # Generate daily overview attachment.
        attachment = self.generate_attachment(devdict, apex_coverage, audit_trail, depdate)
        with open(attachment, 'rb') as att:
            att_part = MIMEApplication(att.read(), Name=attachment)
        att_part['Content-Disposition'] = 'attachment; filename="%s"' % attachment
        
        # Find all Apex classes which need coverage, but don't have a developer.
        anon_need_coverage = {}
        for apex_class, details in apex_coverage.items():
            if not details['developer'] and details['coveredPercent'] < 80:
                anon_need_coverage[apex_class] = details['coveredPercent']
                
        # Add warnings for these anonymous Apex classes.
        apex_warning = ''
        if len(anon_need_coverage) > 0:
            apex_warning += 'WARNING: The following Apex classes lack test coverage, but have no associated developer:\n'
            for apex_class, covered_percent in anon_need_coverage.items():
                apex_warning += apex_class + ' (' + str(int(covered_percent)) + '% covered)\n'
            apex_warning += '\n'

        for developer, overview in devdict.items():
            mail = MIMEMultipart()
            mail['From'] = CONF['MAIL']['FROM_NAME'] + ' <' + CONF['MAIL']['FROM_MAIL'] + '>'
            mail['To'] = developer
            mail['Subject'] = subject
            body = gBody.replace('%NAME', developer.split('@')[0])

            # List all included and excluded components for this developer.
            components = ''
            components += MailerHelper.list_components(overview['included'], apex_coverage, 'INCLUDED')
            components += MailerHelper.list_components(overview['excluded'], apex_coverage, 'EXCLUDED')
            body = body.replace('%COMPONENTS', components)

            # Add user's audit trail actions, if present.
            warnings = ''
            warnings += MailerHelper.list_audit_trail_changes(audit_trail, developer)
            warnings += apex_warning
            body = body.replace('%WARNINGS', warnings)

            # Add body + attachment.
            mail.attach(MIMEText(body.encode('utf-8'), 'plain'))
            mail.attach(att_part)

            if preview_only: print(body + '\n\n')
            else:            self.send_mail(mail)

        Helper.remove_file(attachment)
        
    def send_mail(self, mail):
        ' Takes a mail MIMEMultipart object and sends it. '
        
        try:
            server = smtplib.SMTP(CONF['MAIL']['SMTP_SERVER'] + ': ' + str(CONF['MAIL']['SMTP_PORT']))
            server.starttls()
            server.login(CONF['MAIL']['FROM_MAIL'], CONF['MAIL']['SMTP_PASS'])
            server.sendmail(mail['From'], mail['To'], mail.as_string())
            server.quit()

            Logger.log.info('SUCCESS: Sent Deployment Update to ' + mail['To'])
        except Exception as e:
            Logger.log.warning('Could not send Deployment Update to ' + mail['To'] + '. Error reason: ' + str(e))


class Releaser:
    
    @staticmethod
    def retrieve(package_xml, source=CONF['DEPLOYMENT']['DEFAULT_SOURCE_ORG'], unpackaged_folder=None):
        ' Takes a package.xml file and retrieves it. '

        Logger.log.info('Retrieve of ' + package_xml + ' from ' + source + ' started')
        output = Helper.execute(['sfdx', 'force:mdapi:retrieve', '-r', './' + CONF['LOCATIONS']['RETRIEVE_FOLDER'], '-k', package_xml, '-u', source, '--verbose', '--json'])

        try:
            output = json.loads(output)

            # Print any warnings (usually about wrong API names).
            if 'messages' in output['result']:
                if type(output['result']['messages']) == list:
                    for msg in output['result']['messages']:
                        Logger.log.warning(msg['problem'])
                else:
                    Logger.log.warning(output['result']['messages']['problem'])
                Logger.log.error('Retrieve of ' + package_xml + ' failed due to component failures')
            else:
                Logger.log.info('Retrieve of ' + package_xml + ' was successful')

                # Unpack 'unpackaged.zip' in CONF['LOCATIONS']['RETRIEVE_FOLDER'] based on package.xml name.
                try:                
                    # Unzip 'unpackaged.zip' in CONF['LOCATIONS']['RETRIEVE_FOLDER'].
                    zip_ref = zipfile.ZipFile(CONF['LOCATIONS']['RETRIEVE_FOLDER'] + '/unpackaged.zip', 'r')
                    zip_ref.extractall(CONF['LOCATIONS']['RETRIEVE_FOLDER'])
                    zip_ref.close()

                    # If no 'unpackaged' folder was specified, determine it based on the package.xml name.
                    if not unpackaged_folder:
                        unpackaged_folder = CONF['LOCATIONS']['RETRIEVE_FOLDER'] + '/unpackaged_' + \
                                        package_xml.replace(CONF['LOCATIONS']['PACKAGE_FOLDER'] + '/package_', '').replace('.xml', '')
                    if os.path.exists(unpackaged_folder): shutil.rmtree(unpackaged_folder)
                    os.rename(CONF['LOCATIONS']['RETRIEVE_FOLDER'] + '/unpackaged', unpackaged_folder)

                    Logger.log.info('Package was extracted in ' + unpackaged_folder.replace(CONF['LOCATIONS']['RETRIEVE_FOLDER'] + '/', ''))
                    return unpackaged_folder
                except Exception as e:
                    Logger.log.error('Unzipping of ' + package_xml + ' failed with error: ' + str(e))

        except Exception as e:
            Logger.log.error('Retrieve of ' + package_xml + ' failed with error: ' + str(e))

        return None

    @staticmethod
    # KNOWN BUG: CANNOT ADD NEW FOLDERS FOR UNSEEN METADATA TYPES.
    def retrieve_update(package):
        '''
        Takes an existing package and updates it based on components
        added to the manifest since the time it was generated
        (without overwriting changes made to existing components).
        '''

        if not package.unpackaged:
            Logger.log.error('Cannot update ' + package.xml + ' before it has been updated')
            return package
        
        Logger.log.info('Started update operation of ' + package.unpackaged)

        # Compare the existing and current list of components to find missing ones.
        new_package = Package()
        missing_components = Helper.find_new_components(package.components, new_package.components)

        if len(missing_components) <= 0:
            logger.warning('Found no new components. Aborting package update')
            return package

        Logger.log.info('Found ' + str(sum(len(v) for v in missing_components.values())) + ' new component(s)')

        # Create a package.xml for the missing components and retrieve it.
        missing_package = Package(components=missing_components)
        missing_package.retrieve()

        # Add all newly retrieved missing components to the existing unpackaged directory.
        Helper.merge_dirs(missing_package.unpackaged, package.unpackaged)

        # Generate a package.xml with the new set of components, and overwrite the existing ones.
        shutil.copy(new_package.xml, package.unpackaged + '/package.xml')
        shutil.copy(new_package.xml, package.xml)

        # Remove all the temporary files we created for this function.
        Helper.remove(new_package.xml)
        Helper.remove(missing_package.xml)
        Helper.remove(missing_package.unpackaged)

        Logger.log.info('Successfully updated ' + package.unpackaged)

        return new_package.components
    
    @staticmethod
    def deploy(unpackaged, test_level='RunLocalTests', check_only=True, target=CONF['DEPLOYMENT']['DEFAULT_TARGET_ORG']):
        ' Takes a directory (unpackaged) and deploys it. '
        
        cmd = ['sfdx', 'force:mdapi:deploy', '-w', '-1', '-l', test_level, '-u', target, '--verbose', '--json']
        if '.zip' in unpackaged: cmd.extend(['-f', unpackaged])
        else:                    cmd.extend(['-d', unpackaged])

        if check_only: cmd.append('--checkonly')

        Logger.log.info('Deployment of ' + unpackaged + ' to ' + target + ' started')
        
        output = Helper.execute(cmd)

        try:
            output = json.loads(output) if type(output) == str else output
            
            if output['result']['success'] and check_only:
                Logger.log.info('Successfully VALIDATED ' + str(output['result']['numberComponentsTotal']) + ' components as part of deployment ' + output['result']['id'] + ' for package ' + unpackaged)
            elif output['result']['success'] and not check_only:
                Logger.log.info('Successfully deployed ' + str(output['result']['numberComponentsTotal']) + ' components as part of deployment ' + output['result']['id'] + ' for package ' + unpackaged)
                Logger.log.info('Do not forget to perform the post-deployment steps, and update the sheet.')
            
            details = output['result']['details']
            if 'componentFailures' in details:
                failures = details['componentFailures']
                Logger.log.error('Deployment of ' + unpackaged + ' returned ' + str(len(failures)) + ' component failures')
                for failure in failures:
                    Logger.log.error(failure['fullName'] + ' - ' + failure['problem'])
            elif 'failures' in details['runTestResult']:
                failures = details['runTestResult']['failures']
                Logger.log.error('Deployment of ' + unpackaged + ' returned ' + str(len(failures)) + ' test failures')
                for failure in failures:
                    Logger.log.error(failure['name'])
                    Logger.log.error(failure['message'])
                    
            return output
        except Exception as e:
            Logger.log.error('Deployment of ' + unpackaged + ' failed with error: ' + str(e))


class MD_Helper:
    
    def __init__(self, username, password, security_token, sandbox=False):
        self.init_session(username, password, security_token, sandbox)
    
    def init_session(self, username, password, security_token, sandbox=False):
        '''
        Takes a username, password, security token, and sandbox boolean.
        Initializes a SOAP API session.
        Returns a session id.
        '''

        sf_url = 'https://test.salesforce.com/services/Soap/c/34.0' if sandbox \
            else 'https://login.salesforce.com/services/Soap/c/34.0'

        headers = {'content-type': 'text/xml', 'SOAPAction': 'Create'}
        body = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:enterprise.soap.sforce.com">
         <soapenv:Header>
            <urn:LoginScopeHeader>
            </urn:LoginScopeHeader>
         </soapenv:Header>
         <soapenv:Body>
            <urn:login>
               <urn:username>""" + username + """</urn:username>
               <urn:password>""" + password + security_token + """</urn:password>
            </urn:login>
         </soapenv:Body>
        </soapenv:Envelope>"""

        try:
            response = requests.post(sf_url, data=body, headers=headers)
            response_xml = ET.fromstring(response.content)
            
            if (response_xml.find('.//{urn:enterprise.soap.sforce.com}sessionId') == None):
                Logger.log.error('Could not establish SOAP API session. \
                                 Check the credentials and security token in config.ini')
                return
            
            self.session_id = response_xml.find('.//{urn:enterprise.soap.sforce.com}sessionId').text
            self.md_server_url = response_xml.find('.//{urn:enterprise.soap.sforce.com}metadataServerUrl').text
            Logger.log.info('Established SOAP API session with ID {}'.format(self.session_id))
        except Exception as e:
            Logger.log.error('Error occurred while connecting to SOAP API: {}'.format(str(e)))
    
    def list_components(self, md_types):
        '''
        Takes a (list of) metadata type(s), returns
        a list with all components of that type(s).
        '''
        
        # Check if metadata types input is valid, and convert it if necessary.
        if type(md_types) == str:
            md_types = [md_types]
        elif type(md_types) != list:
            Logger.log.error('The list_components function requires either a string or list as input')
            return
        
        Logger.log.info('Started querying components for {} metadata type(s): {}'.format(len(md_types), ', '.join(md_types)))
        
        # Execute a separate query for each MD type (to avoid hitting API limits).
        components = []
        for md_type in md_types:
            components.extend(self.query_components(md_type))
            
        Logger.log.info('Successfully fetched {} components for {} metadata type(s)'.format(len(components), len(md_types)))
            
        return components
    
        
    def query_components(self, md_type):
        ' Queries all components for a single MD type. '
        
        headers = {'content-type': 'text/xml', 'SOAPAction': 'retrieve'}
        body = """
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:met="http://soap.sforce.com/2006/04/metadata">
                <soapenv:Header>
                    <met:CallOptions></met:CallOptions>
                    <met:SessionHeader>
                        <met:sessionId>""" + self.session_id + """</met:sessionId>
                    </met:SessionHeader>
                </soapenv:Header>
                <soapenv:Body>
                    <met:listMetadata>
                        <met:queries>
                            <met:type>""" + md_type + """</met:type>
                        </met:queries>
                        <met:asOfVersion>37.0</met:asOfVersion>
                    </met:listMetadata>
                </soapenv:Body>
            </soapenv:Envelope>"""
        
        # Query API for list of metadata types.
        try:
            response = requests.post(self.md_server_url, data=body, headers=headers)
            response_dict = xmltodict.parse(response.content)
            md_components = response_dict['soapenv:Envelope']['soapenv:Body']['listMetadataResponse']['result']
            Logger.log.info('Fetched {} components of type {}'.format(len(md_components), md_type))
            return md_components
        except (KeyError, TypeError):
            Logger.log.warning('Did not find components of type {}'.format(md_type))
        except Exception as e:
            Logger.log.error('Error while fetching components for {}: {}'.format(md_type, str(e)))
        
        return []
            
    def update_sheet(self, md_types=None):
        ' Updates the sheet with all components in the org. '
        
        if not md_types: md_types = CONF['SHEET_MANAGER']['MD_TYPES'].split(',')
        
        # Fetch all components with the provided metadata types.
        components = self.list_components(md_types)
        
        # Update all appropriate component values in a list of cell values.
        component_cells = []
        for component in components:
            try:
                component_cells.extend([component['type'], component['fullName'], component['createdByName'], component['lastModifiedByName'], component['lastModifiedDate']])
            except:
                pass

        # Update the sheet.
        headers = ['Object Type', 'API Name', 'Created By', 'Last Modified By', 'Last Modified Date']
        sheet = GSheet()
        sheet.update_components_tab(component_cells, headers)


# Authenticate SFDX (Heroku-only).
for key, val in os.environ.iteritems():
    if val.startswith('force://'):
        try:
            file = open('authurl', 'w') 
            file.write(val) 
            file.close()
            Helper.execute(['sfdx', 'force:auth:sfdxurl:store', '-f', 'authurl', '-a', key])
            if os.path.exists('authurl'): os.remove('authurl')
        except Exception as e:
            print 'Error occurred while authenticating SFDX org', key, 'with auth URL', val, ':', e