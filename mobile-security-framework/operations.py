""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """
import os

from .make_rest_api_call import MakeRestApiCall
from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.builtins import upload_file_to_cyops, download_file_from_cyops, create_cyops_attachment
from os.path import join
from integrations.crudhub import make_request, make_file_upload_request
from django.conf import settings

logger = get_logger("mobile-security-framework")


def upload_file(config: dict, params: dict) -> dict:
    try:
        endpoint = "/api/v1/upload"
        method = "POST"
        params = _build_payload(params)

        file_iri = _handle_params(params)
        files = _submitFile(file_iri.get('file_iri'), file_iri.get('file_name'))
        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, files=files)
        return response
    except Exception as err:
        logger.error(f"Error occurred in Upload File{err}")
        raise ConnectorError(err)


def scan_file(config: dict, params: dict) -> dict:
    try:
        endpoint = "/api/v1/scan"
        method = "POST"
        params = _build_payload(params)
        if params.get('re_scan'):
            params['re_scan'] = 1

        params['re_scan'] = 0

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, data=params)
        return response
    except Exception as err:
        logger.error(f"Error occurred in Scan File{err}")
        raise ConnectorError(err)


def delete_scan(config: dict, params: dict) -> dict:
    try:
        endpoint = "/api/v1/delete_scan"
        method = "POST"
        params = _build_payload(params)

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, data=params)
        return response
    except Exception as err:
        logger.error(f"Error occurred in Delete Scan File{err}")
        raise ConnectorError(err)


def display_recent_scans(config: dict, params: dict) -> dict:
    try:
        endpoint = "/api/v1/scans"
        method = "GET"
        params = _build_payload(params)

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, params=params)
        return response
    except Exception as err:
        logger.error(f"Error occurred in Display Recent Scan Files{err}")
        raise ConnectorError(err)


def get_app_scorecard(config: dict, params: dict) -> dict:
    try:
        endpoint = "/api/v1/scorecard"
        method = "POST"

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, data=params)
        return response
    except Exception as err:
        logger.error(f"Error occurred in App Scorecard API{err}")
        raise ConnectorError(err)


def generate_pdf_report(config: dict, params: dict) -> dict:
    try:
        endpoint = "/api/v1/download_pdf"
        method = "POST"
        file_name = params.get("file_name")
        if not file_name.endswith(".pdf"):
            file_name = file_name + ".pdf"
        path = os.path.join(settings.TMP_FILE_ROOT, file_name)

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, data=params)

        with open(path, 'wb') as fp:
            fp.write(response)

        return upload_file_to_cyops(file_path=file_name, filename=file_name, name=file_name, create_attachment=True)
    except Exception as err:
        logger.error(f"Error occurred in Generate PDF Report{err}")
        raise ConnectorError(err)


def generate_json_report(config: dict, params: dict) -> dict:
    try:
        endpoint = "/api/v1/report_json"
        method = "POST"

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, data=params)
        return response
    except Exception as err:
        logger.error(f"Error occurred in Generate JSON Report{err}")
        raise ConnectorError(err)


def view_source_files(config: dict, params: dict) -> dict:
    try:
        endpoint = "/api/v1/view_source"
        method = "POST"
        params = _build_payload(params)

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, data=params,
                                   headers={'Content-Type': 'application/x-www-form-urlencoded'})
        return response
    except Exception as err:
        logger.error(f"Error occurred in View Source Files{err}")
        raise ConnectorError(err)


def compare_scan_results(config: dict, params: dict) -> dict:
    try:
        endpoint = "/api/v1/compare"
        method = "POST"

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, data=params)
        return response
    except Exception as err:
        logger.error(f"Error occurred in Compare Apps{err}")
        raise ConnectorError(err)


def suppress_by_rule(config: dict, params: dict) -> dict:
    try:
        endpoint = "/api/v1/suppress_by_rule"
        method = "POST"

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, data=params)
        return response
    except Exception as err:
        logger.error(f"Error occurred in Suppress by rule {err}")
        raise ConnectorError(err)


def suppress_by_files(config: dict, params: dict) -> dict:
    try:
        endpoint = "/api/v1/suppress_by_files"
        method = "POST"

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, data=params)
        return response
    except Exception as err:
        logger.error(f"Error occurred in Suppress by Files {err}")
        raise ConnectorError(err)


def view_suppressions(config: dict, params: dict) -> dict:
    try:
        endpoint = "/api/v1/list_suppressions"
        method = "POST"

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, data=params)
        return response
    except Exception as err:
        logger.error(f"Error occurred in View Suppressions {err}")
        raise ConnectorError(err)


def delete_suppressions(config: dict, params: dict) -> dict:
    try:
        endpoint = "/api/v1/delete_suppression"
        method = "POST"

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, data=params)
        return response
    except Exception as err:
        logger.error(f"Error occurred in Delete Suppressions {err}")
        raise ConnectorError(err)


def _handle_params(params):
    value = str(params.get('value'))
    input_type = params.get('input')
    try:
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        if input_type == 'Attachment ID':
            if not value.startswith('/api/3/attachments/'):
                value = '/api/3/attachments/{0}'.format(value)
            attachment_data = make_request(value, 'GET')
            file_iri = attachment_data['file']['@id']
            file_name = attachment_data['file']['filename']
            return {'file_iri': file_iri, 'file_name': file_name}
        elif input_type == 'File IRI':
            if value.startswith('/api/3/files/'):
                return value
            else:
                raise ConnectorError('Invalid File IRI {0}'.format(value))
    except Exception as err:
        raise ConnectorError('Requested resource could not be found with input type "{0}" and value "{1}"'.format
                             (input_type, value.replace('/api/3/attachments/', '')))


def _submitFile(file_iri, file_name):
    try:
        file_path = join('/tmp', download_file_from_cyops(file_iri)['cyops_file_path'])
        files = [
            ('file',
             (file_name, open(file_path, 'rb'), 'application/octet-stream'))
        ]
        return files
        raise ConnectorError('File size too large, submit file up to 32 MB')
    except Exception as Err:
        raise ConnectorError('Error in submitFile(): %s' % Err)


def _filePath(file_iri):
    file_path = join('/tmp', download_file_from_cyops(file_iri)['cyops_file_path'])
    return file_path


def _build_payload(params):
    return {key: val for key, val in params.items() if val is not None and val != ''}


operations = {
    "upload_file": upload_file,
    "scan_file": scan_file,
    "delete_scan": delete_scan,
    "display_recent_scans": display_recent_scans,
    "get_app_scorecard": get_app_scorecard,
    "generate_pdf_report": generate_pdf_report,
    "generate_json_report": generate_json_report,
    "view_source_files": view_source_files,
    "compare_scan_results": compare_scan_results,
    "suppress_by_rule": suppress_by_rule,
    "suppress_by_files": suppress_by_files,
    "view_suppressions": view_suppressions,
    "delete_suppressions": delete_suppressions,
}
