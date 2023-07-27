""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """

import requests
import time
from connectors.core.connector import get_logger, ConnectorError
from connectors.core.utils import update_connnector_config


error_msg = {
    401: 'Authentication failed due to invalid credentials',
    429: 'Rate limit was exceeded',
    403: 'Token is invalid or expired',
    "ssl_error": 'SSL certificate validation failed',
    'time_out': 'The request timed out while trying to connect to the remote server',
}

logger = get_logger("mobile-security-framework_1_0_0")


class MakeRestApiCall:

    def __init__(self, config):
        self.server_url = config.get('server_url', '')
        self.verify_ssl = config.get("verify_ssl", True)
        self.method_header = {"Authorization": config.get('api_key')}
        logger.info(f"URL : {self.server_url} , Header is {self.method_header}")

    def make_request(self, endpoint='', params=None,files=None, data=None, method='GET', headers=None, url=None, json_data=None):
        try:
            if url is None:
                url = self.server_url + endpoint
            if headers is not None:
                self.method_header.update(headers)

            logger.info(f" Before making call : Header is {self.method_header} and data is {data}")

            response = requests.request(method=method, url=url,files=files,
                                        headers=self.method_header, data=data, json=json_data, params=params, verify=self.verify_ssl)

            try:
                from connectors.debug_utils.curl_script import make_curl
                make_curl(method, endpoint, headers=headers, params=params, data=data, verify_ssl=self.verify_ssl)
            except Exception as err:
                logger.error(f"Error in curl utils: {str(err)}")


            if response.ok:
                logger.info(f"Inside Response OK")
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response.content
            else:
                logger.error("Error: {0}".format(response.json()))
                raise ConnectorError('{0}'.format(error_msg.get(response.status_code, response.text)))
        except requests.exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(error_msg.get('ssl_error')))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(error_msg.get('time_out')))
        except Exception as e:
            logger.error('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))