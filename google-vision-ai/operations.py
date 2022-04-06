""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from requests import request, exceptions as req_exceptions
from .google_api_auth import *
import shutil, base64
from connectors.cyops_utilities.builtins import download_file_from_cyops
from integrations.crudhub import make_request
from os.path import join

SCOPES = ['https://www.googleapis.com/auth/cloud-platform']

logger = get_logger('google-vision-ai')


def make_rest_call(method, endpoint, connector_info, config, params=None, data=None, headers={}):
    try:
        go = GoogleAuth(config)
        endpoint = go.host + endpoint
        token = go.validate_token(config, connector_info)
        headers['Authorization'] = token
        headers['Content-Type'] = 'application/json'
        logger.debug("Endpoint: {0}".format(endpoint))
        try:
            response = request(method, endpoint, headers=headers, params=params, json=data, verify=go.verify_ssl)
            logger.debug("Response Status Code: {0}".format(response.status_code))
            logger.debug("Response: {0}".format(response.text))
            logger.debug("API Header: {0}".format(response.headers))
            if response.status_code in [200, 201, 204]:
                if response.text != "":
                    return response.json()
                else:
                    return True
            else:
                if response.text != "":
                    err_resp = response.json()
                    failure_msg = err_resp['error']['message']
                    error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason,
                                                                         failure_msg if failure_msg else '')
                else:
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
                logger.error(error_msg)
                raise ConnectorError(error_msg)
        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            raise ConnectorError(str(err))
    except Exception as err:
        raise ConnectorError(str(err))


def handle_params(params):
    value = str(params.get('value'))
    try:
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        if not value.startswith('/api/3/attachments/'):
            value = '/api/3/attachments/{0}'.format(value)
        attachment_data = make_request(value, 'GET')
        file_iri = attachment_data['file']['@id']
        file_name = attachment_data['file']['filename']
        logger.info('file id = {0}, file_name = {1}'.format(file_iri, file_name))
        return file_iri, file_name
    except Exception as err:
        logger.info('handle_params(): Exception occurred {0}'.format(err))
        raise ConnectorError(
            'Requested resource could not be found with input type Attachment ID and value "{0}"'.format
            (value.replace('/api/3/attachments/', '')))


def submit_images(config, params, connector_info):
    url = '/v1/images:annotate'
    file_iri, file_name = handle_params(params)
    file_path = join('/tmp', download_file_from_cyops(file_iri)['cyops_file_path'])
    logger.info("File Path: {0}".format(file_path))
    try:
        shutil.copy(file_path, file_name)
    except Exception as err:
        logger.exception("Failed to prepare file for upload: {0}".format(str(err)))
        raise ConnectorError("Failed to prepare file for upload.")
    try:
        with open(file_name, 'rb') as attachment:
            content = attachment.read()
        if content:
            data = {'requests': [{
                'image': {
                    'content': base64.b64encode(content).decode('UTF-8')
                },
                'features': [{
                    'type': params.get('type'),
                    'maxResults': params.get('maxResults')
                }]
            }]
            }
            logger.debug("Payload: {0}".format(data))
            response = make_rest_call('POST', url, connector_info, config, data=data)
            return response
    finally:
        shutil.rmtree(file_name, ignore_errors=True)


def get_locations_operations(config, params, connector_info):
    try:
        url = '/v1/locations/{0}/operations/{1}'.format(params.get('location_id'), params.get('operation_id'))
        response = make_rest_call('GET', url, connector_info, config)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_operations(config, params, connector_info):
    try:
        url = '/v1/operations/{0}'.format(params.get('operation_id'))
        response = make_rest_call('GET', url, connector_info, config)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def _check_health(config, connector_info):
    try:
        return check(config, connector_info)
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'submit_images': submit_images,
    'get_locations_operations': get_locations_operations,
    'get_operations': get_operations
}
