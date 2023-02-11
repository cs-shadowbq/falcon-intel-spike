#import code  # troubleshooting only
import os
import configparser
import logging
from pymongo import MongoClient

try:
    from falconpy import api_complete as FalconSDK
except ImportError as no_falconpy:
    raise SystemExit(
        "The CrowdStrike Python SDK must be installed in order to use this utility.\n"
        "Install this application with the command `python3 -m pip install crowdstrike-falconpy`."
    ) from no_falconpy

class AppConfig(configparser.ConfigParser):
    
    FALCON_CLOUD_REGIONS = {'us-1', 'us-2', 'eu-1', 'us-gov-1'}
    ENV_DEFAULTS = [
        ['falcon', 'cloud_region', 'FALCON_CLOUD_REGION'],
        ['falcon', 'client_id', 'FALCON_CLIENT_ID'],
        ['falcon', 'client_secret', 'FALCON_CLIENT_SECRET'],
        ['mongodb', 'connectionstring'. 'MONGO_CONNECTIONSTRING']
        ['mongodb', 'database'. 'MONGO_DATABASE']
        ['mongodb', 'collection'. 'MONGO_COLLECTION']
    ]

    def __init__(self):
        super().__init__()
        self.read(['config.ini', 'config/defaults.ini', 'config/config.ini', 'config/devel.ini'])
        self._override_from_env()

    def _override_from_env(self):
        for section, var, envvar in self.__class__.ENV_DEFAULTS:
            value = os.getenv(envvar)
            if value:
                self.set(section, var, value)

    def validate(self):
        for section, var, envvar in self.__class__.ENV_DEFAULTS:
            try:
                self.get(section, var)
            except configparser.NoOptionError as err:
                raise Exception(
                    "Please provide environment variable {} or configuration option {}.{}".format(
                        envvar, section, var)) from err
        self.validate_falcon()


    def validate_falcon(self):
        if int(self.get('falcon', 'reconnect_retry_count')) not in range(1, 10000):
            raise Exception('Malformed configuration: expected falcon.reconnect_retry_count to be in range 0-10000')
        if self.get('falcon', 'cloud_region') not in self.FALCON_CLOUD_REGIONS:
            raise Exception(
                'Malformed configuration: expected falcon.cloud_region to be in {}'.format(self.FALCON_CLOUD_REGIONS)
            )


    @property
    def indicators(self):
        return {'limit': config['csdata']['limit'], 'include_deleted': config['csdata']['include_deleted'], 'filter': "_marker:>''", 'sort': config['csdata']['sort']}


class ApiError(Exception):
    pass


class NoIOCsError(ApiError):
    def __init__(self):
        super().__init__(
            'Falcon Intel IOCs API not discovered. This may be caused by a lack of scope approval for'
            'the API key, or lack of subscription to Falcon Intelligence.')


class FalconAPI():
    CLOUD_REGIONS = {
        'us-1': 'api.crowdstrike.com',
        'us-2': 'api.us-2.crowdstrike.com',
        'eu-1': 'api.eu-1.crowdstrike.com',
        'us-gov-1': 'api.laggar.gcw.crowdstrike.com',
    }

    def __init__(self):
        self.client = FalconSDK.APIHarness(creds={
            'client_id': config.get('falcon', 'client_id'),
            'client_secret': config.get('falcon', 'client_secret')},
            base_url=self.__class__.base_url())
        self.client.authenticate()
        self.response = None
        self.pagination = False
        self.pagination_url = None

    @classmethod
    def base_url(cls):
        return 'https://' + cls.CLOUD_REGIONS[config.get('falcon', 'cloud_region')]

    def _resources(self, *args, **kwargs):
        response = self._mycommand(*args, **kwargs)
        body = response['body']
        return body['resources'] if 'resources' in body and body['resources'] else []

    def _mycommand(self, *args, **kwargs):
        response = self.client.command(*args, **kwargs)
        body = response['body']
        log.info('Connection to Intel API resulted with status code: ' + str(response['status_code']))

        if 'errors' in body and body['errors'] is not None and len(body['errors']) > 0:
            raise ApiError(f"Error received from CrowdStrike Falcon platform: {body['errors']}")
        if 'status_code' not in response or response['status_code'] not in [200, 201]:
            raise ApiError(f'Unexpected response code from Falcon API. Response was: {response}')
        if 'Next-Page' in response['headers'] and len(response['headers']['Next-Page']) > 0:
            log.info('Pagination is required')
            self.pagination = True
            self.pagination_url = response['headers']['Next-Page']
        else:
            log.info('Pagination is not required')
            self.pagination = False

        return response


def get_current_marker(parameters):
    with open(marker_file, 'a+') as marker:
        marker.seek(0)
        read = marker.read()
        tracker = read.split('\n')
        if len(tracker) == 0:
            log.info('Marker file is empty')
        else:
            log.info(f'This is last marker collected per the tracker: {tracker[-1]}')
            parameters['filter'] = "_marker:>'" + tracker[-1] + "'"
    return parameters


def update_marker(parameters, _last_indicator_marker):
    log.info(f'Tracker file updated: {_last_indicator_marker}')
    with open(marker_file, 'a+') as t:
        t.write(f'\n{_last_indicator_marker}')
    parameters['filter'] = "_marker:>'" + _last_indicator_marker + "'"
    return parameters

VERSION = "0.0.1-spike"
APPLICATION_NAME = "falcon-intel-indicators-to-mongodb"

if __name__ == "__main__":



    config = AppConfig()
    config.validate()
    marker_file = config['main']['marker_file']
    api = FalconAPI()
    api.client.authenticated

    level = logging.getLevelName(config.get('logging', 'level'))
    log = logging.getLogger('falconspike')
    log.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    formatter = logging.Formatter(f'%(asctime)s %(name)s %(threadName)-10s %(levelname)-5s - {VERSION} v{APPLICATION_NAME}: %(message)s', '%Y-%m-%d %H:%M:%S')
    ch.setFormatter(formatter)
    log.addHandler(ch)

    parameters = config.indicators
    parameters = get_current_marker(parameters)
    indicators = []

    # Interact with Code if Troubleshooting Mongo Connection Strings
    # code.interact(local=dict(globals(), **locals()))
    
    client = MongoClient(config['mongodb']['connectionstring'])
    my_database = client[config['mongodb']['database']]
    my_collection = my_database[config['mongodb']['collection']]

    fetch = True

    while fetch:
        indicators_response = api._resources(action='QueryIntelIndicatorEntities', parameters=parameters)
        if len(indicators_response) > 0:
            for x in iter(indicators_response):
                log.info(f'writing append indicator: {x["id"]}')
                my_collection.insert_one(x)
        else:
            fetch = False
        _last_indicator = indicators_response[-1]
        parameters = update_marker(parameters, _last_indicator['_marker'])
