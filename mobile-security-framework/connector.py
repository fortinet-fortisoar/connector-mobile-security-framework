""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """


from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations
from .check_health import _check_health

logger = get_logger("mobile-security-framework")
class MobSFConnector(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            operation = operations.get(operation)
            if not operation:
                logger.error('Unsupported operation: {0}'.format(operation))
                raise ConnectorError('Unsupported operation')
            return operation(config, params)
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)

    def check_health(self, config=None):
        try:
            return _check_health(config)
        except Exception as err:
            raise ConnectorError(err)
