# OPENFAAS-JOB-WORKER from seb835 
# https://github.com/seb-835/openfaas-job-worker
#
# Original Project : OSCAR - On-premises Serverless Container-aware ARchitectures
# Copyright (C) GRyCAP - I3M - UPV
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import os
import logging
import json
from nats.aio.client import Client as NATS
from stan.aio.client import Client as STAN
import jobworker.utils as utils
from jobworker.subscribers.subscriber import Subscriber

class NatsSubscriber(Subscriber):

    cluster_id = 'faas-cluster'
    subject = 'job-faas-request'
    queue_group = 'faas'

    def __init__(self):
        self.client_id = 'job-faas-worker-{0}'.format(os.uname().nodename)

        self.nats_address = utils.get_environment_variable('NATS_ADDRESS')
        if not self.nats_address:
            self.nats_address = 'nats.openfaas'

        self.nats_port = utils.get_environment_variable('NATS_PORT')
        if not self.nats_port:
            self.nats_port = '4222'

        self.subject = utils.get_environment_variable('NATS_QUEUE')
        if not self.subject:
            self.subject = 'job-faas-request'

    async def run(self, loop, handler):
        # Use borrowed connection for NATS then mount NATS Streaming
        # client on top.
        logging.info('Connecting to nats://{0}:{1}...'.format(self.nats_address, self.nats_port))
        nc = NATS()
        await nc.connect('{0}:{1}'.format(self.nats_address, self.nats_port), loop=loop)

        # Start session with NATS Streaming cluster.
        logging.info('Establishing connection to cluster: {0} with clientID: {1}...'.format(self.cluster_id, self.client_id))
        sc = STAN()
        await sc.connect(self.cluster_id, self.client_id, nats=nc)

        # Send msg.data to handler (KubernetesClient.launch_job())
        async def cb(msg):
            data = json.loads(msg.data.decode('utf-8'))
            logging.info("\nReceived  message (seq={}) : {}\n".format(msg.seq, data))
            handler(data)

        try:
            await sc.subscribe(self.subject, queue=self.queue_group, cb=cb)
            logging.info('Listening on "{0}", queue "{1}"'.format(self.subject, self.queue_group))
        except asyncio.CancelledError as e:
            await sc.close()
            await nc.close()
            raise e



